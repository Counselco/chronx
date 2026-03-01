use chronx_core::account::{Account, AuthPolicy, TimeLockContract, TimeLockStatus};
use chronx_core::claims::{
    CertificateSchema, ClaimLane, ClaimState, LaneThresholds, OracleSnapshot,
    OracleSubmission, ProviderRecord, ProviderStatus, SignatureRules, SlashReason,
};
use chronx_core::constants::{
    CANCELLATION_WINDOW_MAX_SECS, MAX_EXTENSION_DATA_BYTES, MAX_LOCK_DURATION_YEARS,
    MAX_MEMO_BYTES, MAX_RECURRING_COUNT, MAX_TAGS_PER_LOCK, MAX_TAG_LENGTH,
    MIN_CHALLENGE_BOND_CHRONOS, MIN_LOCK_AMOUNT_CHRONOS, MIN_LOCK_DURATION_SECS,
    MIN_RECOVERY_BOND_CHRONOS, MIN_VERIFIER_STAKE_CHRONOS,
    ORACLE_MAX_AGE_SECS, ORACLE_MIN_SUBMISSIONS, PROVIDER_BOND_CHRONOS,
    RECOVERY_CHALLENGE_WINDOW_SECS, RECOVERY_EXECUTION_DELAY_SECS,
    RECOVERY_VERIFIER_THRESHOLD, SCHEMA_BOND_CHRONOS,
};
use std::sync::Arc;

use chronx_core::error::ChronxError;
use chronx_core::transaction::{Action, Transaction};
use chronx_core::types::Timestamp;
use chronx_crypto::hash::account_id_from_pubkey;
use chronx_dag::validation::{validate_signatures, validate_vertex};
use chronx_dag::vertex::Vertex;
use tracing::{info, warn};

use crate::db::StateDb;

// ── Staged mutations ──────────────────────────────────────────────────────────

/// All state changes staged by apply_action before atomic commit.
#[derive(Default)]
struct StagedMutations {
    accounts: Vec<Account>,
    timelocks: Vec<TimeLockContract>,
    providers: Vec<ProviderRecord>,
    schemas: Vec<CertificateSchema>,
    claims: Vec<ClaimState>,
    oracle_submissions: Vec<OracleSubmission>,
}

// ── StateEngine ───────────────────────────────────────────────────────────────

/// The state transition engine.
///
/// Validates and applies transactions to the persistent state database.
/// Each `apply` call is atomic: either all actions succeed or none do.
pub struct StateEngine {
    pub db: Arc<StateDb>,
    pub pow_difficulty: u8,
}

impl StateEngine {
    pub fn new(db: Arc<StateDb>, pow_difficulty: u8) -> Self {
        Self { db, pow_difficulty }
    }

    /// Validate and apply a transaction. Returns `Ok(())` on success.
    pub fn apply(&self, tx: &Transaction, now: Timestamp) -> Result<(), ChronxError> {
        // ── DAG-level validation ──────────────────────────────────────────────
        validate_vertex(tx, self.pow_difficulty, |pid| self.db.vertex_exists(pid))?;

        // ── Duplicate check ───────────────────────────────────────────────────
        if self.db.vertex_exists(&tx.tx_id) {
            return Err(ChronxError::DuplicateVertex(tx.tx_id.to_hex()));
        }

        // ── Expiry check ──────────────────────────────────────────────────────
        if let Some(exp) = tx.expires_at {
            if now > exp {
                return Err(ChronxError::TransactionExpired);
            }
        }

        // ── Resolve sender account ────────────────────────────────────────────
        let sender = self
            .db
            .get_account(&tx.from)?
            .ok_or_else(|| ChronxError::UnknownAccount(tx.from.to_string()))?;

        // ── Nonce check ───────────────────────────────────────────────────────
        if tx.nonce != sender.nonce {
            return Err(ChronxError::InvalidNonce {
                expected: sender.nonce,
                got: tx.nonce,
            });
        }

        // ── Signature validation ──────────────────────────────────────────────
        validate_signatures(tx, &sender.auth_policy)?;

        // ── Apply each action ─────────────────────────────────────────────────
        let mut staged = StagedMutations::default();
        let mut staged_sender = sender.clone();

        for action in &tx.actions {
            self.apply_action(action, &mut staged_sender, &mut staged, now, &tx.tx_id)?;
        }

        // Increment nonce after all actions succeed.
        staged_sender.nonce += 1;
        staged.accounts.push(staged_sender);

        // ── Commit ────────────────────────────────────────────────────────────
        for acc in &staged.accounts {
            self.db.put_account(acc)?;
        }
        for tlc in &staged.timelocks {
            self.db.put_timelock(tlc)?;
        }
        for p in &staged.providers {
            self.db.put_provider(p)?;
        }
        for s in &staged.schemas {
            self.db.put_schema(s)?;
        }
        for cs in &staged.claims {
            self.db.put_claim(cs)?;
        }
        // Recompute oracle snapshots for any pairs that received a new submission.
        for sub in &staged.oracle_submissions {
            self.db.put_oracle_submission(sub)?;
            self.recompute_oracle_snapshot(&sub.pair, now)?;
        }

        // Update DAG tips.
        for parent_id in &tx.parents {
            let _ = self.db.remove_tip(parent_id);
        }
        self.db.add_tip(&tx.tx_id)?;

        // Persist the vertex.
        let depth = if tx.parents.is_empty() {
            0
        } else {
            tx.parents
                .iter()
                .filter_map(|pid| self.db.get_vertex(pid).ok().flatten())
                .map(|v| v.depth)
                .max()
                .unwrap_or(0)
                + 1
        };
        self.db.put_vertex(&Vertex::new(tx.clone(), depth, now))?;

        info!(tx_id = %tx.tx_id, "applied transaction");
        Ok(())
    }

    // ── Oracle helper ─────────────────────────────────────────────────────────

    fn recompute_oracle_snapshot(&self, pair: &str, now: Timestamp) -> Result<(), ChronxError> {
        let mut prices: Vec<u64> = self
            .db
            .iter_oracle_submissions_for_pair(pair)?
            .into_iter()
            .filter(|s| now - s.submitted_at <= ORACLE_MAX_AGE_SECS)
            .map(|s| s.price_cents)
            .collect();

        if prices.len() < ORACLE_MIN_SUBMISSIONS {
            return Ok(()); // Not enough data yet; keep old snapshot.
        }
        prices.sort_unstable();
        let median = prices[prices.len() / 2];

        let snap = OracleSnapshot {
            pair: pair.to_string(),
            price_cents: median,
            num_submissions: prices.len() as u32,
            updated_at: now,
        };
        self.db.put_oracle_snapshot(&snap)?;
        Ok(())
    }

    // ── Action dispatch ───────────────────────────────────────────────────────

    fn apply_action(
        &self,
        action: &Action,
        sender: &mut Account,
        staged: &mut StagedMutations,
        now: Timestamp,
        tx_id: &chronx_core::types::TxId,
    ) -> Result<(), ChronxError> {
        match action {
            // ── Transfer ─────────────────────────────────────────────────────
            Action::Transfer { to, amount } => {
                if *amount == 0 {
                    return Err(ChronxError::ZeroAmount);
                }
                if *to == sender.account_id {
                    return Err(ChronxError::SelfTransfer);
                }
                if sender.spendable_balance() < *amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *amount,
                        have: sender.spendable_balance(),
                    });
                }
                sender.balance -= amount;

                let mut recipient = self
                    .db
                    .get_account(to)?
                    .unwrap_or_else(|| Account::new(to.clone(), AuthPolicy::SingleSig {
                        public_key: chronx_core::types::DilithiumPublicKey(vec![]),
                    }));
                recipient.balance += amount;
                staged.accounts.push(recipient);
                Ok(())
            }

            // ── TimeLockCreate ────────────────────────────────────────────────
            Action::TimeLockCreate {
                recipient, amount, unlock_at, memo,
                cancellation_window_secs, notify_recipient, tags, private,
                expiry_policy, split_policy, claim_attempts_max, recurring,
                extension_data, oracle_hint, jurisdiction_hint,
                governance_proposal_id, client_ref,
            } => {
                // ── Consensus validation ──────────────────────────────────────
                if *amount == 0 {
                    return Err(ChronxError::ZeroAmount);
                }
                if *amount < MIN_LOCK_AMOUNT_CHRONOS {
                    return Err(ChronxError::LockAmountTooSmall { min: MIN_LOCK_AMOUNT_CHRONOS });
                }
                if *unlock_at <= now {
                    return Err(ChronxError::UnlockTimestampInPast);
                }
                if *unlock_at < now + MIN_LOCK_DURATION_SECS {
                    return Err(ChronxError::LockDurationTooShort { min_secs: MIN_LOCK_DURATION_SECS });
                }
                let max_unlock = now + (MAX_LOCK_DURATION_YEARS as i64) * 365 * 24 * 3600;
                if *unlock_at > max_unlock {
                    return Err(ChronxError::LockDurationTooLong { max_years: MAX_LOCK_DURATION_YEARS });
                }
                if let Some(m) = memo {
                    if m.len() > MAX_MEMO_BYTES {
                        return Err(ChronxError::MemoTooLong { max: MAX_MEMO_BYTES });
                    }
                }
                if let Some(t) = tags {
                    if t.len() > MAX_TAGS_PER_LOCK {
                        return Err(ChronxError::TooManyTags { max: MAX_TAGS_PER_LOCK });
                    }
                    for tag in t {
                        if tag.len() > MAX_TAG_LENGTH {
                            return Err(ChronxError::TagTooLong { max: MAX_TAG_LENGTH });
                        }
                    }
                }
                if let Some(ed) = extension_data {
                    if ed.len() > MAX_EXTENSION_DATA_BYTES {
                        return Err(ChronxError::ExtensionDataTooLarge { max: MAX_EXTENSION_DATA_BYTES });
                    }
                }
                if let Some(w) = cancellation_window_secs {
                    if *w > CANCELLATION_WINDOW_MAX_SECS {
                        return Err(ChronxError::CancellationWindowTooLong { max: CANCELLATION_WINDOW_MAX_SECS });
                    }
                }
                if let Some(sp) = split_policy {
                    let sum: u32 = sp.recipients.iter().map(|(_, bp)| *bp as u32).sum();
                    if sum != 10_000 {
                        return Err(ChronxError::SplitPolicyBasisPointsMismatch { got: sum });
                    }
                }
                if let Some(rec) = recurring {
                    use chronx_core::account::RecurringPolicy;
                    let count = match rec {
                        RecurringPolicy::None => 0,
                        RecurringPolicy::Weekly { count } => *count,
                        RecurringPolicy::Monthly { count } => *count,
                        RecurringPolicy::Annual { count } => *count,
                    };
                    if count > MAX_RECURRING_COUNT {
                        return Err(ChronxError::RecurringCountTooLarge { max: MAX_RECURRING_COUNT });
                    }
                }

                if sender.spendable_balance() < *amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *amount,
                        have: sender.spendable_balance(),
                    });
                }
                sender.balance -= amount;

                let recipient_account_id = account_id_from_pubkey(&recipient.0);
                let contract = TimeLockContract {
                    id: tx_id.clone(),
                    sender: sender.account_id.clone(),
                    recipient_key: recipient.clone(),
                    recipient_account_id,
                    amount: *amount,
                    unlock_at: *unlock_at,
                    created_at: now,
                    status: TimeLockStatus::Pending,
                    memo: memo.clone(),
                    lock_version: 0,
                    claim_policy: None,
                    beneficiary_anchor_commitment: None,
                    org_identifier: None,
                    cancellation_window_secs: *cancellation_window_secs,
                    notify_recipient: notify_recipient.unwrap_or(true),
                    tags: tags.clone(),
                    private: private.unwrap_or(false),
                    expiry_policy: expiry_policy.clone(),
                    split_policy: split_policy.clone(),
                    claim_attempts_max: *claim_attempts_max,
                    recurring: recurring.clone(),
                    extension_data: extension_data.clone(),
                    oracle_hint: oracle_hint.clone(),
                    jurisdiction_hint: jurisdiction_hint.clone(),
                    governance_proposal_id: governance_proposal_id.clone(),
                    client_ref: *client_ref,
                };
                staged.timelocks.push(contract);
                Ok(())
            }

            // ── TimeLockClaim ─────────────────────────────────────────────────
            Action::TimeLockClaim { lock_id } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                // V1 locks with a claim_policy must use the claims state machine.
                if contract.lock_version >= 1 && contract.claim_policy.is_some() {
                    return Err(ChronxError::LockRequiresClaimsFramework);
                }

                if contract.status != TimeLockStatus::Pending {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }
                if now < contract.unlock_at {
                    return Err(ChronxError::TimeLockNotMatured {
                        unlock_time: contract.unlock_at,
                    });
                }

                let expected_id = account_id_from_pubkey(&contract.recipient_key.0);
                if sender.account_id != expected_id {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                sender.balance += contract.amount;
                contract.status = TimeLockStatus::Claimed { claimed_at: now };
                staged.timelocks.push(contract);
                Ok(())
            }

            // ── TimeLockSell ──────────────────────────────────────────────────
            Action::TimeLockSell { lock_id: _, ask_price: _ } => {
                warn!("TimeLockSell submitted — secondary market not active at V1");
                Err(ChronxError::FeatureNotActive(
                    "secondary market (TimeLockSell) is not active in V1".into(),
                ))
            }

            // ── CancelTimeLock ────────────────────────────────────────────────
            Action::CancelTimeLock { lock_id } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                // Only the original sender may cancel.
                if contract.sender != sender.account_id {
                    return Err(ChronxError::CancelNotBySender);
                }
                // Lock must be in Pending state.
                if contract.status != TimeLockStatus::Pending {
                    return Err(ChronxError::InvalidClaimStateTransition);
                }
                // Lock must have a cancellation window.
                let window_secs = contract
                    .cancellation_window_secs
                    .ok_or(ChronxError::TimeLockIrrevocable)?;
                // Window must not have expired.
                if now > contract.created_at + window_secs as i64 {
                    return Err(ChronxError::CancellationWindowExpired);
                }

                // Return funds to sender.
                sender.balance += contract.amount;
                contract.status = TimeLockStatus::Cancelled { cancelled_at: now };
                staged.timelocks.push(contract);
                Ok(())
            }

            // ── StartRecovery ─────────────────────────────────────────────────
            Action::StartRecovery { target_account, proposed_owner_key, evidence_hash, bond_amount } => {
                if *bond_amount < MIN_RECOVERY_BOND_CHRONOS {
                    return Err(ChronxError::RecoveryBondTooLow { min: MIN_RECOVERY_BOND_CHRONOS });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance(),
                    });
                }

                let mut target = self
                    .db
                    .get_account(target_account)?
                    .ok_or_else(|| ChronxError::UnknownAccount(target_account.to_string()))?;

                if target.recovery_state.active {
                    return Err(ChronxError::RecoveryAlreadyActive(target_account.to_string()));
                }

                sender.balance -= bond_amount;

                target.recovery_state.active = true;
                target.recovery_state.proposed_owner_key = Some(proposed_owner_key.clone());
                target.recovery_state.recovery_start_time = Some(now);
                target.recovery_state.recovery_execute_after =
                    Some(now + RECOVERY_EXECUTION_DELAY_SECS);
                target.recovery_state.recovery_bond = *bond_amount;
                target.recovery_state.evidence_hash = Some(evidence_hash.clone());
                target.recovery_state.votes_approve.clear();
                target.recovery_state.votes_reject.clear();
                target.recovery_state.challenge_active = false;

                staged.accounts.push(target);
                Ok(())
            }

            // ── ChallengeRecovery ─────────────────────────────────────────────
            Action::ChallengeRecovery { target_account, counter_evidence_hash, bond_amount } => {
                if *bond_amount < MIN_CHALLENGE_BOND_CHRONOS {
                    return Err(ChronxError::ChallengeBondTooLow { min: MIN_CHALLENGE_BOND_CHRONOS });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance(),
                    });
                }

                let mut target = self
                    .db
                    .get_account(target_account)?
                    .ok_or_else(|| ChronxError::UnknownAccount(target_account.to_string()))?;

                if !target.recovery_state.active {
                    return Err(ChronxError::NoActiveRecovery(target_account.to_string()));
                }

                let window_end = target.recovery_state.recovery_start_time.unwrap_or(0)
                    + RECOVERY_CHALLENGE_WINDOW_SECS;
                if now > window_end {
                    return Err(ChronxError::ChallengeWindowClosed);
                }

                sender.balance -= bond_amount;
                target.recovery_state.challenge_active = true;
                target.recovery_state.challenge_bond = *bond_amount;
                target.recovery_state.counter_evidence_hash = Some(counter_evidence_hash.clone());

                staged.accounts.push(target);
                Ok(())
            }

            // ── FinalizeRecovery ──────────────────────────────────────────────
            Action::FinalizeRecovery { target_account } => {
                let mut target = self
                    .db
                    .get_account(target_account)?
                    .ok_or_else(|| ChronxError::UnknownAccount(target_account.to_string()))?;

                let rs = &target.recovery_state;
                if !rs.active {
                    return Err(ChronxError::NoActiveRecovery(target_account.to_string()));
                }
                if now < rs.recovery_execute_after.unwrap_or(i64::MAX) {
                    return Err(ChronxError::RecoveryDelayNotElapsed);
                }
                if rs.votes_approve.len() < RECOVERY_VERIFIER_THRESHOLD as usize {
                    return Err(ChronxError::RecoveryNotApproved);
                }

                let new_key = target
                    .recovery_state
                    .proposed_owner_key
                    .take()
                    .ok_or(ChronxError::RecoveryNotApproved)?;

                target.auth_policy = AuthPolicy::RecoveryEnabled {
                    owner_key: new_key,
                    recovery_config: chronx_core::account::RecoveryConfig::default(),
                };
                target.recovery_state = chronx_core::account::RecoveryState::default();

                staged.accounts.push(target);
                Ok(())
            }

            // ── RegisterVerifier ──────────────────────────────────────────────
            Action::RegisterVerifier { stake_amount } => {
                if *stake_amount < MIN_VERIFIER_STAKE_CHRONOS {
                    return Err(ChronxError::VerifierStakeTooLow { min: MIN_VERIFIER_STAKE_CHRONOS });
                }
                if sender.balance < *stake_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *stake_amount,
                        have: sender.balance,
                    });
                }
                sender.verifier_stake += stake_amount;
                sender.is_verifier = true;
                Ok(())
            }

            // ── VoteRecovery ──────────────────────────────────────────────────
            Action::VoteRecovery { target_account, approve, fee_bid: _ } => {
                if !sender.is_verifier {
                    return Err(ChronxError::VerifierNotRegistered(sender.account_id.to_string()));
                }

                let mut target = self
                    .db
                    .get_account(target_account)?
                    .ok_or_else(|| ChronxError::UnknownAccount(target_account.to_string()))?;

                if !target.recovery_state.active {
                    return Err(ChronxError::NoActiveRecovery(target_account.to_string()));
                }

                if target.recovery_state.votes_approve.contains(tx_id)
                    || target.recovery_state.votes_reject.contains(tx_id)
                {
                    return Err(ChronxError::VerifierAlreadyVoted);
                }

                if *approve {
                    target.recovery_state.votes_approve.push(tx_id.clone());
                } else {
                    target.recovery_state.votes_reject.push(tx_id.clone());
                }

                staged.accounts.push(target);
                Ok(())
            }

            // ── OpenClaim ─────────────────────────────────────────────────────
            Action::OpenClaim { lock_id } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                if contract.claim_policy.is_none() {
                    return Err(ChronxError::NoPolicyOnLock);
                }
                if contract.status != TimeLockStatus::Pending {
                    return Err(ChronxError::InvalidClaimStateTransition);
                }
                if now < contract.unlock_at {
                    return Err(ChronxError::TimeLockNotMatured { unlock_time: contract.unlock_at });
                }

                // Snapshot oracle price to fix V_claim.
                let snap = self.db.get_oracle_snapshot("KX/USD")?;
                let (v_claim_usd_cents, lane) = if let Some(s) = snap {
                    let amount_kx = contract.amount / chronx_core::constants::CHRONOS_PER_KX;
                    let v_cents = amount_kx as u64 * s.price_cents;
                    let thresholds = LaneThresholds::default_thresholds();
                    let lane = thresholds.lane_for(v_cents);
                    (v_cents, lane as u8)
                } else {
                    // No oracle data: default to Elevated for safety.
                    (u64::MAX, ClaimLane::Elevated as u8)
                };

                // Ambiguity check: V1 locks with ambiguity_mode require a unique identifier.
                // For simplicity in MVP: flag as Ambiguous if org_identifier is absent
                // and no beneficiary_anchor_commitment is set.
                // (Full governance-driven policy lookup omitted in MVP.)
                let is_ambiguous = contract.lock_version >= 1
                    && contract.org_identifier.is_none()
                    && contract.beneficiary_anchor_commitment.is_none();

                if is_ambiguous {
                    contract.status = TimeLockStatus::Ambiguous { flagged_at: now };
                } else {
                    contract.status = TimeLockStatus::ClaimOpen { opened_at: now };
                    let cs = ClaimState::new(lock_id.0.clone(), lane, v_claim_usd_cents, now);
                    staged.claims.push(cs);
                }

                staged.timelocks.push(contract);
                Ok(())
            }

            // ── SubmitClaimCommit ─────────────────────────────────────────────
            Action::SubmitClaimCommit { lock_id, commit_hash, bond_amount } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                if !matches!(contract.status, TimeLockStatus::ClaimOpen { .. }) {
                    return Err(ChronxError::InvalidClaimStateTransition);
                }

                let mut cs = self
                    .db
                    .get_claim(&lock_id.0)?
                    .ok_or_else(|| ChronxError::ClaimNotFound(lock_id.to_string()))?;

                let thresholds = LaneThresholds::default_thresholds();
                let lane = ClaimLane::from_u8(cs.lane);
                let min_bond = thresholds.min_bond(lane);

                if *bond_amount < min_bond {
                    return Err(ChronxError::ClaimBondTooLow { min: min_bond });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance(),
                    });
                }

                sender.balance -= bond_amount;
                cs.agent_id = Some(sender.account_id.clone());
                cs.commit_hash = Some(*commit_hash);
                cs.commit_bond = *bond_amount;
                cs.committed_at = Some(now);

                contract.status = TimeLockStatus::ClaimCommitted { committed_at: now };
                staged.timelocks.push(contract);
                staged.claims.push(cs);
                Ok(())
            }

            // ── RevealClaim ───────────────────────────────────────────────────
            Action::RevealClaim { lock_id, payload, salt, certificates } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                let committed_at = match &contract.status {
                    TimeLockStatus::ClaimCommitted { committed_at } => *committed_at,
                    _ => return Err(ChronxError::InvalidClaimStateTransition),
                };

                let mut cs = self
                    .db
                    .get_claim(&lock_id.0)?
                    .ok_or_else(|| ChronxError::ClaimNotFound(lock_id.to_string()))?;

                // Only the committing agent may reveal.
                if cs.agent_id.as_ref() != Some(&sender.account_id) {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                // Check reveal window.
                let thresholds = LaneThresholds::default_thresholds();
                let lane = ClaimLane::from_u8(cs.lane);
                let window = thresholds.reveal_window(lane);
                if now > committed_at + window {
                    // Slash: agent failed to reveal in time. Commit the slash
                    // as a valid state transition (Ok) so staged mutations persist.
                    let slash_amount = cs.commit_bond;
                    cs.commit_bond = 0;
                    contract.status = TimeLockStatus::ClaimSlashed {
                        reason: SlashReason::RevealTimeout,
                        slashed_at: now,
                    };
                    staged.timelocks.push(contract);
                    staged.claims.push(cs);
                    let _ = slash_amount; // In a full impl, credit to treasury.
                    return Ok(());
                }

                // Verify hash: blake3(payload || salt) must match commit_hash.
                let expected_hash = {
                    let mut h = blake3::Hasher::new();
                    h.update(payload);
                    h.update(salt);
                    *h.finalize().as_bytes()
                };
                let stored_hash = cs.commit_hash.ok_or(ChronxError::InvalidClaimStateTransition)?;
                if expected_hash != stored_hash {
                    // Slash: hash mismatch. Commit the slash as a valid state
                    // transition (Ok) so staged mutations persist.
                    let slash_amount = cs.commit_bond;
                    cs.commit_bond = 0;
                    contract.status = TimeLockStatus::ClaimSlashed {
                        reason: SlashReason::RevealHashMismatch,
                        slashed_at: now,
                    };
                    staged.timelocks.push(contract);
                    staged.claims.push(cs);
                    let _ = slash_amount;
                    return Ok(());
                }

                cs.revealed_payload = Some(payload.clone());
                cs.revealed_salt = Some(*salt);
                cs.certificates = certificates.clone();
                cs.revealed_at = Some(now);

                contract.status = TimeLockStatus::ClaimRevealed { revealed_at: now };
                staged.timelocks.push(contract);
                staged.claims.push(cs);
                Ok(())
            }

            // ── ChallengeClaimReveal ──────────────────────────────────────────
            Action::ChallengeClaimReveal { lock_id, evidence_hash, bond_amount } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                let revealed_at = match &contract.status {
                    TimeLockStatus::ClaimRevealed { revealed_at } => *revealed_at,
                    _ => return Err(ChronxError::InvalidClaimStateTransition),
                };

                let mut cs = self
                    .db
                    .get_claim(&lock_id.0)?
                    .ok_or_else(|| ChronxError::ClaimNotFound(lock_id.to_string()))?;

                // Check challenge window is still open.
                let thresholds = LaneThresholds::default_thresholds();
                let lane = ClaimLane::from_u8(cs.lane);
                let window = thresholds.challenge_window(lane);
                if now > revealed_at + window {
                    return Err(ChronxError::ClaimChallengeWindowExpired);
                }

                // Challenger must post at least the same bond as the agent.
                if *bond_amount < cs.commit_bond {
                    return Err(ChronxError::ClaimBondTooLow { min: cs.commit_bond });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance(),
                    });
                }

                sender.balance -= bond_amount;
                cs.challenger = Some(sender.account_id.clone());
                cs.challenge_bond = *bond_amount;
                cs.challenge_evidence_hash = Some(*evidence_hash);
                cs.challenged_at = Some(now);

                contract.status = TimeLockStatus::ClaimChallenged { challenged_at: now };
                staged.timelocks.push(contract);
                staged.claims.push(cs);
                Ok(())
            }

            // ── FinalizeClaim ─────────────────────────────────────────────────
            Action::FinalizeClaim { lock_id } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                let mut cs = self
                    .db
                    .get_claim(&lock_id.0)?
                    .ok_or_else(|| ChronxError::ClaimNotFound(lock_id.to_string()))?;

                match &contract.status {
                    TimeLockStatus::ClaimRevealed { revealed_at } => {
                        // No challenge: ensure challenge window has closed.
                        let thresholds = LaneThresholds::default_thresholds();
                        let lane = ClaimLane::from_u8(cs.lane);
                        let window = thresholds.challenge_window(lane);
                        if now <= *revealed_at + window {
                            return Err(ChronxError::ClaimChallengeWindowOpen);
                        }

                        // Agent wins: pay out lock amount + return bond.
                        let agent_id = cs.agent_id
                            .clone()
                            .ok_or(ChronxError::InvalidClaimStateTransition)?;
                        let payout = contract.amount + cs.commit_bond;

                        // If agent == transaction sender, credit in-place so that
                        // the staged_sender write in apply() carries the payout.
                        // Otherwise load the agent account from DB.
                        if agent_id == sender.account_id {
                            sender.balance += payout;
                        } else {
                            let mut agent_acc = self.db.get_account(&agent_id)?
                                .ok_or_else(|| ChronxError::UnknownAccount(agent_id.to_string()))?;
                            agent_acc.balance += payout;
                            staged.accounts.push(agent_acc);
                        }
                        cs.commit_bond = 0;

                        contract.status = TimeLockStatus::ClaimFinalized {
                            paid_to: agent_id.clone(),
                            finalized_at: now,
                        };
                        staged.timelocks.push(contract);
                        staged.claims.push(cs);
                        Ok(())
                    }

                    TimeLockStatus::ClaimChallenged { .. } => {
                        // MVP: challenger wins automatically.
                        // Full implementation would evaluate evidence off-chain via oracle/committee.
                        let challenger_id = cs.challenger
                            .clone()
                            .ok_or(ChronxError::InvalidClaimStateTransition)?;

                        // Challenger gets their bond back + agent's bond as reward.
                        // Lock funds are returned to sender (or protocol treasury in full impl).
                        let challenger_payout = cs.challenge_bond + cs.commit_bond;

                        let mut challenger_acc = self.db.get_account(&challenger_id)?
                            .ok_or_else(|| ChronxError::UnknownAccount(challenger_id.to_string()))?;
                        challenger_acc.balance += challenger_payout;

                        // Return lock amount to original sender.
                        let mut lock_sender = self.db.get_account(&contract.sender)?
                            .ok_or_else(|| ChronxError::UnknownAccount(contract.sender.to_string()))?;
                        lock_sender.balance += contract.amount;

                        cs.commit_bond = 0;
                        cs.challenge_bond = 0;

                        contract.status = TimeLockStatus::ClaimSlashed {
                            reason: SlashReason::SuccessfulChallenge,
                            slashed_at: now,
                        };
                        staged.accounts.push(challenger_acc);
                        staged.accounts.push(lock_sender);
                        staged.timelocks.push(contract);
                        staged.claims.push(cs);
                        Ok(())
                    }

                    _ => Err(ChronxError::InvalidClaimStateTransition),
                }
            }

            // ── RegisterProvider ──────────────────────────────────────────────
            Action::RegisterProvider { provider_class, jurisdictions, bond_amount } => {
                if *bond_amount < PROVIDER_BOND_CHRONOS {
                    return Err(ChronxError::ProviderBondTooLow { min: PROVIDER_BOND_CHRONOS });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance(),
                    });
                }
                if self.db.get_provider(&sender.account_id)?.is_some() {
                    return Err(ChronxError::ProviderAlreadyRegistered);
                }

                sender.balance -= bond_amount;

                // Extract current signing key from sender's auth policy.
                let pubkey = match &sender.auth_policy {
                    AuthPolicy::SingleSig { public_key } => public_key.clone(),
                    AuthPolicy::RecoveryEnabled { owner_key, .. } => owner_key.clone(),
                    AuthPolicy::MultiSig { public_keys, .. } =>
                        public_keys.first().cloned().unwrap_or_else(|| chronx_core::types::DilithiumPublicKey(vec![])),
                };

                let record = ProviderRecord {
                    provider_id: sender.account_id.clone(),
                    public_keys: vec![pubkey],
                    provider_class: provider_class.clone(),
                    jurisdictions: jurisdictions.clone(),
                    status: ProviderStatus::Active,
                    registration_bond: *bond_amount,
                    registered_at: now,
                };
                staged.providers.push(record);
                Ok(())
            }

            // ── RevokeProvider ────────────────────────────────────────────────
            Action::RevokeProvider { provider_id } => {
                let mut record = self
                    .db
                    .get_provider(provider_id)?
                    .ok_or_else(|| ChronxError::ProviderNotFound(provider_id.to_string()))?;

                // Only the provider themselves may self-revoke in this MVP.
                if sender.account_id != *provider_id {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                record.status = ProviderStatus::Revoked { revoked_at: now };
                // Return registration bond on clean revocation.
                sender.balance += record.registration_bond;
                record.registration_bond = 0;
                staged.providers.push(record);
                Ok(())
            }

            // ── RotateProviderKey ─────────────────────────────────────────────
            Action::RotateProviderKey { new_public_key } => {
                let mut record = self
                    .db
                    .get_provider(&sender.account_id)?
                    .ok_or_else(|| ChronxError::ProviderNotFound(sender.account_id.to_string()))?;

                if let ProviderStatus::Revoked { .. } = &record.status {
                    return Err(ChronxError::ProviderRevoked);
                }

                record.public_keys.push(new_public_key.clone());
                staged.providers.push(record);
                Ok(())
            }

            // ── RegisterSchema ────────────────────────────────────────────────
            Action::RegisterSchema {
                name,
                version,
                required_fields_hash,
                provider_class_thresholds,
                min_providers,
                max_cert_age_secs,
                bond_amount,
            } => {
                if *bond_amount < SCHEMA_BOND_CHRONOS {
                    return Err(ChronxError::SchemaBondTooLow { min: SCHEMA_BOND_CHRONOS });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance(),
                    });
                }

                sender.balance -= bond_amount;

                let schema_id = self.db.next_schema_id()?;
                let schema = CertificateSchema {
                    schema_id,
                    name: name.clone(),
                    version: *version,
                    required_fields_hash: *required_fields_hash,
                    provider_class_thresholds: provider_class_thresholds.clone(),
                    signature_rules: SignatureRules {
                        min_providers: *min_providers,
                        max_cert_age_secs: *max_cert_age_secs,
                    },
                    active: true,
                    registered_by: sender.account_id.clone(),
                    registered_at: now,
                };
                staged.schemas.push(schema);
                Ok(())
            }

            // ── DeactivateSchema ──────────────────────────────────────────────
            Action::DeactivateSchema { schema_id } => {
                let mut schema = self
                    .db
                    .get_schema(*schema_id)?
                    .ok_or(ChronxError::SchemaNotFound(*schema_id))?;

                // Only the registrant may deactivate in this MVP.
                if schema.registered_by != sender.account_id {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                schema.active = false;
                staged.schemas.push(schema);
                Ok(())
            }

            // ── SubmitOraclePrice ─────────────────────────────────────────────
            Action::SubmitOraclePrice { pair, price_cents } => {
                // Caller must be a registered provider of class "oracle".
                let record = self
                    .db
                    .get_provider(&sender.account_id)?
                    .ok_or_else(|| ChronxError::ProviderNotFound(sender.account_id.to_string()))?;

                if let ProviderStatus::Revoked { .. } = &record.status {
                    return Err(ChronxError::ProviderRevoked);
                }
                if record.provider_class != "oracle" {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                let sub = OracleSubmission {
                    submitter: sender.account_id.clone(),
                    pair: pair.clone(),
                    price_cents: *price_cents,
                    submitted_at: now,
                };
                staged.oracle_submissions.push(sub);
                Ok(())
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use chronx_core::account::{AuthPolicy, TimeLockContract, TimeLockStatus};
    use chronx_core::constants::{
        CHRONOS_PER_KX, MIN_RECOVERY_BOND_CHRONOS, MIN_VERIFIER_STAKE_CHRONOS,
        PROVIDER_BOND_CHRONOS,
    };
    use chronx_core::transaction::{Action, AuthScheme, Transaction};
    use chronx_core::types::{EvidenceHash, TimeLockId, TxId};
    use chronx_crypto::{mine_pow, tx_id_from_body, KeyPair};
    use chronx_crypto::hash::account_id_from_pubkey;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn temp_db(name: &str) -> StateDb {
        let dir = std::env::temp_dir().join(format!("chronx_engine_test_{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        StateDb::open(&dir).expect("open temp db")
    }

    fn make_tx(kp: &KeyPair, nonce: u64, actions: Vec<Action>) -> Transaction {
        let mut tx = Transaction {
            tx_id: TxId::from_bytes([0u8; 32]),
            parents: vec![],
            timestamp: 1_000_000,
            nonce,
            from: kp.account_id.clone(),
            actions,
            pow_nonce: 0,
            signatures: vec![],
            auth_scheme: AuthScheme::SingleSig,
            tx_version: 1,
            client_ref: None,
            fee_chronos: 0,
            expires_at: None,
        };
        let body_bytes = tx.body_bytes();
        tx.tx_id = tx_id_from_body(&body_bytes);
        tx.signatures = vec![kp.sign(&body_bytes)];
        tx
    }

    fn seed_account(db: &StateDb, kp: &KeyPair, balance: u128) {
        let mut acc = Account::new(
            kp.account_id.clone(),
            AuthPolicy::SingleSig { public_key: kp.public_key.clone() },
        );
        acc.balance = balance;
        db.put_account(&acc).unwrap();
    }

    fn seed_timelock(db: &StateDb, lock_id: TxId, sender: &KeyPair, recipient: &KeyPair, amount: u128, unlock_at: i64) {
        let contract = TimeLockContract {
            id: lock_id,
            sender: sender.account_id.clone(),
            recipient_key: recipient.public_key.clone(),
            recipient_account_id: account_id_from_pubkey(&recipient.public_key.0),
            amount,
            unlock_at,
            created_at: 0,
            status: TimeLockStatus::Pending,
            memo: None,
            lock_version: 0,
            claim_policy: None,
            beneficiary_anchor_commitment: None,
            org_identifier: None,
            cancellation_window_secs: None,
            notify_recipient: true,
            tags: None,
            private: false,
            expiry_policy: None,
            split_policy: None,
            claim_attempts_max: None,
            recurring: None,
            extension_data: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
        };
        db.put_timelock(&contract).unwrap();
    }

    /// Seed a V1 lock (with claim_policy set and org_identifier to avoid ambiguity).
    fn seed_v1_timelock(db: &StateDb, lock_id: TxId, sender: &KeyPair, recipient: &KeyPair, amount: u128, unlock_at: i64) {
        let contract = TimeLockContract {
            id: lock_id.clone(),
            sender: sender.account_id.clone(),
            recipient_key: recipient.public_key.clone(),
            recipient_account_id: account_id_from_pubkey(&recipient.public_key.0),
            amount,
            unlock_at,
            created_at: 0,
            status: TimeLockStatus::Pending,
            memo: None,
            lock_version: 1,
            claim_policy: Some(1),
            beneficiary_anchor_commitment: None,
            org_identifier: Some("Acme Corp".to_string()),
            cancellation_window_secs: None,
            notify_recipient: true,
            tags: None,
            private: false,
            expiry_policy: None,
            split_policy: None,
            claim_attempts_max: None,
            recurring: None,
            extension_data: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
        };
        db.put_timelock(&contract).unwrap();
    }

    /// Seed an oracle snapshot so open_claim can read it.
    /// Build a minimal `Action::TimeLockCreate` with all new fields set to None/defaults.
    fn tlc_action(recipient: chronx_core::types::DilithiumPublicKey, amount: u128, unlock_at: i64, memo: Option<String>) -> Action {
        Action::TimeLockCreate {
            recipient,
            amount,
            unlock_at,
            memo,
            cancellation_window_secs: None,
            notify_recipient: None,
            tags: None,
            private: None,
            expiry_policy: None,
            split_policy: None,
            claim_attempts_max: None,
            recurring: None,
            extension_data: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
        }
    }

    fn seed_oracle(db: &StateDb, price_cents: u64) {
        let snap = OracleSnapshot {
            pair: "KX/USD".to_string(),
            price_cents,
            num_submissions: 3,
            updated_at: 0,
        };
        db.put_oracle_snapshot(&snap).unwrap();
    }

    fn make_tx_with_parents(kp: &KeyPair, nonce: u64, parents: Vec<TxId>, actions: Vec<Action>) -> Transaction {
        let mut tx = Transaction {
            tx_id: TxId::from_bytes([0u8; 32]),
            parents,
            timestamp: 1_000_000,
            nonce,
            from: kp.account_id.clone(),
            actions,
            pow_nonce: 0,
            signatures: vec![],
            auth_scheme: AuthScheme::SingleSig,
            tx_version: 1,
            client_ref: None,
            fee_chronos: 0,
            expires_at: None,
        };
        let body_bytes = tx.body_bytes();
        tx.pow_nonce = mine_pow(&body_bytes, 0);
        tx.tx_id = tx_id_from_body(&body_bytes);
        tx.signatures = vec![kp.sign(&body_bytes)];
        tx
    }

    const NOW: i64 = 2_000_000;

    // ── Transfer ──────────────────────────────────────────────────────────────

    #[test]
    fn transfer_valid() {
        let engine = StateEngine::new(Arc::new(temp_db("t_valid")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let tx = make_tx(&sender, 0, vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: 10 * CHRONOS_PER_KX,
        }]);
        engine.apply(&tx, NOW).unwrap();

        let s = engine.db.get_account(&sender.account_id).unwrap().unwrap();
        let r = engine.db.get_account(&recipient.account_id).unwrap().unwrap();
        assert_eq!(s.balance, 90 * CHRONOS_PER_KX);
        assert_eq!(r.balance, 10 * CHRONOS_PER_KX);
        assert_eq!(s.nonce, 1);
    }

    #[test]
    fn transfer_self_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("t_self")), 0);
        let kp = KeyPair::generate();
        seed_account(&engine.db, &kp, 100 * CHRONOS_PER_KX);
        let tx = make_tx(&kp, 0, vec![Action::Transfer {
            to: kp.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::SelfTransfer));
    }

    #[test]
    fn transfer_insufficient_balance() {
        let engine = StateEngine::new(Arc::new(temp_db("t_insuf")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 5 * CHRONOS_PER_KX);
        let tx = make_tx(&sender, 0, vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: 10 * CHRONOS_PER_KX,
        }]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::InsufficientBalance { .. }));
    }

    #[test]
    fn transfer_bad_nonce() {
        let engine = StateEngine::new(Arc::new(temp_db("t_nonce")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);
        let tx = make_tx(&sender, 99, vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::InvalidNonce { .. }));
    }

    // ── TimeLockCreate ────────────────────────────────────────────────────────

    #[test]
    fn timelock_create_valid() {
        let engine = StateEngine::new(Arc::new(temp_db("tlc_valid")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let unlock_at = NOW + 86_400;
        let tx = make_tx(&sender, 0, vec![tlc_action(recipient.public_key.clone(), 50 * CHRONOS_PER_KX, unlock_at, Some("test".into()))]);
        engine.apply(&tx, NOW).unwrap();

        let s = engine.db.get_account(&sender.account_id).unwrap().unwrap();
        assert_eq!(s.balance, 50 * CHRONOS_PER_KX);

        let contract = engine.db.get_timelock(&tx.tx_id).unwrap().unwrap();
        assert_eq!(contract.amount, 50 * CHRONOS_PER_KX);
        assert_eq!(contract.unlock_at, unlock_at);
        assert_eq!(contract.status, TimeLockStatus::Pending);
        assert_eq!(contract.lock_version, 0, "new locks from TimeLockCreate must be V0");
    }

    #[test]
    fn timelock_create_past_unlock_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("tlc_past")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);
        let tx = make_tx(&sender, 0, vec![tlc_action(recipient.public_key.clone(), CHRONOS_PER_KX, NOW - 1, None)]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::UnlockTimestampInPast));
    }

    #[test]
    fn timelock_create_zero_amount_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("tlc_zero")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);
        let tx = make_tx(&sender, 0, vec![tlc_action(recipient.public_key.clone(), 0, NOW + 86_400, None)]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::ZeroAmount));
    }

    // ── TimeLockClaim ─────────────────────────────────────────────────────────

    #[test]
    fn timelock_claim_after_maturity() {
        let engine = StateEngine::new(Arc::new(temp_db("tl_claim")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 0);
        seed_account(&engine.db, &recipient, 0);

        let lock_id = TxId::from_bytes([42u8; 32]);
        seed_timelock(&engine.db, lock_id.clone(), &sender, &recipient, 50 * CHRONOS_PER_KX, NOW - 1);

        let tx = make_tx(&recipient, 0, vec![Action::TimeLockClaim {
            lock_id: TimeLockId(lock_id),
        }]);
        engine.apply(&tx, NOW).unwrap();

        let r = engine.db.get_account(&recipient.account_id).unwrap().unwrap();
        assert_eq!(r.balance, 50 * CHRONOS_PER_KX);
    }

    #[test]
    fn timelock_claim_too_early() {
        let engine = StateEngine::new(Arc::new(temp_db("tl_early")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 0);
        seed_account(&engine.db, &recipient, 0);
        let lock_id = TxId::from_bytes([43u8; 32]);
        seed_timelock(&engine.db, lock_id.clone(), &sender, &recipient, 50 * CHRONOS_PER_KX, NOW + 86_400);
        let tx = make_tx(&recipient, 0, vec![Action::TimeLockClaim {
            lock_id: TimeLockId(lock_id),
        }]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::TimeLockNotMatured { .. }));
    }

    #[test]
    fn timelock_claim_wrong_claimer() {
        let engine = StateEngine::new(Arc::new(temp_db("tl_wrong")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        let impostor = KeyPair::generate();
        seed_account(&engine.db, &sender, 0);
        seed_account(&engine.db, &impostor, 0);
        let lock_id = TxId::from_bytes([44u8; 32]);
        seed_timelock(&engine.db, lock_id.clone(), &sender, &recipient, 50 * CHRONOS_PER_KX, NOW - 1);
        let tx = make_tx(&impostor, 0, vec![Action::TimeLockClaim {
            lock_id: TimeLockId(lock_id),
        }]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::AuthPolicyViolation));
    }

    // ── Recovery ──────────────────────────────────────────────────────────────

    #[test]
    fn recovery_start_valid() {
        let engine = StateEngine::new(Arc::new(temp_db("rec_start")), 0);
        let requester = KeyPair::generate();
        let target_kp = KeyPair::generate();
        let new_owner = KeyPair::generate();
        seed_account(&engine.db, &requester, MIN_RECOVERY_BOND_CHRONOS + CHRONOS_PER_KX);
        engine.db.put_account(&Account::new(
            target_kp.account_id.clone(),
            AuthPolicy::SingleSig { public_key: target_kp.public_key.clone() },
        )).unwrap();

        let tx = make_tx(&requester, 0, vec![Action::StartRecovery {
            target_account: target_kp.account_id.clone(),
            proposed_owner_key: new_owner.public_key.clone(),
            evidence_hash: EvidenceHash([0xABu8; 32]),
            bond_amount: MIN_RECOVERY_BOND_CHRONOS,
        }]);
        engine.apply(&tx, NOW).unwrap();

        let req = engine.db.get_account(&requester.account_id).unwrap().unwrap();
        assert_eq!(req.balance, CHRONOS_PER_KX);
        let tgt = engine.db.get_account(&target_kp.account_id).unwrap().unwrap();
        assert!(tgt.recovery_state.active);
    }

    #[test]
    fn recovery_bond_too_low() {
        let engine = StateEngine::new(Arc::new(temp_db("rec_bond_low")), 0);
        let requester = KeyPair::generate();
        let target_kp = KeyPair::generate();
        let new_owner = KeyPair::generate();
        seed_account(&engine.db, &requester, MIN_RECOVERY_BOND_CHRONOS * 2);
        engine.db.put_account(&Account::new(
            target_kp.account_id.clone(),
            AuthPolicy::SingleSig { public_key: target_kp.public_key.clone() },
        )).unwrap();
        let tx = make_tx(&requester, 0, vec![Action::StartRecovery {
            target_account: target_kp.account_id.clone(),
            proposed_owner_key: new_owner.public_key.clone(),
            evidence_hash: EvidenceHash([0u8; 32]),
            bond_amount: MIN_RECOVERY_BOND_CHRONOS - 1,
        }]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::RecoveryBondTooLow { .. }));
    }

    #[test]
    fn register_verifier_valid() {
        let engine = StateEngine::new(Arc::new(temp_db("reg_verifier")), 0);
        let kp = KeyPair::generate();
        seed_account(&engine.db, &kp, MIN_VERIFIER_STAKE_CHRONOS + CHRONOS_PER_KX);
        let tx = make_tx(&kp, 0, vec![Action::RegisterVerifier {
            stake_amount: MIN_VERIFIER_STAKE_CHRONOS,
        }]);
        engine.apply(&tx, NOW).unwrap();
        let acc = engine.db.get_account(&kp.account_id).unwrap().unwrap();
        assert!(acc.is_verifier);
        assert_eq!(acc.verifier_stake, MIN_VERIFIER_STAKE_CHRONOS);
        assert_eq!(acc.spendable_balance(), CHRONOS_PER_KX);
    }

    #[test]
    fn recovery_full_workflow() {
        let engine = StateEngine::new(Arc::new(temp_db("rec_full")), 0);
        let requester = KeyPair::generate();
        let target_kp = KeyPair::generate();
        let new_owner = KeyPair::generate();
        let verifiers: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate()).collect();

        let big = MIN_VERIFIER_STAKE_CHRONOS + MIN_RECOVERY_BOND_CHRONOS + 10 * CHRONOS_PER_KX;
        seed_account(&engine.db, &requester, big);
        engine.db.put_account(&Account::new(
            target_kp.account_id.clone(),
            AuthPolicy::SingleSig { public_key: target_kp.public_key.clone() },
        )).unwrap();
        for v in &verifiers {
            seed_account(&engine.db, v, MIN_VERIFIER_STAKE_CHRONOS + CHRONOS_PER_KX);
        }

        engine.apply(&make_tx(&requester, 0, vec![Action::StartRecovery {
            target_account: target_kp.account_id.clone(),
            proposed_owner_key: new_owner.public_key.clone(),
            evidence_hash: EvidenceHash([0x01u8; 32]),
            bond_amount: MIN_RECOVERY_BOND_CHRONOS,
        }]), NOW).unwrap();

        for v in &verifiers {
            engine.apply(&make_tx(v, 0, vec![Action::RegisterVerifier {
                stake_amount: MIN_VERIFIER_STAKE_CHRONOS,
            }]), NOW).unwrap();
        }

        for v in &verifiers {
            engine.apply(&make_tx(v, 1, vec![Action::VoteRecovery {
                target_account: target_kp.account_id.clone(),
                approve: true,
                fee_bid: 0,
            }]), NOW).unwrap();
        }

        let mut tgt = engine.db.get_account(&target_kp.account_id).unwrap().unwrap();
        tgt.recovery_state.recovery_execute_after = Some(NOW - 1);
        engine.db.put_account(&tgt).unwrap();

        engine.apply(&make_tx(&requester, 1, vec![Action::FinalizeRecovery {
            target_account: target_kp.account_id.clone(),
        }]), NOW).unwrap();

        let final_tgt = engine.db.get_account(&target_kp.account_id).unwrap().unwrap();
        assert!(!final_tgt.recovery_state.active);
        match &final_tgt.auth_policy {
            AuthPolicy::RecoveryEnabled { owner_key, .. } => {
                assert_eq!(*owner_key, new_owner.public_key);
            }
            _ => panic!("expected RecoveryEnabled after finalization"),
        }
    }

    // ── DAG vertex persistence ─────────────────────────────────────────────────

    #[test]
    fn vertex_written_to_db_after_apply() {
        let engine = StateEngine::new(Arc::new(temp_db("dag_vertex_persist")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let tx = make_tx(&sender, 0, vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        engine.apply(&tx, NOW).unwrap();

        assert!(engine.db.vertex_exists(&tx.tx_id), "vertex not persisted after apply");
        let v = engine.db.get_vertex(&tx.tx_id).unwrap().unwrap();
        assert_eq!(v.depth, 0);
    }

    #[test]
    fn chained_tx_parent_accepted() {
        let engine = StateEngine::new(Arc::new(temp_db("dag_chain")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let tx1 = make_tx(&sender, 0, vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        engine.apply(&tx1, NOW).unwrap();

        let tx2 = make_tx_with_parents(&sender, 1, vec![tx1.tx_id.clone()], vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        engine.apply(&tx2, NOW).unwrap();

        let v2 = engine.db.get_vertex(&tx2.tx_id).unwrap().unwrap();
        assert_eq!(v2.depth, 1);
        let s = engine.db.get_account(&sender.account_id).unwrap().unwrap();
        assert_eq!(s.balance, 98 * CHRONOS_PER_KX);
        assert_eq!(s.nonce, 2);
    }

    #[test]
    fn duplicate_tx_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("dag_dup")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let tx = make_tx(&sender, 0, vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        engine.apply(&tx, NOW).unwrap();
        let err = engine.apply(&tx, NOW).unwrap_err();
        assert!(matches!(err, ChronxError::DuplicateVertex(_)));
    }

    // ── V2 Claims: Honest claim ───────────────────────────────────────────────

    #[test]
    fn honest_claim_full_flow() {
        let engine = StateEngine::new(Arc::new(temp_db("claim_honest")), 0);
        let lock_sender = KeyPair::generate();
        let agent = KeyPair::generate();

        // Fund agent for bonds + some balance.
        let bond = 10 * CHRONOS_PER_KX; // 10 KX — trivial lane minimum.
        seed_account(&engine.db, &lock_sender, 0);
        seed_account(&engine.db, &agent, bond + CHRONOS_PER_KX);

        let lock_id = TxId::from_bytes([55u8; 32]);
        let lock_amount = 5 * CHRONOS_PER_KX;
        seed_v1_timelock(&engine.db, lock_id.clone(), &lock_sender, &agent, lock_amount, NOW - 1);
        seed_oracle(&engine.db, 100); // $1 per KX → 5 KX = $5 → trivial lane

        // 1. OpenClaim
        engine.apply(&make_tx(&agent, 0, vec![Action::OpenClaim {
            lock_id: TimeLockId(lock_id.clone()),
        }]), NOW).unwrap();
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(c.status, TimeLockStatus::ClaimOpen { .. }), "expected ClaimOpen after open_claim");

        // 2. SubmitClaimCommit
        let payload = b"I am the beneficiary - Alice Smith";
        let salt = [0xAAu8; 32];
        let commit_hash = {
            let mut h = blake3::Hasher::new();
            h.update(payload);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        engine.apply(&make_tx(&agent, 1, vec![Action::SubmitClaimCommit {
            lock_id: TimeLockId(lock_id.clone()),
            commit_hash,
            bond_amount: bond,
        }]), NOW).unwrap();
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(c.status, TimeLockStatus::ClaimCommitted { .. }), "expected ClaimCommitted");

        // 3. RevealClaim (within window)
        engine.apply(&make_tx(&agent, 2, vec![Action::RevealClaim {
            lock_id: TimeLockId(lock_id.clone()),
            payload: payload.to_vec(),
            salt,
            certificates: vec![],
        }]), NOW + 1).unwrap();
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(c.status, TimeLockStatus::ClaimRevealed { .. }), "expected ClaimRevealed");

        // 4. FinalizeClaim (after challenge window — trivial: 7 days)
        let after_window = NOW + 1 + 7 * 24 * 3600 + 1;
        engine.apply(&make_tx(&agent, 3, vec![Action::FinalizeClaim {
            lock_id: TimeLockId(lock_id.clone()),
        }]), after_window).unwrap();

        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(
            matches!(c.status, TimeLockStatus::ClaimFinalized { .. }),
            "expected ClaimFinalized, got {:?}", c.status
        );

        // Agent should have received lock_amount + bond back.
        let agent_acc = engine.db.get_account(&agent.account_id).unwrap().unwrap();
        assert_eq!(
            agent_acc.balance,
            CHRONOS_PER_KX + lock_amount + bond,
            "agent balance should be initial_balance - bond + lock_amount + bond = initial + lock_amount"
        );
    }

    // ── V2 Claims: Fraudulent claim — reveal hash mismatch ────────────────────

    #[test]
    fn fraudulent_claim_hash_mismatch_slashed() {
        let engine = StateEngine::new(Arc::new(temp_db("claim_fraud")), 0);
        let lock_sender = KeyPair::generate();
        let agent = KeyPair::generate();

        let bond = 10 * CHRONOS_PER_KX;
        seed_account(&engine.db, &lock_sender, 0);
        seed_account(&engine.db, &agent, bond + 5 * CHRONOS_PER_KX);

        let lock_id = TxId::from_bytes([77u8; 32]);
        seed_v1_timelock(&engine.db, lock_id.clone(), &lock_sender, &agent, 5 * CHRONOS_PER_KX, NOW - 1);
        seed_oracle(&engine.db, 100);

        // OpenClaim + SubmitClaimCommit with a valid commit_hash.
        engine.apply(&make_tx(&agent, 0, vec![Action::OpenClaim {
            lock_id: TimeLockId(lock_id.clone()),
        }]), NOW).unwrap();

        let real_payload = b"real payload";
        let salt = [0xBBu8; 32];
        let commit_hash = {
            let mut h = blake3::Hasher::new();
            h.update(real_payload);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        engine.apply(&make_tx(&agent, 1, vec![Action::SubmitClaimCommit {
            lock_id: TimeLockId(lock_id.clone()),
            commit_hash,
            bond_amount: bond,
        }]), NOW).unwrap();

        // Reveal with WRONG payload — hash mismatch → slash committed as Ok.
        engine.apply(&make_tx(&agent, 2, vec![Action::RevealClaim {
            lock_id: TimeLockId(lock_id.clone()),
            payload: b"tampered payload".to_vec(),
            salt,
            certificates: vec![],
        }]), NOW + 1).unwrap();

        // Status should be ClaimSlashed.
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(c.status, TimeLockStatus::ClaimSlashed { reason: SlashReason::RevealHashMismatch, .. }));
    }

    // ── V2 Claims: Successful challenge ──────────────────────────────────────

    #[test]
    fn successful_challenge_slashes_agent() {
        let engine = StateEngine::new(Arc::new(temp_db("claim_challenge")), 0);
        let lock_sender = KeyPair::generate();
        let agent = KeyPair::generate();
        let challenger = KeyPair::generate();

        let bond = 10 * CHRONOS_PER_KX;
        let lock_amount = 5 * CHRONOS_PER_KX;
        seed_account(&engine.db, &lock_sender, lock_amount); // needs balance to receive refund
        seed_account(&engine.db, &agent, bond + CHRONOS_PER_KX);
        seed_account(&engine.db, &challenger, bond * 2);

        let lock_id = TxId::from_bytes([88u8; 32]);
        seed_v1_timelock(&engine.db, lock_id.clone(), &lock_sender, &agent, lock_amount, NOW - 1);
        seed_oracle(&engine.db, 100);

        // 1. OpenClaim
        engine.apply(&make_tx(&agent, 0, vec![Action::OpenClaim {
            lock_id: TimeLockId(lock_id.clone()),
        }]), NOW).unwrap();

        // 2. SubmitClaimCommit
        let payload = b"agent claim";
        let salt = [0xCCu8; 32];
        let commit_hash = { let mut h = blake3::Hasher::new(); h.update(payload); h.update(&salt); *h.finalize().as_bytes() };
        engine.apply(&make_tx(&agent, 1, vec![Action::SubmitClaimCommit {
            lock_id: TimeLockId(lock_id.clone()),
            commit_hash,
            bond_amount: bond,
        }]), NOW).unwrap();

        // 3. RevealClaim (valid hash)
        engine.apply(&make_tx(&agent, 2, vec![Action::RevealClaim {
            lock_id: TimeLockId(lock_id.clone()),
            payload: payload.to_vec(),
            salt,
            certificates: vec![],
        }]), NOW + 1).unwrap();

        // 4. ChallengeClaimReveal (within 7-day window)
        engine.apply(&make_tx(&challenger, 0, vec![Action::ChallengeClaimReveal {
            lock_id: TimeLockId(lock_id.clone()),
            evidence_hash: [0xDDu8; 32],
            bond_amount: bond,
        }]), NOW + 2).unwrap();
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(c.status, TimeLockStatus::ClaimChallenged { .. }));

        // 5. FinalizeClaim — challenger wins (MVP)
        engine.apply(&make_tx(&agent, 3, vec![Action::FinalizeClaim {
            lock_id: TimeLockId(lock_id.clone()),
        }]), NOW + 3).unwrap();

        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(c.status, TimeLockStatus::ClaimSlashed { reason: SlashReason::SuccessfulChallenge, .. }));

        // Challenger gets back their bond + agent's bond.
        let ch_acc = engine.db.get_account(&challenger.account_id).unwrap().unwrap();
        assert_eq!(ch_acc.balance, bond * 2 - bond + bond + bond, "challenger: initial - bond + bond_back + agent_bond");
        // Sender gets lock_amount returned.
        let s_acc = engine.db.get_account(&lock_sender.account_id).unwrap().unwrap();
        assert_eq!(s_acc.balance, lock_amount * 2, "sender gets lock_amount back on top of seeded balance");
    }

    // ── V2 Claims: Ambiguity mode ─────────────────────────────────────────────

    #[test]
    fn ambiguity_mode_no_identifier() {
        let engine = StateEngine::new(Arc::new(temp_db("claim_ambig")), 0);
        let lock_sender = KeyPair::generate();
        let agent = KeyPair::generate();
        seed_account(&engine.db, &lock_sender, 0);
        seed_account(&engine.db, &agent, 100 * CHRONOS_PER_KX);
        seed_oracle(&engine.db, 100);

        // V1 lock with NO org_identifier and NO beneficiary_anchor_commitment.
        let lock_id = TxId::from_bytes([99u8; 32]);
        let contract = TimeLockContract {
            id: lock_id.clone(),
            sender: lock_sender.account_id.clone(),
            recipient_key: agent.public_key.clone(),
            recipient_account_id: account_id_from_pubkey(&agent.public_key.0),
            amount: 5 * CHRONOS_PER_KX,
            unlock_at: NOW - 1,
            created_at: 0,
            status: TimeLockStatus::Pending,
            memo: None,
            lock_version: 1,
            claim_policy: Some(1), // has a policy
            beneficiary_anchor_commitment: None, // no commitment
            org_identifier: None,               // no org
            cancellation_window_secs: None,
            notify_recipient: true,
            tags: None,
            private: false,
            expiry_policy: None,
            split_policy: None,
            claim_attempts_max: None,
            recurring: None,
            extension_data: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
        };
        engine.db.put_timelock(&contract).unwrap();

        // OpenClaim should transition to Ambiguous, not ClaimOpen.
        engine.apply(&make_tx(&agent, 0, vec![Action::OpenClaim {
            lock_id: TimeLockId(lock_id.clone()),
        }]), NOW).unwrap();

        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(c.status, TimeLockStatus::Ambiguous { .. }),
            "expected Ambiguous for lock with no unique identifier, got {:?}", c.status);
    }

    // ── V2 Claims: Oracle oracle manipulation attempt rejected ────────────────

    #[test]
    fn oracle_submission_rejected_for_non_oracle_provider() {
        let engine = StateEngine::new(Arc::new(temp_db("oracle_manip")), 0);
        let submitter = KeyPair::generate();
        seed_account(&engine.db, &submitter, PROVIDER_BOND_CHRONOS + CHRONOS_PER_KX);

        // Register as "kyc" provider (not "oracle").
        engine.apply(&make_tx(&submitter, 0, vec![Action::RegisterProvider {
            provider_class: "kyc".to_string(),
            jurisdictions: vec!["US".to_string()],
            bond_amount: PROVIDER_BOND_CHRONOS,
        }]), NOW).unwrap();

        // Attempt to submit oracle price — should fail.
        let err = engine.apply(&make_tx(&submitter, 1, vec![Action::SubmitOraclePrice {
            pair: "KX/USD".to_string(),
            price_cents: 999_999_999, // malicious inflated price
        }]), NOW).unwrap_err();
        assert!(matches!(err, ChronxError::AuthPolicyViolation),
            "non-oracle provider must not submit oracle prices");
    }

    // ── V2 Claims: Compliance certificate requirement (structural check) ───────

    #[test]
    fn v1_lock_requires_claims_framework() {
        let engine = StateEngine::new(Arc::new(temp_db("claim_v1_direct")), 0);
        let lock_sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &lock_sender, 0);
        seed_account(&engine.db, &recipient, 0);

        // V1 lock with claim_policy set.
        let lock_id = TxId::from_bytes([111u8; 32]);
        seed_v1_timelock(&engine.db, lock_id.clone(), &lock_sender, &recipient, CHRONOS_PER_KX, NOW - 1);

        // Attempting direct TimeLockClaim must fail.
        let err = engine.apply(&make_tx(&recipient, 0, vec![Action::TimeLockClaim {
            lock_id: TimeLockId(lock_id),
        }]), NOW).unwrap_err();
        assert!(matches!(err, ChronxError::LockRequiresClaimsFramework),
            "V1 lock must not be directly claimable");
    }
}
