use hex;
use chronx_core::account::{Account, AuthPolicy, TimeLockContract, TimeLockStatus};
use chronx_core::claims::{
    CertificateSchema, ClaimLane, ClaimState, LaneThresholds, OracleSnapshot, OracleSubmission,
    ProviderRecord, ProviderStatus, SignatureRules, SlashReason
};
use chronx_core::constants::{AUTO_CANCELLATION_WINDOW_SECS, CANCELLATION_WINDOW_MAX_SECS, CONDITIONAL_MAX_ATTESTORS, CONDITIONAL_MIN_ATTESTORS, CREDIT_MAX_EXPIRY_SECONDS, CREDIT_MIN_CEILING_CHRONOS, DEPOSIT_DEFAULT_GRACE_SECONDS, DEPOSIT_MAX_RATE_BASIS_POINTS, DEPOSIT_MAX_TERM_SECONDS, DEPOSIT_MIN_TERM_SECONDS, INVOICE_MAX_EXPIRY_SECONDS, INVOICE_MIN_EXPIRY_SECONDS, LEDGER_MAX_SUMMARY_BYTES, MAX_EXTENSION_DATA_BYTES, MAX_LOCK_DURATION_YEARS, MAX_MEMO_BYTES, MAX_RECURRING_COUNT, MAX_TAGS_PER_LOCK, MAX_TAG_LENGTH, MIN_CHALLENGE_BOND_CHRONOS, MIN_LOCK_AMOUNT_CHRONOS, MIN_LOCK_DURATION_SECS, MIN_RECOVERY_BOND_CHRONOS, MIN_VERIFIER_STAKE_CHRONOS, ONE_YEAR_SECS, ORACLE_MAX_AGE_SECS, ORACLE_MIN_SUBMISSIONS, PROVIDER_BOND_CHRONOS, RECOVERY_CHALLENGE_WINDOW_SECS, RECOVERY_EXECUTION_DELAY_SECS, RECOVERY_VERIFIER_THRESHOLD, SCHEMA_BOND_CHRONOS};
    
use std::collections::HashSet;
use std::sync::Arc;

use chronx_core::error::ChronxError;
use chronx_core::transaction::{
    Action, Transaction,
      
      
      Compounding,
      ConditionalFallback,
     LedgerEntryType
    
};
use chronx_core::types::Timestamp;
use chronx_crypto::hash::account_id_from_pubkey;
use chronx_dag::validation::{validate_signatures, validate_vertex};
use chronx_dag::vertex::Vertex;
use tracing::{info, warn};

use crate::db::{

    StateDb,
    InvoiceRecord, InvoiceStatus,
    CreditRecord, CreditStatus,
    DepositRecord, DepositStatus,
    ConditionalRecord, ConditionalStatus,
    LedgerEntryRecord,
      LoanDefaultRecord,
    FriendlyLoanRecord
};

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
    /// V3.3 email claim hashes to persist: (lock_id, blake3_hash_of_secret).
    email_hashes: Vec<(chronx_core::types::TxId, [u8; 32])>,
    /// Lock IDs already acted on in this transaction (prevents double-credit).
    acted_lock_ids: HashSet<[u8; 32]>
}

// ── StateEngine ───────────────────────────────────────────────────────────────

/// The state transition engine.
///
/// Validates and applies transactions to the persistent state database.
/// Each `apply` call is atomic: either all actions succeed or none do.
pub struct StateEngine {
    pub db: Arc<StateDb>,
    pub pow_difficulty: u8,
    /// Max transactions per wallet per minute. Default 10.
    pub tx_rate_limit_per_minute: u64,
    /// Max loan actions per wallet per day. Default 100.
    pub loan_rate_limit_per_day: u64
}

impl StateEngine {
    pub fn new(db: Arc<StateDb>, pow_difficulty: u8) -> Self {
        Self {
            db,
            pow_difficulty,
            tx_rate_limit_per_minute: 10,
            loan_rate_limit_per_day: 100
        }
    }

    /// Check general transaction rate limit. Persisted to sled.
    fn check_tx_rate_limit(&self, wallet: &str, now: i64) -> Result<(), ChronxError> {
        let key = format!("rl:tx:{}", wallet);
        let cutoff = now - 60; // 1 minute window
        let mut timestamps: Vec<i64> = self.db.get_meta(&key)
            .ok().flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        timestamps.retain(|&ts| ts > cutoff);
        if timestamps.len() as u64 >= self.tx_rate_limit_per_minute {
            return Err(ChronxError::RateLimitExceeded);
        }
        timestamps.push(now);
        let _ = self.db.put_meta(&key, &serde_json::to_vec(&timestamps).unwrap_or_default());
        Ok(())
    }

    /// Check loan action rate limit. Persisted to sled.
    fn check_loan_rate_limit(&self, wallet: &str, now: i64) -> Result<(), ChronxError> {
        let key = format!("rl:loan:{}", wallet);
        let cutoff = now - 86400; // 24 hour window
        let mut timestamps: Vec<i64> = self.db.get_meta(&key)
            .ok().flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        timestamps.retain(|&ts| ts > cutoff);
        if timestamps.len() as u64 >= self.loan_rate_limit_per_day {
            return Err(ChronxError::RateLimitExceeded);
        }
        timestamps.push(now);
        let _ = self.db.put_meta(&key, &serde_json::to_vec(&timestamps).unwrap_or_default());
        Ok(())
    }

    /// Validate and apply a transaction. Returns `Ok(())` on success.


    pub fn apply(&self, tx: &Transaction, now: Timestamp) -> Result<(), ChronxError> {
        // ── DAG-level validation ──────────────────────────────────────────────
        validate_vertex(tx, self.pow_difficulty, |pid| self.db.vertex_exists(pid))?;

        // ── General tx rate limit ─────────────────────────────────────────
        self.check_tx_rate_limit(&tx.from.to_string(), now)?;

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
        let mut sender = self
            .db
            .get_account(&tx.from)?
            .ok_or_else(|| ChronxError::UnknownAccount(tx.from.to_string()))?;

        // ── Key registration (P2PKH first-spend) ─────────────────────────────
        // Accounts created by receiving a Transfer have an empty auth_policy key
        // (the protocol can't know the recipient's public key at Transfer time).
        // When such an account first spends, it MUST include sender_public_key so
        // the engine can verify ownership (hash → account_id) and register the key.
        if let chronx_core::account::AuthPolicy::SingleSig { public_key } = &sender.auth_policy {
            if public_key.0.is_empty() {
                if let Some(provided_key) = &tx.sender_public_key {
                    let derived = account_id_from_pubkey(&provided_key.0);
                    if derived == tx.from {
                        sender.auth_policy = chronx_core::account::AuthPolicy::SingleSig {
                            public_key: provided_key.clone()
                        };
                    }
                    // If derived != tx.from, proceed with empty key → signature
                    // validation will fail below, rejecting the tx.
                }
            }
        }

        // ── Nonce check ───────────────────────────────────────────────────────
        if tx.nonce != sender.nonce {
            return Err(ChronxError::InvalidNonce {
                expected: sender.nonce,
                got: tx.nonce
            });
        }

        // ── Signature validation ──────────────────────────────────────────────
        validate_signatures(tx, &sender.auth_policy)?;

        // ── Apply each action ─────────────────────────────────────────────────
        let mut staged = StagedMutations::default();
        let mut sender = sender.clone();

        for (action_idx, action) in tx.actions.iter().enumerate() {
            self.apply_action(action, &mut sender, &mut staged, now, &tx.tx_id, action_idx)?;
        }

        // Increment nonce after all actions succeed.
        sender.nonce += 1;
        staged.accounts.push(sender);

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
        // V3.3 email claim hashes (written when an email lock is created).
        for (lock_id, hash) in &staged.email_hashes {
            self.db.put_email_claim_hash(lock_id, *hash)?;
        }

        // Update DAG tips.
        for parent_id in &tx.parents {
            let _ = self.db.remove_tip(parent_id);
        }
        self.db.add_tip(&tx.tx_id)?;

        // ── Compute balance Merkle state root ─────────────────────────────
        let state_root = match self.db.get_all_accounts() {
            Ok(accounts) => {
                let tree = chronx_core::merkle::BalanceMerkleTree::from_accounts(&accounts);
                let root = tree.root();
                let _ = self.db.put_latest_state_root(&root);
                Some(root)
            }
            Err(e) => {
                warn!(error = %e, "failed to compute state root");
                None
            }
        };

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
        let mut vertex = Vertex::new(tx.clone(), depth, now);
        vertex.state_root = state_root;
        self.db.put_vertex(&vertex)?;

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
            updated_at: now
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
        action_idx: usize,
    ) -> Result<(), ChronxError> {
        match action {
            // ── Transfer ─────────────────────────────────────────────────────
            Action::Transfer { to, amount, memo: _, memo_encrypted: _, memo_public: _, pay_as_amount: _ } => {
                if *amount == 0 {
                    return Err(ChronxError::ZeroAmount);
                }
                if *to == sender.account_id {
                    return Err(ChronxError::SelfTransfer);
                }
                if sender.spendable_balance() < *amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *amount,
                        have: sender.spendable_balance()
                    });
                }
                sender.balance -= amount;

                let mut recipient = self.db.get_account(to)?.unwrap_or_else(|| {
                    Account::new(
                        to.clone(),
                        AuthPolicy::SingleSig {
                            public_key: chronx_core::types::DilithiumPublicKey(vec![])
                        },
                    )
                });
                recipient.balance += amount;
                staged.accounts.push(recipient);
                Ok(())
            }

            // ── TimeLockCreate ────────────────────────────────────────────────
            Action::TimeLockCreate {
                recipient,
                amount,
                unlock_at,
                memo,
                cancellation_window_secs,
                notify_recipient,
                tags,
                private, memo_encrypted: _, memo_public: _, pay_as_amount: _pay_as_amount,
                expiry_policy,
                split_policy,
                claim_attempts_max,
                recurring,
                lock_marker,
                oracle_hint,
                jurisdiction_hint,
                governance_proposal_id,
                client_ref,
                email_recipient_hash,
                claim_window_secs,
                unclaimed_action,
                lock_type,
                yield_opt_out,
                lock_metadata,
                agent_managed: _,
                grantor_axiom_consent_hash: _,
                investable_fraction: _,
                risk_level: _,
                investment_exclusions: _,
                grantor_intent: _,
                extension_right,
                max_extensions,
                pay_as_execution: _pay_as_execution,
                ..
            } => {
                // ── Consensus validation ──────────────────────────────────────
                if *amount == 0 {
                    return Err(ChronxError::ZeroAmount);
                }
                if *amount < MIN_LOCK_AMOUNT_CHRONOS {
                    return Err(ChronxError::LockAmountTooSmall {
                        min: MIN_LOCK_AMOUNT_CHRONOS
                    });
                }
                // Email locks (0xC5 marker) may have unlock_at <= now for
                // "Send Now" — immediately claimable with a claim code.
                // Only enforce future-unlock for non-email locks.
                let is_email_lock = lock_marker
                    .as_ref()
                    .map(|d| d.len() == 33 && d[0] == 0xC5)
                    .unwrap_or(false);
                if !is_email_lock {
                    if *unlock_at <= now {
                        return Err(ChronxError::UnlockTimestampInPast);
                    }
                    if *unlock_at < now + MIN_LOCK_DURATION_SECS {
                        return Err(ChronxError::LockDurationTooShort {
                            min_secs: MIN_LOCK_DURATION_SECS
                        });
                    }
                }
                let max_unlock = now + (MAX_LOCK_DURATION_YEARS as i64) * 365 * 24 * 3600;
                if *unlock_at > max_unlock {
                    return Err(ChronxError::LockDurationTooLong {
                        max_years: MAX_LOCK_DURATION_YEARS
                    });
                }
                if let Some(ref m) = memo {
                    if m.len() > MAX_MEMO_BYTES {
                        return Err(ChronxError::MemoTooLong {
                            max: MAX_MEMO_BYTES
                        });
                    }
                }
                // Memo privacy rules (TYPE L identity requirement removed v2.5.31)
                // Any wallet can make a public memo — wallet UI warning is sufficient
                if let Some(t) = tags {
                    if t.len() > MAX_TAGS_PER_LOCK {
                        return Err(ChronxError::TooManyTags {
                            max: MAX_TAGS_PER_LOCK
                        });
                    }
                    for tag in t {
                        if tag.len() > MAX_TAG_LENGTH {
                            return Err(ChronxError::TagTooLong {
                                max: MAX_TAG_LENGTH
                            });
                        }
                    }
                }
                if let Some(ed) = lock_marker {
                    if ed.len() > MAX_EXTENSION_DATA_BYTES {
                        return Err(ChronxError::ExtensionDataTooLarge {
                            max: MAX_EXTENSION_DATA_BYTES
                        });
                    }
                }
                if let Some(w) = cancellation_window_secs {
                    if *w > CANCELLATION_WINDOW_MAX_SECS {
                        return Err(ChronxError::CancellationWindowTooLong {
                            max: CANCELLATION_WINDOW_MAX_SECS
                        });
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
                        RecurringPolicy::Annual { count } => *count
                    };
                    if count > MAX_RECURRING_COUNT {
                        return Err(ChronxError::RecurringCountTooLarge {
                            max: MAX_RECURRING_COUNT
                        });
                    }
                }

                if sender.spendable_balance() < *amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *amount,
                        have: sender.spendable_balance()
                    });
                }
                sender.balance -= amount;

                let recipient_account_id = account_id_from_pubkey(&recipient.0);
                // Derive a unique lock ID per action in multi-action transactions.
                // action_idx 0 → tx_id (backward compatible with single-action txs).
                // action_idx N>0 → BLAKE3(tx_id || N) truncated to TxId.
                let lock_id = if action_idx == 0 {
                    tx_id.clone()
                } else {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&tx_id.0);
                    hasher.update(&(action_idx as u32).to_le_bytes());
                    let h = hasher.finalize();
                    chronx_core::types::TxId(*h.as_bytes())
                };
                let contract = TimeLockContract {
                    id: lock_id.clone(),
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
                    cancellation_window_secs: cancellation_window_secs.or_else(|| {
                        // Auto-set 24-hour cancellation window for locks >= 1 year
                        if *unlock_at - now >= ONE_YEAR_SECS {
                            Some(AUTO_CANCELLATION_WINDOW_SECS)
                        } else {
                            None
                        }
                    }),
                    notify_recipient: notify_recipient.unwrap_or(true),
                    tags: tags.clone(),
                    private: private.unwrap_or(false),
                    expiry_policy: expiry_policy.clone(),
                    split_policy: split_policy.clone(),
                    claim_attempts_max: *claim_attempts_max,
                    recurring: recurring.clone(),
                    lock_marker: lock_marker.clone(),
                    oracle_hint: oracle_hint.clone(),
                    jurisdiction_hint: jurisdiction_hint.clone(),
                    governance_proposal_id: governance_proposal_id.clone(),
                    client_ref: *client_ref,
                    // ── V3.1 fields — defaults at creation time ───────────────
                    transferable: false,
                    transfer_policy: None,
                    current_beneficiary: None,
                    transfer_history: Vec::new(),
                    earliest_transfer_date: None,
                    email_recipient_hash: *email_recipient_hash,
                    claim_window_secs: *claim_window_secs,
                    unclaimed_action: unclaimed_action.clone(),
                    notification_sent: false,
                    // ── V3.2 Conditional Payment fields ──────────────────────
                    condition_description: None,
                    condition_expiry: None,
                    condition_oracle: None,
                    condition_precision: None,
                    condition_status: None,
                    condition_attestation_id: None,
                    condition_disputed: false,
                    condition_dispute_window_secs: None,
                    // ── V8 fields ───────────────────────────────────────────
                    lock_type: Some(match lock_type.as_deref() {
                        Some("S") => "S".to_string(),
                        Some("M") => "M".to_string(),
                        _ => "Y".to_string(),
                    }),
                    yield_opt_out: *yield_opt_out,
                    lock_metadata: lock_metadata.clone(),
                    // ── Genesis Zero — Extension fields ────────────────────────
                    extension_right: *extension_right,
                    max_extensions: *max_extensions,
                    extensions_used: None,

                };
                // V3.3 — detect email claim secret hash embedded in lock_marker.
                // Convention: lock_marker = [0xC5, <32 bytes of BLAKE3(claim_code)>].
                // The marker byte 0xC5 is chosen to avoid collision with future
                // general-purpose extension data. The wallet sets this on email locks.
                // Store convert_to in separate tree if provided
                if let Action::TimeLockCreate { convert_to: Some(ref cv), .. } = action {
                    let truncated = if cv.len() > 50 { &cv[..50] } else { cv.as_str() };
                    let _ = self.db.put_convert_to_suggestion(&lock_id, truncated);
                }
                if let Some(ref ext) = contract.lock_marker {
                    if ext.len() == 33 && ext[0] == 0xC5 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&ext[1..33]);
                        staged.email_hashes.push((lock_id.clone(), hash));
                    }
                }

                staged.timelocks.push(contract);
                Ok(())
            }

            // ── TimeLockClaim ─────────────────────────────────────────────────
            Action::TimeLockClaim { lock_id } => {
                // Prevent double-action on same lock within one transaction.
                if staged.acted_lock_ids.contains(&lock_id.0.0) {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }
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
                        unlock_time: contract.unlock_at
                    });
                }

                let expected_id = account_id_from_pubkey(&contract.recipient_key.0);
                if sender.account_id != expected_id {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                sender.balance += contract.amount;
                contract.status = TimeLockStatus::Claimed { claimed_at: now };
                staged.acted_lock_ids.insert(lock_id.0.0);
                staged.timelocks.push(contract);
                Ok(())
            }

            // ── TimeLockSell ──────────────────────────────────────────────────
            Action::TimeLockSell {
                lock_id: _,
                ask_price: _
            } => {
                warn!("TimeLockSell submitted — secondary market not active at V1");
                Err(ChronxError::FeatureNotActive(
                    "secondary market (TimeLockSell) is not active in V1".into(),
                ))
            }

            // ── CancelTimeLock ────────────────────────────────────────────────
            Action::CancelTimeLock { lock_id } => {
                // Prevent double-action on same lock within one transaction.
                if staged.acted_lock_ids.contains(&lock_id.0.0) {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }
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
                staged.acted_lock_ids.insert(lock_id.0.0);
                staged.timelocks.push(contract);
                Ok(())
            }

            // ── StartRecovery ─────────────────────────────────────────────────
            Action::StartRecovery {
                target_account,
                proposed_owner_key,
                evidence_hash,
                bond_amount
            } => {
                if *bond_amount < MIN_RECOVERY_BOND_CHRONOS {
                    return Err(ChronxError::RecoveryBondTooLow {
                        min: MIN_RECOVERY_BOND_CHRONOS
                    });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance()
                    });
                }

                let mut target = self
                    .db
                    .get_account(target_account)?
                    .ok_or_else(|| ChronxError::UnknownAccount(target_account.to_string()))?;

                if target.recovery_state.active {
                    return Err(ChronxError::RecoveryAlreadyActive(
                        target_account.to_string(),
                    ));
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
            Action::ChallengeRecovery {
                target_account,
                counter_evidence_hash,
                bond_amount
            } => {
                if *bond_amount < MIN_CHALLENGE_BOND_CHRONOS {
                    return Err(ChronxError::ChallengeBondTooLow {
                        min: MIN_CHALLENGE_BOND_CHRONOS
                    });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance()
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
                    recovery_config: chronx_core::account::RecoveryConfig::default()
                };
                target.recovery_state = chronx_core::account::RecoveryState::default();

                staged.accounts.push(target);
                Ok(())
            }

            // ── RegisterVerifier ──────────────────────────────────────────────
            Action::RegisterVerifier { stake_amount } => {
                if *stake_amount < MIN_VERIFIER_STAKE_CHRONOS {
                    return Err(ChronxError::VerifierStakeTooLow {
                        min: MIN_VERIFIER_STAKE_CHRONOS
                    });
                }
                if sender.balance < *stake_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *stake_amount,
                        have: sender.balance
                    });
                }
                sender.verifier_stake += stake_amount;
                sender.is_verifier = true;
                Ok(())
            }

            // ── VoteRecovery ──────────────────────────────────────────────────
            Action::VoteRecovery {
                target_account,
                approve,
                fee_bid: _
            } => {
                if !sender.is_verifier {
                    return Err(ChronxError::VerifierNotRegistered(
                        sender.account_id.to_string(),
                    ));
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
                    return Err(ChronxError::TimeLockNotMatured {
                        unlock_time: contract.unlock_at
                    });
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
            Action::SubmitClaimCommit {
                lock_id,
                commit_hash,
                bond_amount
            } => {
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
                        have: sender.spendable_balance()
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
            Action::RevealClaim {
                lock_id,
                payload,
                salt,
                certificates
            } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                let committed_at = match &contract.status {
                    TimeLockStatus::ClaimCommitted { committed_at } => *committed_at,
                    _ => return Err(ChronxError::InvalidClaimStateTransition)
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
                        slashed_at: now
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
                let stored_hash = cs
                    .commit_hash
                    .ok_or(ChronxError::InvalidClaimStateTransition)?;
                if expected_hash != stored_hash {
                    // Slash: hash mismatch. Commit the slash as a valid state
                    // transition (Ok) so staged mutations persist.
                    let slash_amount = cs.commit_bond;
                    cs.commit_bond = 0;
                    contract.status = TimeLockStatus::ClaimSlashed {
                        reason: SlashReason::RevealHashMismatch,
                        slashed_at: now
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
            Action::ChallengeClaimReveal {
                lock_id,
                evidence_hash,
                bond_amount
            } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                let revealed_at = match &contract.status {
                    TimeLockStatus::ClaimRevealed { revealed_at } => *revealed_at,
                    _ => return Err(ChronxError::InvalidClaimStateTransition)
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
                    return Err(ChronxError::ClaimBondTooLow {
                        min: cs.commit_bond
                    });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance()
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
                        let agent_id = cs
                            .agent_id
                            .clone()
                            .ok_or(ChronxError::InvalidClaimStateTransition)?;
                        let payout = contract.amount + cs.commit_bond;

                        // If agent == transaction sender, credit in-place so that
                        // the sender write in apply() carries the payout.
                        // Otherwise load the agent account from DB.
                        if agent_id == sender.account_id {
                            sender.balance += payout;
                        } else {
                            let mut agent_acc = self
                                .db
                                .get_account(&agent_id)?
                                .ok_or_else(|| ChronxError::UnknownAccount(agent_id.to_string()))?;
                            agent_acc.balance += payout;
                            staged.accounts.push(agent_acc);
                        }
                        cs.commit_bond = 0;

                        contract.status = TimeLockStatus::ClaimFinalized {
                            paid_to: agent_id.clone(),
                            finalized_at: now
                        };
                        staged.timelocks.push(contract);
                        staged.claims.push(cs);
                        Ok(())
                    }

                    TimeLockStatus::ClaimChallenged { .. } => {
                        // MVP: challenger wins automatically.
                        // Full implementation would evaluate evidence off-chain via oracle/committee.
                        let challenger_id = cs
                            .challenger
                            .clone()
                            .ok_or(ChronxError::InvalidClaimStateTransition)?;

                        // Challenger gets their bond back + agent's bond as reward.
                        // Lock funds are returned to sender (or protocol treasury in full impl).
                        let challenger_payout = cs.challenge_bond + cs.commit_bond;

                        let mut challenger_acc =
                            self.db.get_account(&challenger_id)?.ok_or_else(|| {
                                ChronxError::UnknownAccount(challenger_id.to_string())
                            })?;
                        challenger_acc.balance += challenger_payout;

                        // Return lock amount to original sender.
                        let mut lock_sender =
                            self.db.get_account(&contract.sender)?.ok_or_else(|| {
                                ChronxError::UnknownAccount(contract.sender.to_string())
                            })?;
                        lock_sender.balance += contract.amount;

                        cs.commit_bond = 0;
                        cs.challenge_bond = 0;

                        contract.status = TimeLockStatus::ClaimSlashed {
                            reason: SlashReason::SuccessfulChallenge,
                            slashed_at: now
                        };
                        staged.accounts.push(challenger_acc);
                        staged.accounts.push(lock_sender);
                        staged.timelocks.push(contract);
                        staged.claims.push(cs);
                        Ok(())
                    }

                    _ => Err(ChronxError::InvalidClaimStateTransition)
                }
            }

            // ── RegisterProvider ──────────────────────────────────────────────
            Action::RegisterProvider {
                provider_class,
                jurisdictions,
                bond_amount
            } => {
                if *bond_amount < PROVIDER_BOND_CHRONOS {
                    return Err(ChronxError::ProviderBondTooLow {
                        min: PROVIDER_BOND_CHRONOS
                    });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance()
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
                    AuthPolicy::MultiSig { public_keys, .. } => public_keys
                        .first()
                        .cloned()
                        .unwrap_or_else(|| chronx_core::types::DilithiumPublicKey(vec![]))
                };

                let record = ProviderRecord {
                    provider_id: sender.account_id.clone(),
                    public_keys: vec![pubkey],
                    provider_class: provider_class.clone(),
                    jurisdictions: jurisdictions.clone(),
                    status: ProviderStatus::Active,
                    registration_bond: *bond_amount,
                    registered_at: now
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
                bond_amount
            } => {
                if *bond_amount < SCHEMA_BOND_CHRONOS {
                    return Err(ChronxError::SchemaBondTooLow {
                        min: SCHEMA_BOND_CHRONOS
                    });
                }
                if sender.spendable_balance() < *bond_amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: *bond_amount,
                        have: sender.spendable_balance()
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
                        max_cert_age_secs: *max_cert_age_secs
                    },
                    active: true,
                    registered_by: sender.account_id.clone(),
                    registered_at: now
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
                    submitted_at: now
                };
                staged.oracle_submissions.push(sub);
                Ok(())
            }

            // ── TimeLockClaimWithSecret ───────────────────────────────────────
            // PATH B — Email lock claim using a plaintext claim secret.
            // Any account that knows the secret can claim, regardless of pubkey.
            // The original sender can STILL cancel/reclaim via CancelTimeLock or
            // the normal TimeLockClaim (their pubkey == recipient_key).
            //
            // CASCADE BEHAVIOUR: If multiple locks share the same claim_secret_hash
            // (a "cascade"), claiming any one of them with the correct secret claims
            // ALL matured, pending locks in the cascade.
            Action::TimeLockClaimWithSecret { lock_id, claim_secret } => {
                // Prevent double-action on same lock within one transaction.
                if staged.acted_lock_ids.contains(&lock_id.0.0) {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }
                let contract = self
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

                // Look up the stored claim-secret hash for this lock.
                let stored_hash = self
                    .db
                    .get_email_claim_hash(&lock_id.0)?
                    .ok_or(ChronxError::AuthPolicyViolation)?;

                // Validate the claim secret: BLAKE3(claim_secret.as_bytes()) must
                // match the hash stored at lock creation time.
                let provided_hash = chronx_crypto::hash::blake3_hash(claim_secret.as_bytes());
                if provided_hash != stored_hash {
                    return Err(ChronxError::InvalidClaimSecret);
                }

                // Secret matches. Find ALL locks sharing this claim_secret_hash
                // (cascade) and claim every matured, pending one.
                let cascade_lock_ids = self.db.get_locks_by_claim_hash(&stored_hash)?;

                let mut claimed_any = false;
                for cascade_id in &cascade_lock_ids {
                    // Skip locks already acted on in this transaction.
                    if staged.acted_lock_ids.contains(&cascade_id.0) {
                        continue;
                    }
                    let mut c = match self.db.get_timelock(cascade_id)? {
                        Some(c) => c,
                        None => continue
                    };
                    if c.status != TimeLockStatus::Pending {
                        continue;
                    }
                    // Skip locks not yet matured.
                    if now < c.unlock_at {
                        continue;
                    }
                    // Check the claim window (72-hour default for email locks).
                    if let Some(window_secs) = c.claim_window_secs {
                        if now > c.created_at + window_secs as i64 {
                            continue;
                        }
                    }
                    sender.balance += c.amount;
                    c.status = TimeLockStatus::Claimed { claimed_at: now };
                    staged.acted_lock_ids.insert(cascade_id.0);
                    staged.timelocks.push(c);
                    claimed_any = true;
                }

                if !claimed_any {
                    // The primary lock wasn't claimable (possibly not matured
                    // or claim window expired).
                    if now < contract.unlock_at {
                        return Err(ChronxError::TimeLockNotMatured {
                            unlock_time: contract.unlock_at
                        });
                    }
                    return Err(ChronxError::ClaimWindowExpired);
                }

                Ok(())
            }

            // ── ReclaimExpiredLock ─────────────────────────────────────────────
            // Manual fallback: sender reclaims an expired email lock.
            Action::ReclaimExpiredLock { lock_id } => {
                // Prevent double-action on same lock within one transaction.
                if staged.acted_lock_ids.contains(&lock_id.0.0) {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                // Only the original sender may reclaim.
                if contract.sender != sender.account_id {
                    return Err(ChronxError::ReclaimNotBySender);
                }
                // Lock must still be Pending.
                if contract.status != TimeLockStatus::Pending {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }
                // Must have a claim window.
                let window_secs = contract
                    .claim_window_secs
                    .ok_or(ChronxError::NoClaimWindow)?;
                // Claim window must have expired.
                if now <= contract.created_at + window_secs as i64 {
                    return Err(ChronxError::ClaimWindowNotExpired);
                }
                // Must have RevertToSender action.
                match &contract.unclaimed_action {
                    Some(chronx_core::account::UnclaimedAction::RevertToSender) => {}
                    _ => return Err(ChronxError::NotRevertToSender)
                }

                // Return funds to sender.
                sender.balance += contract.amount;
                contract.status = TimeLockStatus::Reverted { reverted_at: now };
                staged.acted_lock_ids.insert(lock_id.0.0);
                staged.timelocks.push(contract);
                Ok(())
            }

            // ── ExecutorWithdraw ──────────────────────────────────────────────
            // MISAI executor withdraws KX from a live Type M lock.
            // Sets lock to PendingExecutor status; a background sweep finalizes
            // after the configurable delay (EXECUTOR_WITHDRAW_DELAY_SECONDS).
            Action::ExecutorWithdraw {
                lock_id,
                destination,
                executor_pubkey
            } => {
                // Prevent double-action on same lock within one transaction.
                if staged.acted_lock_ids.contains(&lock_id.0.0) {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }

                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                // 1. lock_type must be "M" — reject all non-M locks.
                match &contract.lock_type {
                    Some(lt) if lt == "M" => {}
                    _ => return Err(ChronxError::NotTypeMlock)
                }

                // 2. Signer must match the registered MISAI executor pubkey.
                let stored_executor_pubkey = self
                    .db
                    .get_meta("misai_executor_pubkey")?
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_default();
                if stored_executor_pubkey.is_empty() || *executor_pubkey != stored_executor_pubkey {
                    return Err(ChronxError::ExecutorPubkeyMismatch);
                }

                // 3. Lock must be Pending.
                if contract.status != TimeLockStatus::Pending {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }

                // 4. lock_metadata must not be null.
                if contract.lock_metadata.is_none() {
                    return Err(ChronxError::LockMetadataNull);
                }

                // 5. Destination must match registered executor wallet.
                let stored_executor_wallet = self
                    .db
                    .get_meta("misai_executor_wallet")?
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_default();
                if stored_executor_wallet.is_empty()
                    || destination.to_string() != stored_executor_wallet
                {
                    return Err(ChronxError::ExecutorWalletMismatch);
                }

                // 6. Rate limit: max 3 per 24-hour window.
                let recent_count = self
                    .db
                    .count_recent_executor_withdrawals(now, 86400)?;
                if recent_count >= 3 {
                    return Err(ChronxError::ExecutorWithdrawRateLimited);
                }

                // Read configurable delay (default 86400 = 24 hours).
                let delay_secs: i64 = std::env::var("EXECUTOR_WITHDRAW_DELAY_SECONDS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(86400);

                let finalize_at = now + delay_secs;

                // 7. Set lock to PendingExecutor — KX stays locked until sweep finalizes.
                contract.status = TimeLockStatus::PendingExecutor {
                    submitted_at: now,
                    finalize_at
                };
                staged.acted_lock_ids.insert(lock_id.0.0);
                staged.timelocks.push(contract.clone());

                // Record the withdrawal for the finalization sweep and rate limiting.
                let record = crate::db::ExecutorWithdrawalRecord {
                    lock_id: lock_id.to_string(),
                    destination: destination.to_string(),
                    amount_chronos: contract.amount as u64,
                    submitted_at: now,
                    finalize_at,
                    status: "PendingExecutor".to_string()
                };
                self.db.put_executor_withdrawal(&lock_id.to_string(), &record)?;

                info!(
                    lock_id = %lock_id,
                    amount_kx = contract.amount / chronx_core::constants::CHRONOS_PER_KX,
                    finalize_at = finalize_at,
                    "ExecutorWithdraw submitted — PendingExecutor until finalize_at"
                );

                Ok(())
            }

            // ── Foundation multisig governance scaffold ──────────────────────────
            // When foundation_multisig_testing_mode is true (current state):
            //   Single founder signature accepted for governance changes.
            // When false (after YubiKey ceremony):
            //   Requires 2-of-3 YubiKey signatures from foundation_multisig_keys.
            // The testing_mode flag itself can only be turned off via deliberate
            // tier change (30-day DrawRequest), ensuring the upgrade to full
            // multisig is a public, documented event.
            // TODO: Implement GovernanceParamUpdate action with multisig check.

            // ── Verifier registration (governance only) ────────────────────────
            Action::VerifierRegister {
                ref verifier_name,
                ref wallet_address,
                bond_amount_kx,
                ref dilithium2_public_key_hex,
                ref jurisdiction,
                ref role
            } => {
                // Only the governance wallet may register verifiers
                let governance_b58 = self.db.get_meta("governance_wallet")
                    .ok()
                    .flatten()
                    .map(|b| String::from_utf8_lossy(&b).to_string());
                // Check sender is governance wallet
                let sender_b58 = sender.account_id.to_b58();
                let is_governance = governance_b58
                    .as_ref()
                    .map(|g| g == &sender_b58)
                    .unwrap_or(false);
                if !is_governance {
                    // Also allow if the sender is the Founder wallet
                    // (for initial setup before governance is fully operational)
                    let founder_check = self.db.get_meta("founder_wallet")
                        .ok()
                        .flatten()
                        .map(|b| String::from_utf8_lossy(&b).to_string());
                    let is_founder = founder_check
                        .as_ref()
                        .map(|f| f == &sender_b58)
                        .unwrap_or(false);
                    if !is_founder {
                        // For protocol initial setup, allow any account to register
                        // verifiers until governance is fully configured.
                        // In production, this should be restricted.
                        warn!(sender = %sender_b58, "verifier registration from non-governance wallet — allowed during  setup");
                    }
                }
                let now_u64 = now as u64;
                let record = crate::db::VerifierRecord {
                    verifier_name: verifier_name.clone(),
                    wallet_address: wallet_address.clone(),
                    bond_amount_kx: *bond_amount_kx,
                    dilithium2_public_key_hex: dilithium2_public_key_hex.clone(),
                    jurisdiction: jurisdiction.clone(),
                    role: role.clone(),
                    approval_date: now_u64,
                    status: "Active".to_string()
                };
                self.db.put_verifier(wallet_address, &record)?;
                info!(verifier = %verifier_name, wallet = %wallet_address, "verifier registered");
                Ok(())
            }

            // ── V8 Agent actions (not yet active) ─────────────────────────────
            Action::AgentRegister { .. }
            | Action::AgentCodeUpdate { .. }
            | Action::AgentLoanRequest { .. } => {
                Err(ChronxError::FeatureNotActive(
                    "Agent actions are not yet active".into(),
                ))
            }

            // ── protocol — TYPE I Invoice ──────────────────────────────────
            Action::CreateInvoice(ref action) => {
                let now_u64 = now as u64;
                let min_expiry = now_u64 + INVOICE_MIN_EXPIRY_SECONDS;
                let max_expiry = now_u64 + INVOICE_MAX_EXPIRY_SECONDS;
                if action.expiry < min_expiry || action.expiry > max_expiry {
                    return Err(ChronxError::InvoiceExpiryOutOfRange);
                }
                if self.db.get_invoice(&action.invoice_id)?.is_some() {
                    return Err(ChronxError::InvoiceDuplicate(hex::encode(action.invoice_id)));
                }
                let record = InvoiceRecord {
                    invoice_id: action.invoice_id,
                    issuer_pubkey: action.issuer_pubkey.0.clone(),
                    payer_pubkey: action.payer_pubkey.as_ref().map(|p| p.0.clone()),
                    amount_chronos: action.amount_chronos,
                    expiry: action.expiry,
                    encrypted_memo: action.encrypted_memo.clone(),
                    memo_hash: action.memo_hash,
                    status: InvoiceStatus::Open,
                    created_at: now_u64,
                    fulfilled_at: None,
                    fulfilled_by: None
                };
                self.db.put_invoice(&record)?;
                info!(invoice_id = %hex::encode(action.invoice_id), "Invoice created");
                Ok(())
            }

            Action::FulfillInvoice(ref action) => {
                let now_u64 = now as u64;
                let invoice = self.db.get_invoice(&action.invoice_id)?
                    .ok_or_else(|| ChronxError::InvoiceNotFound(hex::encode(action.invoice_id)))?;
                if !matches!(invoice.status, InvoiceStatus::Open) {
                    return Err(ChronxError::InvoiceNotOpen);
                }
                if now_u64 >= invoice.expiry {
                    return Err(ChronxError::InvoiceLapsed);
                }
                if let Some(ref expected_payer) = invoice.payer_pubkey {
                    if action.payer_pubkey.0 != *expected_payer {
                        return Err(ChronxError::InvoicePayerMismatch);
                    }
                }
                if action.amount_chronos != invoice.amount_chronos {
                    return Err(ChronxError::InvoiceAmountMismatch);
                }
                // Deduct from payer (the sender of this tx)
                let amount = action.amount_chronos as u128;
                if sender.balance < amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: amount,
                        have: sender.balance
                    });
                }
                sender.balance -= amount;
                // Credit to issuer
                let issuer_account_id = chronx_crypto::hash::account_id_from_pubkey(&invoice.issuer_pubkey);
                let mut issuer = self.db.get_account(&issuer_account_id)?
                    .ok_or_else(|| ChronxError::UnknownAccount(issuer_account_id.to_b58()))?;
                issuer.balance += amount;
                staged.accounts.push(issuer);
                // Update invoice
                self.db.update_invoice_status(
                    &action.invoice_id,
                    InvoiceStatus::Fulfilled,
                    Some(now_u64),
                    Some(action.payer_pubkey.0.clone()),
                )?;
                info!(invoice_id = %hex::encode(action.invoice_id), "Invoice fulfilled");
                Ok(())
            }

            Action::CancelInvoice(ref action) => {
                let invoice = self.db.get_invoice(&action.invoice_id)?
                    .ok_or_else(|| ChronxError::InvoiceNotFound(hex::encode(action.invoice_id)))?;
                if !matches!(invoice.status, InvoiceStatus::Open) {
                    return Err(ChronxError::InvoiceNotOpen);
                }
                if action.issuer_pubkey.0 != invoice.issuer_pubkey {
                    return Err(ChronxError::AuthPolicyViolation);
                }
                self.db.update_invoice_status(
                    &action.invoice_id,
                    InvoiceStatus::Cancelled,
                    None, None,
                )?;
                info!(invoice_id = %hex::encode(action.invoice_id), "Invoice cancelled");
                Ok(())
            }

            Action::RejectInvoice { invoice_id, memo: _ } => {
                let invoice = self.db.get_invoice(invoice_id)?
                    .ok_or_else(|| ChronxError::InvoiceNotFound(hex::encode(invoice_id)))?;
                if !matches!(invoice.status, InvoiceStatus::Open) {
                    return Err(ChronxError::InvoiceNotOpen);
                }
                // Only the designated payer may reject
                match &invoice.payer_pubkey {
                    Some(expected_payer) => {
                        let payer_account_id = account_id_from_pubkey(expected_payer);
                        if payer_account_id != sender.account_id {
                            return Err(ChronxError::InvoicePayerMismatch);
                        }
                    }
                    None => {
                        // Open invoice (no designated payer) — any wallet can reject
                    }
                }
                self.db.update_invoice_status(
                    invoice_id,
                    InvoiceStatus::Rejected,
                    None, None,
                )?;
                info!(invoice_id = %hex::encode(invoice_id), "Invoice rejected");
                Ok(())
            }

            // ── protocol — TYPE C Credit Authorization ─────────────────────
            Action::CreateCredit(ref action) => {
                let now_u64 = now as u64;
                let min_ceiling = CREDIT_MIN_CEILING_CHRONOS;
                if action.ceiling_chronos < min_ceiling {
                    return Err(ChronxError::CreditCeilingTooLow);
                }
                if action.expiry > now_u64 + CREDIT_MAX_EXPIRY_SECONDS || action.expiry <= now_u64 {
                    return Err(ChronxError::CreditExpiryOutOfRange);
                }
                if self.db.get_credit(&action.credit_id)?.is_some() {
                    return Err(ChronxError::CreditDuplicate(hex::encode(action.credit_id)));
                }
                let record = CreditRecord {
                    credit_id: action.credit_id,
                    grantor_pubkey: action.grantor_pubkey.0.clone(),
                    beneficiary_pubkey: action.beneficiary_pubkey.0.clone(),
                    ceiling_chronos: action.ceiling_chronos,
                    per_draw_max_chronos: action.per_draw_max_chronos,
                    expiry: action.expiry,
                    drawn_chronos: 0,
                    status: CreditStatus::Open,
                    encrypted_terms: action.encrypted_terms.clone(),
                    created_at: now_u64,
                };
                self.db.put_credit(&record)?;
                info!(credit_id = %hex::encode(action.credit_id), "Credit authorization created");
                Ok(())
            }

            Action::DrawCredit(ref action) => {
                let now_u64 = now as u64;
                let credit = self.db.get_credit(&action.credit_id)?
                    .ok_or_else(|| ChronxError::CreditNotFound(hex::encode(action.credit_id)))?;
                if !matches!(credit.status, CreditStatus::Open) {
                    return Err(ChronxError::CreditNotOpen);
                }
                if now_u64 >= credit.expiry {
                    return Err(ChronxError::CreditLapsed);
                }
                // Signer must be beneficiary — the tx sender's pubkey must match
                // (Verified via sender matching beneficiary account)
                if let Some(max) = credit.per_draw_max_chronos {
                    if action.amount_chronos > max {
                        return Err(ChronxError::CreditDrawExceedsPerDrawMax);
                    }
                }
                if credit.drawn_chronos + action.amount_chronos > credit.ceiling_chronos {
                    return Err(ChronxError::CreditDrawExceedsCeiling);
                }
                // Deduct from grantor's live balance
                let grantor_account_id = chronx_crypto::hash::account_id_from_pubkey(&credit.grantor_pubkey);
                let mut grantor = self.db.get_account(&grantor_account_id)?
                    .ok_or_else(|| ChronxError::UnknownAccount(grantor_account_id.to_b58()))?;
                let amount = action.amount_chronos as u128;
                if grantor.balance < amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: amount,
                        have: grantor.balance
                    });
                }
                grantor.balance -= amount;
                staged.accounts.push(grantor);
                // Credit beneficiary (the sender of this tx)
                sender.balance += amount;
                // Update drawn amount
                self.db.update_credit_drawn(&action.credit_id, action.amount_chronos)?;
                info!(credit_id = %hex::encode(action.credit_id), amount = action.amount_chronos, "Credit drawn");
                Ok(())
            }

            Action::RevokeCredit(ref action) => {
                let credit = self.db.get_credit(&action.credit_id)?
                    .ok_or_else(|| ChronxError::CreditNotFound(hex::encode(action.credit_id)))?;
                if !matches!(credit.status, CreditStatus::Open) {
                    return Err(ChronxError::CreditNotOpen);
                }
                if action.grantor_pubkey.0 != credit.grantor_pubkey {
                    return Err(ChronxError::AuthPolicyViolation);
                }
                self.db.update_credit_status(&action.credit_id, CreditStatus::Revoked)?;
                info!(credit_id = %hex::encode(action.credit_id), "Credit revoked");
                Ok(())
            }

            // ── protocol — TYPE Y Interest Bearing Deposit ─────────────────
            Action::CreateDeposit(ref action) => {
                let now_u64 = now as u64;
                if action.term_seconds < DEPOSIT_MIN_TERM_SECONDS || action.term_seconds > DEPOSIT_MAX_TERM_SECONDS {
                    return Err(ChronxError::DepositTermOutOfRange);
                }
                if action.rate_basis_points > DEPOSIT_MAX_RATE_BASIS_POINTS {
                    return Err(ChronxError::DepositRateTooHigh);
                }
                if self.db.get_deposit(&action.deposit_id)?.is_some() {
                    return Err(ChronxError::DepositDuplicate(hex::encode(action.deposit_id)));
                }
                // Calculate total_due_chronos
                let total_due = calculate_deposit_total_due(
                    action.principal_chronos,
                    action.rate_basis_points,
                    action.term_seconds,
                    &action.compounding,
                );
                let principal = action.principal_chronos as u128;
                if sender.balance < principal {
                    return Err(ChronxError::InsufficientBalance {
                        need: principal,
                        have: sender.balance
                    });
                }
                // Deduct from depositor, credit to obligor
                sender.balance -= principal;
                let obligor_account_id = chronx_crypto::hash::account_id_from_pubkey(&action.obligor_pubkey.0);
                let mut obligor = self.db.get_account(&obligor_account_id)?
                    .ok_or_else(|| ChronxError::UnknownAccount(obligor_account_id.to_b58()))?;
                obligor.balance += principal;
                staged.accounts.push(obligor);

                let compounding_str = match action.compounding {
                    Compounding::Simple => "Simple",
                    Compounding::Daily => "Daily",
                    Compounding::Monthly => "Monthly",
                    Compounding::Annually => "Annually"
                };
                let record = DepositRecord {
                    deposit_id: action.deposit_id,
                    depositor_pubkey: action.depositor_pubkey.0.clone(),
                    obligor_pubkey: action.obligor_pubkey.0.clone(),
                    principal_chronos: action.principal_chronos,
                    rate_basis_points: action.rate_basis_points,
                    term_seconds: action.term_seconds,
                    compounding: compounding_str.to_string(),
                    maturity_timestamp: now_u64 + action.term_seconds,
                    total_due_chronos: total_due,
                    penalty_basis_points: action.penalty_basis_points,
                    status: DepositStatus::Active,
                    created_at: now_u64,
                    settled_at: None,
                    auto_renew: true,
                    renewal_count: 0,
                    accrued_yield_chronos: 0,
                };
                self.db.put_deposit(&record)?;
                info!(deposit_id = %hex::encode(action.deposit_id), total_due, "Deposit created");
                Ok(())
            }

            Action::SettleDeposit(ref action) => {
                let now_u64 = now as u64;
                let deposit = self.db.get_deposit(&action.deposit_id)?
                    .ok_or_else(|| ChronxError::DepositNotFound(hex::encode(action.deposit_id)))?;
                if !matches!(deposit.status, DepositStatus::Active | DepositStatus::Matured) {
                    return Err(ChronxError::DepositNotSettleable);
                }
                if action.amount_chronos != deposit.total_due_chronos {
                    return Err(ChronxError::DepositAmountMismatch);
                }
                // Deduct from obligor (tx sender)
                let amount = action.amount_chronos as u128;
                if sender.balance < amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: amount,
                        have: sender.balance
                    });
                }
                sender.balance -= amount;
                // Credit depositor
                let depositor_account_id = chronx_crypto::hash::account_id_from_pubkey(&deposit.depositor_pubkey);
                let mut depositor = self.db.get_account(&depositor_account_id)?
                    .ok_or_else(|| ChronxError::UnknownAccount(depositor_account_id.to_b58()))?;
                depositor.balance += amount;
                staged.accounts.push(depositor);
                self.db.update_deposit_status(&action.deposit_id, DepositStatus::Settled, Some(now_u64))?;
                info!(deposit_id = %hex::encode(action.deposit_id), "Deposit settled");
                Ok(())
            }

            // ── protocol — TYPE V Conditional Validity ─────────────────────
            Action::CreateConditional(ref action) => {
                let now_u64 = now as u64;
                let attestor_count = action.attestor_pubkeys.len() as u32;
                let is_oracle_trigger = action.condition_type.as_deref() == Some("OracleTrigger");
                // OracleTrigger conditions do not require human attestors
                if !is_oracle_trigger {
                    if !(CONDITIONAL_MIN_ATTESTORS..=CONDITIONAL_MAX_ATTESTORS).contains(&attestor_count) {
                        return Err(ChronxError::AttestorCountOutOfRange);
                    }
                    if action.min_attestors > attestor_count {
                        return Err(ChronxError::MinAttestorsExceedsCount);
                    }
                }
                if action.valid_until <= now_u64 {
                    return Err(ChronxError::ConditionalExpiryInPast);
                }
                if self.db.get_conditional(&action.type_v_id)?.is_some() {
                    return Err(ChronxError::ConditionalDuplicate(hex::encode(action.type_v_id)));
                }
                // Hold funds from sender
                let amount = action.amount_chronos as u128;
                if sender.balance < amount {
                    return Err(ChronxError::InsufficientBalance {
                        need: amount,
                        have: sender.balance
                    });
                }
                sender.balance -= amount;

                let fallback_str = match action.fallback {
                    ConditionalFallback::Void => "Void",
                    ConditionalFallback::Return => "Return",
                    ConditionalFallback::Escrow => "Escrow"
                };
                let record = ConditionalRecord {
                    type_v_id: action.type_v_id,
                    sender_pubkey: action.sender_pubkey.0.clone(),
                    recipient_pubkey: action.recipient_pubkey.0.clone(),
                    amount_chronos: action.amount_chronos,
                    attestor_pubkeys: action.attestor_pubkeys.iter().map(|p| p.0.clone()).collect(),
                    min_attestors: action.min_attestors,
                    attestation_memo: action.attestation_memo.clone(),
                    valid_until: action.valid_until,
                    fallback: fallback_str.to_string(),
                    encrypted_terms: action.encrypted_terms.clone(),
                    attestations_received: Vec::new(),
                    status: ConditionalStatus::Pending,
                    created_at: now_u64,
                    success_payment_wallet: action.success_payment_wallet.clone(),
                    success_payment_chronos: action.success_payment_chronos,
                    released_so_far_chronos: 0,
                    release_count: 0,
                    condition_type: action.condition_type.clone(),
                    oracle_pair: action.oracle_pair.clone(),
                    oracle_trigger_threshold: action.oracle_trigger_threshold,
                    oracle_trigger_direction: action.oracle_trigger_direction.clone(),
                    oracle_creation_price: if action.condition_type.as_deref() == Some("OracleTrigger") {
                        // Record creation price from oracle cache
                        self.db.get_meta("oracle_price_kx_usd")
                            .ok().flatten()
                            .and_then(|b| String::from_utf8(b).ok())
                            .and_then(|s| s.parse::<f64>().ok())
                    } else { None },
                    escalation_wallet: None,
                    escalation_lock_seconds: None,
                    attestors_suspended: false,
                    escalation_active: false,
                };
                self.db.put_conditional(&record)?;
                info!(type_v_id = %hex::encode(action.type_v_id), "Conditional payment created");
                Ok(())
            }

            Action::AttestConditional(ref action) => {
                let now_u64 = now as u64;
                let cond = self.db.get_conditional(&action.type_v_id)?
                    .ok_or_else(|| ChronxError::ConditionalNotFound(hex::encode(action.type_v_id)))?;
                if !matches!(cond.status, ConditionalStatus::Pending | ConditionalStatus::PartiallyReleased) {
                    return Err(ChronxError::ConditionalNotPending);
                }
                if now_u64 >= cond.valid_until {
                    return Err(ChronxError::ConditionalExpired);
                }
                let attestor_bytes = action.attestor_pubkey.0.clone();
                if cond.attestors_suspended {
                    if let Some(ref esc_wallet) = cond.escalation_wallet {
                        let attestor_account = chronx_crypto::hash::account_id_from_pubkey(&action.attestor_pubkey.0);
                        if attestor_account.to_b58() != *esc_wallet {
                            return Err(ChronxError::AttestorNotAuthorized);
                        }
                    } else {
                        return Err(ChronxError::AttestorNotAuthorized);
                    }
                } else {
                    if !cond.attestor_pubkeys.contains(&attestor_bytes) {
                        return Err(ChronxError::AttestorNotAuthorized);
                    }
                    if cond.attestations_received.iter().any(|(p, _)| *p == attestor_bytes) {
                        return Err(ChronxError::AttestorAlreadyAttested);
                    }
                }
                let updated = self.db.add_attestation(&action.type_v_id, attestor_bytes, now_u64)?;
                if updated.attestations_received.len() as u32 >= updated.min_attestors {
                    let remaining = updated.amount_chronos.saturating_sub(updated.released_so_far_chronos);
                    if remaining == 0 { return Err(ChronxError::ConditionalFullyReleased); }
                    let release_amount: u64 = match action.release_amount_chronos {
                        Some(partial) => {
                            if partial == 0 { return Err(ChronxError::ZeroAmount); }
                            if partial > remaining { return Err(ChronxError::ReleaseAmountExceedsLocked); }
                            partial
                        }
                        None => remaining,
                    };
                    let recipient_account_id = chronx_crypto::hash::account_id_from_pubkey(&updated.recipient_pubkey);
                    let mut recipient = match self.db.get_account(&recipient_account_id)? {
                        Some(acc) => acc,
                        None => Account {
                            account_id: recipient_account_id.clone(), balance: 0,
                            auth_policy: chronx_core::account::AuthPolicy::SingleSig {
                                public_key: chronx_core::types::DilithiumPublicKey(updated.recipient_pubkey.clone())
                            },
                            nonce: 0, recovery_state: Default::default(), post_recovery_restriction: None,
                            verifier_stake: 0, is_verifier: false, account_version: 3, created_at: Some(now),
                            display_name_hash: None, incoming_locks_count: 0, outgoing_locks_count: 0,
                            total_locked_incoming_chronos: 0, total_locked_outgoing_chronos: 0,
                            preferred_fiat_currency: None, lock_marker: None,
                                            savings_balance: 0, savings_invested: false, savings_withdrawal_pending: false
                        }
                    };
                    recipient.balance += release_amount as u128;
                    staged.accounts.push(recipient);
                    let new_released = updated.released_so_far_chronos + release_amount;
                    let new_remaining = updated.amount_chronos.saturating_sub(new_released);
                    let new_count = updated.release_count + 1;
                    let event = serde_json::json!({"release_amount": release_amount, "released_at": now_u64, "release_number": new_count, "remaining": new_remaining});
                    let _ = self.db.save_partial_release(&action.type_v_id, &serde_json::to_vec(&event).unwrap_or_default());
                    if new_remaining == 0 {
                        self.db.update_conditional_status(&action.type_v_id, ConditionalStatus::Released)?;
                        info!(type_v_id = %hex::encode(action.type_v_id), "Conditional FULLY released");
                    } else {
                        self.db.update_conditional_status(&action.type_v_id, ConditionalStatus::PartiallyReleased)?;
                        if let Some(mut record) = self.db.get_conditional(&action.type_v_id)? {
                            record.released_so_far_chronos = new_released;
                            record.release_count = new_count;
                            record.attestations_received.clear();
                            self.db.put_conditional_raw(&action.type_v_id, &record)?;
                        }
                        info!(type_v_id = %hex::encode(action.type_v_id), "Conditional PARTIALLY released, {} remaining", new_remaining);
                    }
                }
                Ok(())
            }

            // ── protocol — TYPE L Ledger Entry ─────────────────────────────
            Action::CreateLedgerEntry(ref action) => {
                let now_u64 = now as u64;
                // Author must be a bonded agent OR registered verifier
                let author_wallet = hex::encode(&action.author_pubkey.0);
                let author_account_id = chronx_crypto::hash::account_id_from_pubkey(&action.author_pubkey.0);
                let author_b58 = author_account_id.to_b58();
                let is_identity_entry = matches!(action.entry_type,
                    LedgerEntryType::IdentityVerified | LedgerEntryType::IdentityRevoked);
                if is_identity_entry {
                    // Identity entries require a registered verifier (e.g. CPNX)
                    if self.db.get_verifier(&author_b58)?.is_none() {
                        return Err(ChronxError::NotBondedAgent);
                    }
                } else {
                    // Non-identity entries require bonded agent or verifier
                    if self.db.get_agent(&author_wallet)?.is_none()
                        && self.db.get_verifier(&author_b58)?.is_none() {
                            return Err(ChronxError::NotBondedAgent);
                        }
                }
                if action.content_summary.len() > LEDGER_MAX_SUMMARY_BYTES {
                    return Err(ChronxError::ContentSummaryTooLarge { max: LEDGER_MAX_SUMMARY_BYTES });
                }
                if self.db.ledger_entry_exists(&action.entry_id) {
                    return Err(ChronxError::LedgerEntryDuplicate(hex::encode(action.entry_id)));
                }
                let entry_type_str = match action.entry_type {
                    LedgerEntryType::Decision => "Decision",
                    LedgerEntryType::Summary => "Summary",
                    LedgerEntryType::Audit => "Audit",
                    LedgerEntryType::Milestone => "Milestone",
                    LedgerEntryType::SignOfLife => "SignOfLife",
                    LedgerEntryType::GuardianTransition => "GuardianTransition",
                    LedgerEntryType::LifeUnconfirmed => "LifeUnconfirmed",
                    LedgerEntryType::BeneficiaryIdentified => "BeneficiaryIdentified",
                    LedgerEntryType::IdentityVerified => "IdentityVerified",
                    LedgerEntryType::IdentityRevoked => "IdentityRevoked"
                };
                let record = LedgerEntryRecord {
                    entry_id: action.entry_id,
                    author_pubkey: action.author_pubkey.0.clone(),
                    mandate_id: action.mandate_id,
                    promise_id: action.promise_id,
                    entry_type: entry_type_str.to_string(),
                    content_hash: action.content_hash,
                    content_summary: action.content_summary.clone(),
                    promise_chain_hash: action.promise_chain_hash,
                    external_ref: action.external_ref.clone(),
                    timestamp: now_u64
                };
                self.db.put_ledger_entry(&record)?;

                // Update identity index for IdentityVerified/IdentityRevoked entries
                if entry_type_str == "IdentityVerified" || entry_type_str == "IdentityRevoked" {
                    let summary_str = String::from_utf8_lossy(&action.content_summary);
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&summary_str) {
                        if let Some(target_wallet) = parsed.get("wallet").and_then(|v| v.as_str()) {
                            self.db.add_identity_entry(target_wallet, action.entry_id)?;

                            // Handle revocation blackouts
                            if entry_type_str == "IdentityRevoked" {
                                if let Some(revocation_type) = parsed.get("revocation_type").and_then(|v| v.as_str()) {
                                    if revocation_type == "fraud" || revocation_type == "impersonation" {
                                        let blackout_years = parsed.get("blackout_years").and_then(|v| v.as_u64()).unwrap_or(5);
                                        let blackout_until = now + (blackout_years as i64 * 365 * 24 * 3600);
                                        let blackout_data = serde_json::json!({
                                            "blackout_until": blackout_until,
                                            "reason": revocation_type,
                                            "revoked_at": now
                                        });
                                        let val = serde_json::to_vec(&blackout_data).unwrap_or_default();
                                        self.db.badge_blackouts_insert(target_wallet, &val)?;
                                        info!(wallet = target_wallet, blackout_years, "Badge blackout set for {}", revocation_type);
                                    }
                                }
                            }

                            let display = parsed.get("display").and_then(|v| v.as_str()).unwrap_or("?");
                            let msg = format!("Identity {} for {} ({})", entry_type_str, target_wallet, display);
                            info!("{}", msg);
                        }
                    }
                }

                info!(entry_id = %hex::encode(action.entry_id), entry_type = entry_type_str, "Ledger entry created");
                Ok(())
            }

            // ── Wallet Group handlers ─────────────────────

            Action::CreateGroup(ref action) => {
                use chronx_core::transaction::{GroupRecord, GroupStatus};
                use chronx_core::constants::WALLET_GROUP_NAME_MAX_BYTES;

                if self.db.get_group(&action.group_id)?.is_some() {
                    return Err(ChronxError::Other("Group ID already exists".into()));
                }
                // Software limit: max 10 members today
                if action.members.len() > 10 {
                    return Err(ChronxError::Other("Max 10 group members (software limit)".into()));
                }
                if action.name_hash.len() > WALLET_GROUP_NAME_MAX_BYTES {
                    return Err(ChronxError::Other("Group name hash too large".into()));
                }
                let record = GroupRecord {
                    group_id: action.group_id,
                    owner_pubkey: action.owner_pubkey.clone(),
                    name_hash: action.name_hash,
                    members: action.members.clone(),
                    member_count: action.members.len() as u64,
                    created_at: now as u64,
                    status: GroupStatus::Active
                };
                self.db.put_group(&record)?;
                info!(group_id = %hex::encode(action.group_id), members = action.members.len(), "Group created");
                Ok(())
            }

            Action::AddGroupMember(ref action) => {
                use chronx_core::transaction::GroupStatus;

                let mut record = self.db.get_group(&action.group_id)?
                    .ok_or_else(|| ChronxError::Other("Group not found".into()))?;
                if record.owner_pubkey != action.owner_pubkey {
                    return Err(ChronxError::Other("Only group owner can add members".into()));
                }
                if record.status == GroupStatus::Dissolved {
                    return Err(ChronxError::Other("Group is dissolved".into()));
                }
                if record.members.len() >= 10 {
                    return Err(ChronxError::Other("Max 10 group members (software limit)".into()));
                }
                if record.members.iter().any(|m| m == &action.new_member) {
                    return Err(ChronxError::Other("Already a member".into()));
                }
                record.members.push(action.new_member.clone());
                record.member_count = record.members.len() as u64;
                self.db.put_group(&record)?;
                info!(group_id = %hex::encode(action.group_id), "Group member added");
                Ok(())
            }

            Action::RemoveGroupMember(ref action) => {
                let mut record = self.db.get_group(&action.group_id)?
                    .ok_or_else(|| ChronxError::Other("Group not found".into()))?;
                if record.owner_pubkey != action.owner_pubkey {
                    return Err(ChronxError::Other("Only group owner can remove members".into()));
                }
                let before_len = record.members.len();
                record.members.retain(|m| m != &action.member);
                if record.members.len() == before_len {
                    return Err(ChronxError::Other("Member not found in group".into()));
                }
                record.member_count = record.members.len() as u64;
                self.db.put_group(&record)?;
                info!(group_id = %hex::encode(action.group_id), "Group member removed");
                Ok(())
            }

            Action::DissolveGroup(ref action) => {
                use chronx_core::transaction::GroupStatus;

                let mut record = self.db.get_group(&action.group_id)?
                    .ok_or_else(|| ChronxError::Other("Group not found".into()))?;
                if record.owner_pubkey != action.owner_pubkey {
                    return Err(ChronxError::Other("Only group owner can dissolve".into()));
                }
                record.status = GroupStatus::Dissolved;
                self.db.put_group(&record)?;
                info!(group_id = %hex::encode(action.group_id), "Group dissolved");
                Ok(())
            }

            Action::TransferGroupOwnership(ref action) => {
                use chronx_core::transaction::GroupStatus;

                let mut record = self.db.get_group(&action.group_id)?
                    .ok_or_else(|| ChronxError::Other("Group not found".into()))?;
                if record.owner_pubkey != action.owner_pubkey {
                    return Err(ChronxError::Other("Only current owner can transfer".into()));
                }
                if record.status == GroupStatus::Dissolved {
                    return Err(ChronxError::Other("Cannot transfer dissolved group".into()));
                }
                record.owner_pubkey = action.new_owner.clone();
                self.db.put_group(&record)?;
                info!(group_id = %hex::encode(action.group_id), "Group ownership transferred");
                Ok(())
            }

            // ── Genesis 10a — Loan actions ──────────────────────────────────

            Action::LoanOffer(offer) => {
                // Loan action rate limit
                self.check_loan_rate_limit(&sender.account_id.to_string(), now)?;
                // LoanOffer stores the offer as pending -- no funds move yet
                if sender.account_id != offer.lender_wallet {
                    return Err(ChronxError::AuthPolicyViolation);
                }
                let mut offer_data = serde_json::to_value(offer)
                    .map_err(|_| ChronxError::SerializationError)?;
                offer_data["status"] = serde_json::json!("pending");
                offer_data["created_at"] = serde_json::json!(now as u64);
                offer_data["loan_id_hex"] = serde_json::json!(hex::encode(offer.loan_id));
                // Ensure wallet addresses are stored as queryable strings
                offer_data["lender_wallet"] = serde_json::json!(offer.lender_wallet.to_string());
                offer_data["borrower_wallet"] = serde_json::json!(offer.borrower_wallet.to_string());
                offer_data["principal_kx"] = serde_json::json!(offer.principal_chronos / 1_000_000);
                let val = serde_json::to_vec(&offer_data)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_loan(&offer.loan_id, &val)?;
                info!(loan_id = %hex::encode(offer.loan_id),
                      lender = %offer.lender_wallet, borrower = %offer.borrower_wallet,
                      "Loan offer created (pending acceptance)");
                Ok(())
            }
            Action::LoanAcceptance(acceptance) => {
                // Loan action rate limit
                self.check_loan_rate_limit(&sender.account_id.to_string(), now)?;
                // Activate the loan: debit lender, credit borrower
                if let Ok(Some(existing)) = self.db.get_loan(&acceptance.loan_id) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        if loan_val.get("status").and_then(|s| s.as_str()) != Some("pending") {
                            return Err(ChronxError::LoanNotActive);
                        }
                        // Store requires_autopay in the active loan record
                        let _requires_ap = loan_val.get("requires_autopay")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        // Record age confirmation
                        loan_val["age_confirmed"] = serde_json::json!(acceptance.age_confirmed);
                        loan_val["accepted_at"] = serde_json::json!(acceptance.accepted_at);

                        // De minimis check: loans under ~$10 USD equiv skip rescission
                        // ICO price $0.00319/KX → $10 ≈ 3135 KX = 3_135_000_000 Chronos
                        let principal_chronos = loan_val.get("principal_chronos")
                            .and_then(|v| v.as_u64()).unwrap_or(0);
                        let deminimis_chronos: u64 = 3_135_000_000;

                        if principal_chronos < deminimis_chronos {
                            // De minimis: transfer KX immediately (no rescission window)
                            let lender_str = loan_val.get("lender_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let borrower_str = loan_val.get("borrower_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            if principal_chronos > 0 && !lender_str.is_empty() && !borrower_str.is_empty() {
                                let lender_id = chronx_core::types::AccountId::from_b58(&lender_str)
                                    .map_err(|_| ChronxError::Other("Invalid lender address".into()))?;
                                let borrower_id = chronx_core::types::AccountId::from_b58(&borrower_str)
                                    .map_err(|_| ChronxError::Other("Invalid borrower address".into()))?;
                                let mut lender_acc = self.db.get_account(&lender_id)?
                                    .ok_or_else(|| ChronxError::Other("Lender account not found".into()))?;
                                if lender_acc.balance < principal_chronos as u128 {
                                    return Err(ChronxError::InsufficientBalance {
                                        need: principal_chronos as u128,
                                        have: lender_acc.balance,
                                    });
                                }
                                lender_acc.balance -= principal_chronos as u128;
                                self.db.put_account(&lender_acc)?;
                                let mut borrower_acc = match self.db.get_account(&borrower_id)? {
                                    Some(a) => a,
                                    None => {
                                        // Auto-create borrower account
                                        chronx_core::account::Account {
                                            account_id: borrower_id.clone(), balance: 0,
                                            auth_policy: chronx_core::account::AuthPolicy::SingleSig {
                                                public_key: chronx_core::types::DilithiumPublicKey(Vec::new())
                                            },
                                            nonce: 0, recovery_state: Default::default(),
                                            post_recovery_restriction: None,
                                            verifier_stake: 0, is_verifier: false, account_version: 3,
                                            created_at: Some(now), display_name_hash: None,
                                            incoming_locks_count: 0, outgoing_locks_count: 0,
                                            total_locked_incoming_chronos: 0,
                                            total_locked_outgoing_chronos: 0,
                                            preferred_fiat_currency: None, lock_marker: None,
                                            savings_balance: 0, savings_invested: false, savings_withdrawal_pending: false
                                        }
                                    }
                                };
                                borrower_acc.balance += principal_chronos as u128;
                                self.db.put_account(&borrower_acc)?;
                                info!(loan_id = %hex::encode(acceptance.loan_id),
                                      principal_kx = principal_chronos / 1_000_000,
                                      "[LOAN DISBURSE] de minimis — KX transferred immediately");
                            }
                            loan_val["status"] = serde_json::json!("active");
                            loan_val["activated_at"] = serde_json::json!(now as u64);
                            let val = serde_json::to_vec(&loan_val)
                                .map_err(|_| ChronxError::SerializationError)?;
                            self.db.save_loan(&acceptance.loan_id, &val)?;
                            info!(loan_id = %hex::encode(acceptance.loan_id),
                                  "De minimis loan accepted — active immediately, KX transferred");
                        } else {
                            // Rescission window: default 72 hours
                            // CRITICAL: Lock lender funds in escrow immediately
                            let rescission_window_secs: i64 = 72 * 3600;
                            let rescission_expires_at = now + rescission_window_secs;

                            // Debit lender → escrow
                            let lender_str = loan_val.get("lender_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            if principal_chronos > 0 && !lender_str.is_empty() {
                                let lender_id = chronx_core::types::AccountId::from_b58(&lender_str)
                                    .map_err(|_| ChronxError::Other("Invalid lender address".into()))?;
                                let mut lender_acc = self.db.get_account(&lender_id)?
                                    .ok_or_else(|| ChronxError::Other("Lender account not found".into()))?;
                                if lender_acc.balance < principal_chronos as u128 {
                                    return Err(ChronxError::InsufficientBalance {
                                        need: principal_chronos as u128,
                                        have: lender_acc.balance,
                                    });
                                }
                                lender_acc.balance -= principal_chronos as u128;
                                self.db.put_account(&lender_acc)?;

                                // Store escrow deposit keyed by loan_id
                                self.db.put_loan_escrow(
                                    &acceptance.loan_id,
                                    &lender_str,
                                    principal_chronos as u128,
                                    rescission_expires_at,
                                )?;
                                info!(loan_id = %hex::encode(acceptance.loan_id),
                                      principal_kx = principal_chronos / 1_000_000,
                                      "[ESCROW LOCK] Lender funds locked in escrow during rescission");
                            }

                            loan_val["status"] = serde_json::json!("accepted_pending_rescission");
                            loan_val["rescission_expires_at"] = serde_json::json!(rescission_expires_at);
                            let val = serde_json::to_vec(&loan_val)
                                .map_err(|_| ChronxError::SerializationError)?;
                            self.db.save_loan(&acceptance.loan_id, &val)?;
                            info!(loan_id = %hex::encode(acceptance.loan_id),
                                  rescission_expires_at, "Loan accepted, pending rescission until {}", rescission_expires_at);
                        }
                    }
                }
                Ok(())
            }
            Action::LoanDecline(decline) => {
                self.check_loan_rate_limit(&sender.account_id.to_string(), now)?;
                if let Ok(Some(existing)) = self.db.get_loan(&decline.loan_id) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        loan_val["status"] = serde_json::json!("declined");
                        loan_val["declined_at"] = serde_json::json!(decline.declined_at);
                        if let Some(reason) = &decline.reason {
                            loan_val["decline_reason"] = serde_json::json!(reason);
                        }
                        let val = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(&decline.loan_id, &val)?;
                    }
                }
                Ok(())
            }
            Action::LoanOfferWithdrawn(withdrawal) => {
                self.check_loan_rate_limit(&sender.account_id.to_string(), now)?;
                if let Ok(Some(existing)) = self.db.get_loan(&withdrawal.loan_id) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        if loan_val.get("status").and_then(|s| s.as_str()) == Some("pending") {
                            loan_val["status"] = serde_json::json!("withdrawn");
                            loan_val["withdrawn_at"] = serde_json::json!(withdrawal.withdrawn_at);
                            let val = serde_json::to_vec(&loan_val)
                                .map_err(|_| ChronxError::SerializationError)?;
                            self.db.save_loan(&withdrawal.loan_id, &val)?;
                        }
                    }
                }
                Ok(())
            }
            Action::LoanPayerUpdate(update) => {
                let _key = format!("payerupdate:{}", hex::encode(update.loan_id));
                let val = serde_json::to_vec(&update)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_loan(&update.loan_id, &val)?;
                Ok(())
            }

            Action::DefaultRecord {
                loan_id, missed_stage_index, missed_amount_kx,
                late_fees_accrued_kx, days_overdue, outstanding_balance_kx,
                stages_remaining, defaulted_at, memo
            } => {
                // Only MISAI executor may submit default records
                let misai_executor = self.db
                    .get_meta("misai_executor_wallet")?
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_default();
                if misai_executor.is_empty() || sender.account_id.to_string() != misai_executor {
                    return Err(ChronxError::MisaiOnlyAction);
                }

                let raw = self.db.get_loan(loan_id)?
                    .ok_or_else(|| ChronxError::LoanNotFound(hex::encode(loan_id)))?;
                let mut loan_val: serde_json::Value = serde_json::from_slice(&raw)
                    .map_err(|_| ChronxError::SerializationError)?;
                let status = loan_val.get("status").and_then(|s| s.as_str()).unwrap_or("");
                if status != "active" && !status.starts_with("reinstated") {
                    return Err(ChronxError::LoanNotActive);
                }
                loan_val["status"] = serde_json::json!({"Defaulted": {"defaulted_at": *defaulted_at}});
                let updated_bytes = serde_json::to_vec(&loan_val)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_loan(loan_id, &updated_bytes)?;

                // Persist detailed default record
                let default_record = LoanDefaultRecord {
                    loan_id: *loan_id,
                    missed_stage_index: *missed_stage_index,
                    missed_amount_kx: *missed_amount_kx,
                    late_fees_accrued_kx: *late_fees_accrued_kx,
                    days_overdue: *days_overdue,
                    outstanding_balance_kx: *outstanding_balance_kx,
                    stages_remaining: *stages_remaining,
                    defaulted_at: *defaulted_at,
                    memo: memo.clone()
                };
                self.db.save_loan_default(loan_id, &default_record)?;

                info!(loan_id = %hex::encode(loan_id),
                      missed_stage = %missed_stage_index,
                      days_overdue = %days_overdue,
                      "Loan default recorded");
                Ok(())
            }

            Action::LoanReinstatement { loan_id, cure_amount_kx: _, new_stages, memo } => {
                let raw = self.db.get_loan(loan_id)?
                    .ok_or_else(|| ChronxError::LoanNotFound(hex::encode(loan_id)))?;
                let mut loan_val: serde_json::Value = serde_json::from_slice(&raw)
                    .map_err(|_| ChronxError::SerializationError)?;
                let is_defaulted = loan_val.get("status").map(|s| {
                    s.as_str() == Some("defaulted") || s.to_string().contains("Defaulted")
                }).unwrap_or(false);
                if !is_defaulted {
                    return Err(ChronxError::LoanNotInDefault);
                }

                // Validate new stages
                if new_stages.is_empty() { return Err(ChronxError::InvalidLoanStages); }
                for w in new_stages.windows(2) {
                    if w[1].due_at <= w[0].due_at {
                        return Err(ChronxError::LoanStagesNotOrdered);
                    }
                }

                loan_val["status"] = serde_json::json!({"Reinstated": {"reinstated_at": now as u64}});
                loan_val["stages"] = serde_json::to_value(new_stages).unwrap_or(serde_json::Value::Null);
                if let Some(m) = memo { loan_val["memo"] = serde_json::json!(m); }
                let updated_bytes = serde_json::to_vec(&loan_val)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_loan(loan_id, &updated_bytes)?;

                info!(loan_id = %hex::encode(loan_id), "Loan reinstated");
                Ok(())
            }

            Action::LoanWriteOff { loan_id, outstanding_balance_kx, write_off_date, memo } => {
                let raw = self.db.get_loan(loan_id)?
                    .ok_or_else(|| ChronxError::LoanNotFound(hex::encode(loan_id)))?;
                let mut loan_val: serde_json::Value = serde_json::from_slice(&raw)
                    .map_err(|_| ChronxError::SerializationError)?;
                let is_defaulted = loan_val.get("status").map(|s| {
                    s.as_str() == Some("defaulted") || s.to_string().contains("Defaulted")
                }).unwrap_or(false);
                if !is_defaulted {
                    return Err(ChronxError::LoanNotInDefault);
                }

                // Only the lender (tx sender) may write off
                let lender_str = loan_val.get("lender_wallet")
                    .or_else(|| loan_val.get("lender"))
                    .and_then(|v| v.as_str()).unwrap_or("");
                if sender.account_id.to_string() != lender_str {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                loan_val["status"] = serde_json::json!({"WrittenOff": {"written_off_at": *write_off_date, "outstanding_kx": *outstanding_balance_kx}});
                if let Some(m) = memo { loan_val["memo"] = serde_json::json!(m); }
                let updated_bytes = serde_json::to_vec(&loan_val)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_loan(loan_id, &updated_bytes)?;

                info!(loan_id = %hex::encode(loan_id), "Loan written off");
                Ok(())
            }

            Action::LoanEarlyPayoff { loan_id, payoff_amount_kx, memo } => {
                let raw = self.db.get_loan(loan_id)?
                    .ok_or_else(|| ChronxError::LoanNotFound(hex::encode(loan_id)))?;
                let mut loan_val: serde_json::Value = serde_json::from_slice(&raw)
                    .map_err(|_| ChronxError::SerializationError)?;
                let status = loan_val.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let is_active = status == "active" || loan_val.get("status").map(|s| s.to_string().contains("Reinstated")).unwrap_or(false);
                if !is_active {
                    return Err(ChronxError::LoanNotActive);
                }

                // Check prepayment terms
                let prepayment = loan_val.get("prepayment").and_then(|v| v.as_str()).unwrap_or("");
                if prepayment == "Prohibited" {
                    return Err(ChronxError::PrepaymentProhibited);
                }

                loan_val["status"] = serde_json::json!({"EarlyPayoff": {"paid_off_at": now as u64}});
                if let Some(m) = memo { loan_val["memo"] = serde_json::json!(m); }
                let updated_bytes = serde_json::to_vec(&loan_val)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_loan(loan_id, &updated_bytes)?;

                info!(loan_id = %hex::encode(loan_id), payoff_kx = %payoff_amount_kx, "Loan early payoff");
                Ok(())
            }


            // ── LenderMemo ─────────────────────────────────────
            Action::LenderMemo { loan_id, default_record_id, ref memo, .. } => {
                let memo_key = format!("{}:{}", hex::encode(loan_id), hex::encode(default_record_id));
                if self.db.loan_memos.contains_key(memo_key.as_bytes()).map_err(|_| ChronxError::DatabaseError)? {
                    return Err(ChronxError::DuplicateMemo);
                }
                let truncated: String = memo.chars().take(512).collect();
                let val = serde_json::to_vec(&serde_json::json!({
                    "loan_id": hex::encode(loan_id),
                    "default_record_id": hex::encode(default_record_id),
                    "memo": truncated
                })).map_err(|_| ChronxError::SerializationError)?;
                self.db.loan_memos.insert(memo_key.as_bytes(), val).map_err(|_| ChronxError::DatabaseError)?;
                Ok(())
            }

            Action::LoanCompletion { loan_id, total_paid_kx, completion_date, stages_completed, memo: _ } => {
                // Only MISAI executor may mark completion
                let misai_executor = self.db
                    .get_meta("misai_executor_wallet")?
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_default();
                if misai_executor.is_empty() || sender.account_id.to_string() != misai_executor {
                    return Err(ChronxError::MisaiOnlyAction);
                }

                let raw = self.db.get_loan(loan_id)?
                    .ok_or_else(|| ChronxError::LoanNotFound(hex::encode(loan_id)))?;
                let mut loan_val: serde_json::Value = serde_json::from_slice(&raw)
                    .map_err(|_| ChronxError::SerializationError)?;
                let status = loan_val.get("status").and_then(|s| s.as_str()).unwrap_or("");
                if status != "active" && !status.starts_with("reinstated") && !loan_val.get("status").map(|s| s.to_string().contains("Reinstated")).unwrap_or(false) {
                    return Err(ChronxError::LoanNotActive);
                }
                loan_val["status"] = serde_json::json!({"Completed": {"completed_at": *completion_date}});
                let updated_bytes = serde_json::to_vec(&loan_val)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_loan(loan_id, &updated_bytes)?;

                info!(loan_id = %hex::encode(loan_id),
                      total_paid_kx = %total_paid_kx,
                      stages = %stages_completed,
                      "Loan completed");
                Ok(())
            }

            // ── Payment Channels (scaffolding) ──────────────────
            Action::ChannelOpen { channel_id, counterparty, locked_chronos, metadata: _ } => {
                if *locked_chronos == 0 {
                    return Err(ChronxError::ZeroAmount);
                }
                info!(channel_id = %hex::encode(channel_id),
                      opener = %sender.account_id, counterparty = %counterparty,
                      locked = locked_chronos,
                      "[CHANNEL] opened");
                Ok(())
            }

            Action::ChannelClose { channel_id, net_settlement_chronos, payment_count, final_state_hash: _ } => {
                // Apply net settlement to balances
                // net_settlement_chronos: positive = opener pays counterparty, negative = counterparty pays opener
                info!(channel_id = %hex::encode(channel_id),
                      payments = payment_count,
                      net = net_settlement_chronos,
                      "[CHANNEL] closed");
                Ok(())
            }

            // ── LoanExit (with pro-rata settlement) ─────────────
            Action::LoanExit { ref loan_id, .. } => {
                // Rate limit
                self.check_loan_rate_limit(&sender.account_id.to_string(), now)?;

                // Load raw loan JSON
                if let Ok(Some(existing)) = self.db.get_loan(loan_id) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        let status = loan_val.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        if status != "active" {
                            return Err(ChronxError::LoanNotActive);
                        }

                        // A5: Pro-rata settlement before closing
                        let rate_bps = loan_val.get("interest_rate")
                            .and_then(|v| v.get("Fixed"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let principal_kx = loan_val.get("principal_kx").and_then(|v| v.as_u64()).unwrap_or(0);
                        let principal_chronos = loan_val.get("principal_chronos").and_then(|v| v.as_u64())
                            .unwrap_or(principal_kx * 1_000_000);
                        let last_at = loan_val.get("last_settlement_at").and_then(|v| v.as_i64())
                            .or_else(|| loan_val.get("accepted_at").and_then(|v| v.as_i64()))
                            .or_else(|| loan_val.get("created_at").and_then(|v| v.as_i64()))
                            .unwrap_or(0);
                        let elapsed = (now - last_at).max(0) as u64;

                        if rate_bps > 0 && principal_chronos > 0 && elapsed > 0 {
                            let accrued = (principal_chronos as u128)
                                .checked_mul(rate_bps as u128).unwrap_or(0)
                                .checked_mul(elapsed as u128).unwrap_or(0)
                                / (10_000u128 * 31_536_000u128);
                            let accrued = accrued as u64;

                            if accrued >= 1 {
                                let borrower_str = loan_val.get("borrower_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let lender_str = loan_val.get("lender_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                if let (Ok(bid), Ok(lid)) = (
                                    chronx_core::types::AccountId::from_b58(&borrower_str),
                                    chronx_core::types::AccountId::from_b58(&lender_str),
                                ) {
                                    if let (Ok(Some(mut bacc)), Ok(Some(mut lacc))) = (
                                        self.db.get_account(&bid),
                                        self.db.get_account(&lid),
                                    ) {
                                        if bacc.balance >= accrued as u128 {
                                            bacc.balance -= accrued as u128;
                                            lacc.balance += accrued as u128;
                                            self.db.put_account(&bacc)?;
                                            self.db.put_account(&lacc)?;
                                            info!(accrued_chronos = accrued,
                                                  loan_id = %hex::encode(loan_id),
                                                  "[LOAN EXIT] final settlement");
                                        }
                                    }
                                }
                            }
                        }

                        // Close the loan
                        loan_val["status"] = serde_json::json!("closed");
                        loan_val["closed_at"] = serde_json::json!(now as u64);
                        let updated = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(loan_id, &updated)?;
                        info!(loan_id = %hex::encode(loan_id), "[LOAN EXIT] closed");
                        Ok(())
                    } else {
                        Err(ChronxError::SerializationError)
                    }
                } else {
                    Err(ChronxError::LoanNotFound(hex::encode(loan_id)))
                }
            }

            // ── v2.5.29: Loan transfer (disabled) ────────────────────────
            Action::LoanTransfer { .. } => {
                Err(ChronxError::Other(
                    "Loan transfer requires governance activation. \
                     Secondary loan market coming post-ICO.".into()
                ))
            }

            // ── v2.5.29: Credit visibility (disabled) ────────────────────
            Action::CreditVisibilityUpdate { .. } => {
                Err(ChronxError::Other(
                    "Credit visibility requires governance activation.".into()
                ))
            }

            Action::LoanFlagPost { .. } => {
                Err(ChronxError::FeatureNotActive(
                    "Loan flag post requires governance activation (loan_flag_post_enabled).".into()
                ))
            }

            Action::CreditHistoryPurge { acknowledged_irreversible, .. } => {
                if !acknowledged_irreversible {
                    return Err(ChronxError::Other(
                        "Must acknowledge irreversibility before purging credit history.".into()
                    ));
                }
                Err(ChronxError::FeatureNotActive(
                    "Credit history purge requires governance activation (credit_history_purge_enabled).".into()
                ))
            }

            Action::AccreditedLenderRegister { .. } => {
                Err(ChronxError::FeatureNotActive(
                    "Accredited lender registry requires governance activation.".into()
                ))
            }

            Action::AccreditedLenderRevoke { .. } => {
                Err(ChronxError::FeatureNotActive(
                    "Accredited lender registry requires governance activation.".into()
                ))
            }

            // ── v2.5.29: Rescission cancel ───────────────────────────────
            Action::LoanRescissionCancel { ref loan_id, ref cancelled_by, .. } => {
                self.check_loan_rate_limit(&sender.account_id.to_string(), now)?;

                // Parse loan_id string as hex into [u8; 32]
                let lid_bytes: [u8; 32] = {
                    let decoded = hex::decode(loan_id)
                        .map_err(|_| ChronxError::Other("Bad loan_id hex".into()))?;
                    if decoded.len() != 32 {
                        return Err(ChronxError::Other("loan_id must be 32 bytes".into()));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    arr
                };

                if let Ok(Some(existing)) = self.db.get_loan(&lid_bytes) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        let status = loan_val.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        if status != "accepted_pending_rescission" {
                            return Err(ChronxError::Other(
                                "Loan is not in rescission window.".into()
                            ));
                        }

                        // Verify submitter is lender or borrower
                        let lender = loan_val.get("lender_wallet").and_then(|s| s.as_str()).unwrap_or("");
                        let borrower = loan_val.get("borrower_wallet").and_then(|s| s.as_str()).unwrap_or("")
                            .to_string();
                        let borrower2 = loan_val.get("borrower").and_then(|s| s.as_str()).unwrap_or("").to_string();
                        let submitter_str = sender.account_id.to_string();
                        if submitter_str != lender && submitter_str != borrower && submitter_str != borrower2 {
                            return Err(ChronxError::Other(
                                "Only loan parties may cancel during rescission.".into()
                            ));
                        }

                        // Check window not expired
                        let expires = loan_val.get("rescission_expires_at")
                            .and_then(|v| v.as_i64()).unwrap_or(0);
                        if now > expires {
                            return Err(ChronxError::Other(
                                "Rescission window has closed. Loan is now active.".into()
                            ));
                        }

                        // Cancel: return escrow to lender, revert to declined
                        if let Ok(Some(escrow_val)) = self.db.get_loan_escrow(&lid_bytes) {
                            let escrow_amount: u128 = escrow_val.get("amount_chronos")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            let escrow_lender = escrow_val.get("lender_wallet")
                                .and_then(|v| v.as_str()).unwrap_or("").to_string();
                            if escrow_amount > 0 && !escrow_lender.is_empty() {
                                let lender_id = chronx_core::types::AccountId::from_b58(&escrow_lender)
                                    .map_err(|_| ChronxError::Other("Invalid lender address".into()))?;
                                let mut lender_acc = self.db.get_account(&lender_id)?
                                    .ok_or_else(|| ChronxError::Other("Lender account not found".into()))?;
                                lender_acc.balance += escrow_amount;
                                self.db.put_account(&lender_acc)?;
                                self.db.remove_loan_escrow(&lid_bytes)?;
                                info!(loan_id = %loan_id,
                                      amount_kx = escrow_amount / 1_000_000,
                                      "[ESCROW RETURN] Funds returned to lender on rescission cancel");
                            }
                        }

                        loan_val["status"] = serde_json::json!("declined");
                        loan_val["rescission_cancelled_at"] = serde_json::json!(now as u64);
                        loan_val["rescission_cancelled_by"] = serde_json::json!(cancelled_by);
                        let updated = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(&lid_bytes, &updated)?;
                        info!(loan_id = %loan_id, cancelled_by = %cancelled_by,
                              "[RESCISSION CANCEL] Loan cancelled during rescission window");
                        Ok(())
                    } else {
                        Err(ChronxError::SerializationError)
                    }
                } else {
                    Err(ChronxError::Other("Loan not found".into()))
                }
            }


            // ── Rescission waive — skip wait, activate immediately ────────
            Action::LoanRescissionWaive { ref loan_id, ref waived_by, .. } => {
                self.check_loan_rate_limit(&sender.account_id.to_string(), now)?;

                let lid_bytes: [u8; 32] = {
                    let decoded = hex::decode(loan_id)
                        .map_err(|_| ChronxError::Other("Bad loan_id hex".into()))?;
                    if decoded.len() != 32 {
                        return Err(ChronxError::Other("loan_id must be 32 bytes".into()));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    arr
                };

                if let Ok(Some(existing)) = self.db.get_loan(&lid_bytes) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        let status = loan_val.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        if status != "accepted_pending_rescission" {
                            return Err(ChronxError::Other(
                                "Loan is not in rescission window.".into()
                            ));
                        }

                        // Verify submitter is lender or borrower
                        let lender = loan_val.get("lender_wallet").and_then(|s| s.as_str()).unwrap_or("");
                        let borrower = loan_val.get("borrower_wallet").and_then(|s| s.as_str()).unwrap_or("").to_string();
                        let submitter_str = sender.account_id.to_string();
                        if submitter_str != lender && submitter_str != borrower {
                            return Err(ChronxError::Other(
                                "Only loan parties may waive rescission.".into()
                            ));
                        }

                        // Release escrow to borrower immediately
                        let borrower_str = borrower.clone();
                        if let Ok(Some(escrow_val)) = self.db.get_loan_escrow(&lid_bytes) {
                            let escrow_amount: u128 = escrow_val.get("amount_chronos")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            if escrow_amount > 0 && !borrower_str.is_empty() {
                                let borrower_id = chronx_core::types::AccountId::from_b58(&borrower_str)
                                    .map_err(|_| ChronxError::Other("Invalid borrower address".into()))?;
                                let mut borrower_acc = match self.db.get_account(&borrower_id)? {
                                    Some(a) => a,
                                    None => {
                                        chronx_core::account::Account {
                                            account_id: borrower_id.clone(), balance: 0,
                                            auth_policy: chronx_core::account::AuthPolicy::SingleSig {
                                                public_key: chronx_core::types::DilithiumPublicKey(Vec::new())
                                            },
                                            nonce: 0, recovery_state: Default::default(),
                                            post_recovery_restriction: None,
                                            verifier_stake: 0, is_verifier: false, account_version: 3,
                                            created_at: Some(now), display_name_hash: None,
                                            incoming_locks_count: 0, outgoing_locks_count: 0,
                                            total_locked_incoming_chronos: 0,
                                            total_locked_outgoing_chronos: 0,
                                            preferred_fiat_currency: None, lock_marker: None,
                                            savings_balance: 0, savings_invested: false, savings_withdrawal_pending: false
                                        }
                                    }
                                };
                                borrower_acc.balance += escrow_amount;
                                self.db.put_account(&borrower_acc)?;
                                self.db.remove_loan_escrow(&lid_bytes)?;
                                info!(loan_id = %loan_id,
                                      amount_kx = escrow_amount / 1_000_000,
                                      "[ESCROW RELEASE] Funds released to borrower on rescission waive");
                            }
                        } else {
                            // Fallback for pre-fix loans without escrow record
                            let lender_str = lender.to_string();
                            let principal_kx = loan_val.get("principal_kx").and_then(|v| v.as_u64()).unwrap_or(0);
                            let principal_chronos = loan_val.get("principal_chronos").and_then(|v| v.as_u64())
                                .unwrap_or(principal_kx * 1_000_000) as u128;
                            if principal_chronos > 0 && !lender_str.is_empty() && !borrower_str.is_empty() {
                                let lender_id = chronx_core::types::AccountId::from_b58(&lender_str)
                                    .map_err(|_| ChronxError::Other("Invalid lender address".into()))?;
                                let borrower_id = chronx_core::types::AccountId::from_b58(&borrower_str)
                                    .map_err(|_| ChronxError::Other("Invalid borrower address".into()))?;
                                let mut lender_acc = self.db.get_account(&lender_id)?
                                    .ok_or_else(|| ChronxError::Other("Lender account not found".into()))?;
                                if lender_acc.balance < principal_chronos {
                                    return Err(ChronxError::InsufficientBalance {
                                        need: principal_chronos, have: lender_acc.balance,
                                    });
                                }
                                lender_acc.balance -= principal_chronos;
                                self.db.put_account(&lender_acc)?;
                                let mut borrower_acc = match self.db.get_account(&borrower_id)? {
                                    Some(a) => a,
                                    None => {
                                        chronx_core::account::Account {
                                            account_id: borrower_id.clone(), balance: 0,
                                            auth_policy: chronx_core::account::AuthPolicy::SingleSig {
                                                public_key: chronx_core::types::DilithiumPublicKey(Vec::new())
                                            },
                                            nonce: 0, recovery_state: Default::default(),
                                            post_recovery_restriction: None,
                                            verifier_stake: 0, is_verifier: false, account_version: 3,
                                            created_at: Some(now), display_name_hash: None,
                                            incoming_locks_count: 0, outgoing_locks_count: 0,
                                            total_locked_incoming_chronos: 0,
                                            total_locked_outgoing_chronos: 0,
                                            preferred_fiat_currency: None, lock_marker: None,
                                            savings_balance: 0, savings_invested: false, savings_withdrawal_pending: false
                                        }
                                    }
                                };
                                borrower_acc.balance += principal_chronos;
                                self.db.put_account(&borrower_acc)?;
                            }
                        }

                        // Activate the loan
                        loan_val["status"] = serde_json::json!("active");
                        loan_val["activated_at"] = serde_json::json!(now as u64);
                        loan_val["rescission_waived_by"] = serde_json::json!(waived_by);
                        loan_val["rescission_waived_at"] = serde_json::json!(now as u64);
                        let updated = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(&lid_bytes, &updated)?;
                        info!(loan_id = %loan_id, waived_by = %waived_by,
                              "[RESCISSION WAIVE] Loan activated immediately, KX transferred");
                        Ok(())
                    } else {
                        Err(ChronxError::SerializationError)
                    }
                } else {
                    Err(ChronxError::Other("Loan not found".into()))
                }
            }

            Action::DrawRequest { .. } => {
                Err(ChronxError::FeatureNotActive(
                    "Milestone draw loans require governance activation.".into()
                ))
            }

            Action::DrawApproval { .. } => {
                Err(ChronxError::FeatureNotActive(
                    "Milestone draw loans require governance activation.".into()
                ))
            }

            Action::DrawDecline { .. } => {
                Err(ChronxError::FeatureNotActive(
                    "Milestone draw loans require governance activation.".into()
                ))
            }


            // ── TYPE A — Authority Grant ─────────────────────────────────────────
            Action::AuthorityGrant(ref action) => {
                use chronx_core::transaction::AuthorityType;

                let sender_b58 = sender.account_id.to_b58();

                // 1. Verify grantor has authority to grant
                match action.authority_type {
                    AuthorityType::Tier1 => {
                        // Only KXGC wallet may issue Tier1 grants
                        let kxgc_b58 = self.db.get_meta("kxgc_bond_wallet")
                            .ok()
                            .flatten()
                            .map(|b| String::from_utf8_lossy(&b).to_string())
                            .unwrap_or_default();
                        if sender_b58 != kxgc_b58 {
                            return Err(ChronxError::Other(
                                "TYPE_A_TIER1_REQUIRES_KXGC: Only the KXGC bond wallet may issue Tier 1 authority grants.".into()
                            ));
                        }
                    }
                    AuthorityType::Tier2 => {
                        // Grantor must have an active Tier1 grant with can_subgrant=true
                        let mut has_authority = false;
                        for (_key, val) in self.db.iter_authority_grants() {
                            if let Ok(grant) = serde_json::from_slice::<serde_json::Value>(&val) {
                                let grantee = grant.get("grantee_wallet").and_then(|v| v.as_str()).unwrap_or("");
                                let status = grant.get("status").and_then(|v| v.as_str()).unwrap_or("");
                                let tier = grant.get("authority_type").and_then(|v| v.as_str()).unwrap_or("");
                                let can_sub = grant.get("can_subgrant").and_then(|v| v.as_bool()).unwrap_or(false);

                                if grantee == sender_b58 && status == "Active" && tier == "Tier1" && can_sub {
                                    // Verify sub-grant limits do not exceed grantor limits
                                    let grantor_coverage = grant.get("max_coverage_ratio")
                                        .and_then(|v| v.as_f64()).unwrap_or(0.0);
                                    let grantor_invest = grant.get("max_investable_pct")
                                        .and_then(|v| v.as_f64()).unwrap_or(0.0);

                                    if action.subgrant_max_coverage > grantor_coverage {
                                        return Err(ChronxError::Other(
                                            format!("TYPE_A_SUBGRANT_EXCEEDS_COVERAGE: subgrant_max_coverage {} exceeds grantor limit {}",
                                                action.subgrant_max_coverage, grantor_coverage)
                                        ));
                                    }
                                    if action.subgrant_max_invest > grantor_invest {
                                        return Err(ChronxError::Other(
                                            format!("TYPE_A_SUBGRANT_EXCEEDS_INVEST: subgrant_max_invest {} exceeds grantor limit {}",
                                                action.subgrant_max_invest, grantor_invest)
                                        ));
                                    }
                                    if action.max_coverage_ratio > grantor_coverage {
                                        return Err(ChronxError::Other(
                                            format!("TYPE_A_COVERAGE_EXCEEDS_GRANTOR: max_coverage_ratio {} exceeds grantor limit {}",
                                                action.max_coverage_ratio, grantor_coverage)
                                        ));
                                    }
                                    if action.max_investable_pct > grantor_invest {
                                        return Err(ChronxError::Other(
                                            format!("TYPE_A_INVEST_EXCEEDS_GRANTOR: max_investable_pct {} exceeds grantor limit {}",
                                                action.max_investable_pct, grantor_invest)
                                        ));
                                    }
                                    has_authority = true;
                                    break;
                                }
                            }
                        }
                        if !has_authority {
                            return Err(ChronxError::Other(
                                "TYPE_A_TIER2_REQUIRES_TIER1: Sender has no active Tier 1 grant with can_subgrant=true.".into()
                            ));
                        }
                    }
                }

                // 2. Validate fields
                if action.max_coverage_ratio < 0.0 || action.max_coverage_ratio > 100.0 {
                    return Err(ChronxError::Other("TYPE_A: max_coverage_ratio must be 0.0-100.0".into()));
                }
                if action.max_investable_pct < 0.0 || action.max_investable_pct > 1.0 {
                    return Err(ChronxError::Other("TYPE_A: max_investable_pct must be 0.0-1.0".into()));
                }
                if let Some(ref memo) = action.memo {
                    if memo.len() > 256 {
                        return Err(ChronxError::Other("TYPE_A: memo exceeds 256 bytes".into()));
                    }
                }

                // 3. Build grant record
                let grant_id = tx_id.as_bytes();
                let now_u64 = now as u64;
                let grant_record = serde_json::json!({
                    "grantor_wallet": sender_b58,
                    "grantee_wallet": action.grantee_wallet.to_b58(),
                    "authority_type": match action.authority_type {
                        AuthorityType::Tier1 => "Tier1",
                        AuthorityType::Tier2 => "Tier2",
                    },
                    "max_coverage_ratio": action.max_coverage_ratio,
                    "max_investable_pct": action.max_investable_pct,
                    "max_obligations_kx": action.max_obligations_kx,
                    "can_subgrant": action.can_subgrant,
                    "subgrant_max_coverage": action.subgrant_max_coverage,
                    "subgrant_max_invest": action.subgrant_max_invest,
                    "effective_from": action.effective_from,
                    "effective_until": action.effective_until,
                    "revocation_notice_seconds": action.revocation_notice_seconds,
                    "status": "Active",
                    "created_at": now_u64,
                    "memo": action.memo,
                    "grant_vertex_id": hex::encode(grant_id),
                });

                let data = serde_json::to_vec(&grant_record)
                    .map_err(|_| ChronxError::SerializationError)?;

                let mut id_arr = [0u8; 32];
                id_arr.copy_from_slice(grant_id);
                self.db.save_authority_grant(&id_arr, &data)?;

                info!(
                    grantor = %sender_b58,
                    grantee = %action.grantee_wallet.to_b58(),
                    tier = ?action.authority_type,
                    coverage = action.max_coverage_ratio,
                    "[TYPE A] authority grant issued"
                );
                Ok(())
            }

            // ── TYPE A — Authority Revoke ────────────────────────────────────────
            Action::AuthorityRevoke(ref action) => {
                let sender_b58 = sender.account_id.to_b58();

                // 1. Find original grant
                let grant_id_bytes = action.grant_vertex_id.as_bytes();
                let mut id_arr = [0u8; 32];
                id_arr.copy_from_slice(grant_id_bytes);

                let existing = self.db.get_authority_grant(&id_arr)?
                    .ok_or_else(|| ChronxError::Other(
                        "TYPE_A_REVOKE: grant not found".into()
                    ))?;

                let mut grant_val: serde_json::Value = serde_json::from_slice(&existing)
                    .map_err(|_| ChronxError::SerializationError)?;

                // 2. Verify revoking wallet is the original grantor
                let grantor = grant_val.get("grantor_wallet")
                    .and_then(|v| v.as_str()).unwrap_or("").to_string();
                if sender_b58 != grantor {
                    return Err(ChronxError::Other(
                        "TYPE_A_REVOKE: only the original grantor may revoke".into()
                    ));
                }

                // 3. Check current status
                let status = grant_val.get("status")
                    .and_then(|v| v.as_str()).unwrap_or("").to_string();
                if status != "Active" && status != "PendingRevocation" {
                    return Err(ChronxError::Other(
                        format!("TYPE_A_REVOKE: grant status is '{}', cannot revoke", status)
                    ));
                }

                // 4. Validate reason
                if action.reason.is_empty() || action.reason.len() > 512 {
                    return Err(ChronxError::Other(
                        "TYPE_A_REVOKE: reason required (1-512 bytes)".into()
                    ));
                }

                // 5. Apply notice period
                let notice_secs = grant_val.get("revocation_notice_seconds")
                    .and_then(|v| v.as_u64()).unwrap_or(2_592_000);
                let now_u64 = now as u64;
                let executes_at = now_u64 + notice_secs;

                grant_val["status"] = serde_json::json!("PendingRevocation");
                grant_val["revocation_submitted_at"] = serde_json::json!(now_u64);
                grant_val["revocation_executes_at"] = serde_json::json!(executes_at);
                grant_val["revocation_reason"] = serde_json::json!(action.reason);

                let updated = serde_json::to_vec(&grant_val)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_authority_grant(&id_arr, &updated)?;

                let grantee = grant_val.get("grantee_wallet")
                    .and_then(|v| v.as_str()).unwrap_or("unknown");
                info!(
                    grantor = %sender_b58,
                    grantee = %grantee,
                    executes_at = executes_at,
                    "[TYPE A] authority revocation notice issued ({}s notice)",
                    notice_secs
                );
                Ok(())
            }


            // -- Genesis Zero -- Obligation Transfer handlers ---------------------

            Action::ObligationTransfer(ref action) => {
                // 1. Find obligation (loan) by obligation_id
                let id_bytes: [u8; 32] = action.obligation_id.0;
                if let Ok(Some(existing)) = self.db.get_loan(&id_bytes) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        // 2. Verify signed_by == current_owner
                        let current_owner = loan_val.get("current_owner")
                            .and_then(|v| v.as_str())
                            .unwrap_or_else(|| {
                                loan_val.get("lender_wallet")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                            });
                        let signed_by_str = action.signed_by.to_string();
                        if signed_by_str != current_owner {
                            return Err(ChronxError::Other(
                                "OBLIGATION_TRANSFER: signed_by does not match current_owner".into()
                            ));
                        }

                        // 3. Check transferable flag
                        let transfer_flag = loan_val.get("transferable")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Free");
                        if transfer_flag == "Locked" {
                            return Err(ChronxError::Other(
                                "OBLIGATION_TRANSFER: obligation is not transferable (Locked)".into()
                            ));
                        }

                        // 4. If Restricted, check governance_unlock_at
                        if transfer_flag == "Restricted" {
                            if let Some(conditions) = loan_val.get("transfer_conditions") {
                                if let Some(unlock_at) = conditions.get("governance_unlock_at").and_then(|v| v.as_u64()) {
                                    if (now as u64) < unlock_at {
                                        return Err(ChronxError::Other(
                                            "OBLIGATION_TRANSFER: governance unlock date not reached".into()
                                        ));
                                    }
                                }
                            }
                        }

                        // 5. Update current_owner
                        loan_val["current_owner"] = serde_json::json!(action.to_wallet.to_string());

                        // 6. Append to transfer_history
                        let record = serde_json::json!({
                            "from_wallet": action.from_wallet.to_string(),
                            "to_wallet": action.to_wallet.to_string(),
                            "consideration_kx": action.consideration_kx,
                            "consideration_currency": action.consideration_currency,
                            "transferred_at": now as u64
                        });
                        if let Some(history) = loan_val.get_mut("transfer_history") {
                            if let Some(arr) = history.as_array_mut() {
                                arr.push(record);
                            }
                        } else {
                            loan_val["transfer_history"] = serde_json::json!([record]);
                        }

                        let updated = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(&id_bytes, &updated)?;

                        info!(obligation = %hex::encode(id_bytes),
                              from = %action.from_wallet.to_string(),
                              to = %action.to_wallet.to_string(),
                              "[OBLIGATION TRANSFER] ownership transferred");
                        Ok(())
                    } else {
                        Err(ChronxError::SerializationError)
                    }
                } else {
                    Err(ChronxError::Other("Obligation not found".into()))
                }
            }

            Action::ObligationTranche(ref action) => {
                // 1. Find obligation
                let id_bytes: [u8; 32] = action.parent_obligation_id.0;
                if let Ok(Some(existing)) = self.db.get_loan(&id_bytes) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        // 2. Verify signed_by == current_owner
                        let current_owner = loan_val.get("current_owner")
                            .and_then(|v| v.as_str())
                            .unwrap_or_else(|| {
                                loan_val.get("lender_wallet")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                            });
                        let signed_by_str = action.signed_by.to_string();
                        if signed_by_str != current_owner {
                            return Err(ChronxError::Other(
                                "OBLIGATION_TRANCHE: signed_by does not match current_owner".into()
                            ));
                        }

                        // 3. Validate tranche_count
                        let max_tranches: u32 = self.db.get_meta("max_tranches_per_obligation")
                            .ok().flatten()
                            .and_then(|b| String::from_utf8(b).ok())
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(1000);
                        if action.tranche_count > max_tranches {
                            return Err(ChronxError::Other(
                                format!("OBLIGATION_TRANCHE: tranche_count {} exceeds max {}", action.tranche_count, max_tranches)
                            ));
                        }

                        // 4. Validate face_value_per_tranche_kx
                        let min_face: u64 = self.db.get_meta("min_tranche_face_value_kx")
                            .ok().flatten()
                            .and_then(|b| String::from_utf8(b).ok())
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(1000);
                        if action.face_value_per_tranche_kx < min_face {
                            return Err(ChronxError::Other(
                                format!("OBLIGATION_TRANCHE: face_value {} below minimum {}", action.face_value_per_tranche_kx, min_face)
                            ));
                        }

                        // 5. Mark parent as tranched, record child count
                        loan_val["tranched"] = serde_json::json!(true);
                        loan_val["tranche_count"] = serde_json::json!(action.tranche_count);

                        let updated = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(&id_bytes, &updated)?;

                        info!(parent = %hex::encode(id_bytes),
                              tranches = action.tranche_count,
                              face_kx = action.face_value_per_tranche_kx,
                              "[OBLIGATION TRANCHE] obligation split into tranches");
                        Ok(())
                    } else {
                        Err(ChronxError::SerializationError)
                    }
                } else {
                    Err(ChronxError::Other("Obligation not found".into()))
                }
            }

            Action::ObligationRetire(ref action) => {
                // 1. Find obligation
                let id_bytes: [u8; 32] = action.obligation_id.0;
                if let Ok(Some(existing)) = self.db.get_loan(&id_bytes) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        // 2. Verify retiring_wallet is borrower or authorized
                        let borrower = loan_val.get("borrower_wallet")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let retiring_str = action.retiring_wallet.to_string();
                        if retiring_str != borrower {
                            return Err(ChronxError::Other(
                                "OBLIGATION_RETIRE: retiring_wallet is not the borrower".into()
                            ));
                        }

                        // 3. Validate retire_fraction
                        if action.retire_fraction < 0.0 || action.retire_fraction > 1.0 {
                            return Err(ChronxError::Other(
                                "OBLIGATION_RETIRE: retire_fraction must be between 0.0 and 1.0".into()
                            ));
                        }

                        // 4. Update retirement fields
                        let prev_fraction = loan_val.get("retired_fraction")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let new_fraction = (prev_fraction + action.retire_fraction).min(1.0);

                        loan_val["retired_fraction"] = serde_json::json!(new_fraction);
                        if (new_fraction - 1.0).abs() < f64::EPSILON {
                            loan_val["retirement_status"] = serde_json::json!("FullyRetired");
                            loan_val["status"] = serde_json::json!("closed");
                        } else if new_fraction > 0.0 {
                            loan_val["retirement_status"] = serde_json::json!("PartiallyRetired");
                        }

                        if let Some(ref ann) = action.announcement {
                            loan_val["retirement_announcement"] = serde_json::json!(ann);
                        }

                        let updated = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(&id_bytes, &updated)?;

                        info!(obligation = %hex::encode(id_bytes),
                              fraction = new_fraction,
                              "[OBLIGATION RETIRE] obligation retired");
                        Ok(())
                    } else {
                        Err(ChronxError::SerializationError)
                    }
                } else {
                    Err(ChronxError::Other("Obligation not found".into()))
                }
            }

            Action::TransferFlagUpdate(ref action) => {
                // 1. Find obligation
                let id_bytes: [u8; 32] = action.obligation_id.0;
                if let Ok(Some(existing)) = self.db.get_loan(&id_bytes) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        // 2. Verify lender_wallet is original lender
                        let lender = loan_val.get("lender_wallet")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let lender_str = action.lender_wallet.to_string();
                        if lender_str != lender {
                            return Err(ChronxError::Other(
                                "TRANSFER_FLAG_UPDATE: only the original lender may update transfer flag".into()
                            ));
                        }

                        // 3. Serialize the new flag
                        let flag_val = serde_json::to_value(&action.new_flag)
                            .unwrap_or(serde_json::json!("Free"));
                        loan_val["transferable"] = flag_val;
                        loan_val["transfer_flag_updated_at"] = serde_json::json!(now as u64);

                        let updated = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(&id_bytes, &updated)?;

                        info!(obligation = %hex::encode(id_bytes),
                              "[TRANSFER FLAG UPDATE] transfer flag changed");
                        Ok(())
                    } else {
                        Err(ChronxError::SerializationError)
                    }
                } else {
                    Err(ChronxError::Other("Obligation not found".into()))
                }
            }

            Action::TermsVisibilityUpdate(ref action) => {
                // 1. Find obligation
                let id_bytes: [u8; 32] = action.obligation_id.0;
                if let Ok(Some(existing)) = self.db.get_loan(&id_bytes) {
                    if let Ok(mut loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                        // 2. Verify lender_wallet is original lender
                        let lender = loan_val.get("lender_wallet")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let lender_str = action.lender_wallet.to_string();
                        if lender_str != lender {
                            return Err(ChronxError::Other(
                                "TERMS_VISIBILITY_UPDATE: only the original lender may update terms visibility".into()
                            ));
                        }

                        // 3. Record visibility change history
                        let prev_visibility = loan_val.get("terms_visibility")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Private")
                            .to_string();
                        let new_vis = serde_json::to_value(&action.new_visibility)
                            .unwrap_or(serde_json::json!("Private"));
                        let new_vis_str = new_vis.as_str().unwrap_or("Private").to_string();

                        // Append to visibility change log
                        let change_record = serde_json::json!({
                            "from": prev_visibility,
                            "to": new_vis_str,
                            "changed_at": now as u64
                        });
                        if let Some(log) = loan_val.get_mut("visibility_change_log") {
                            if let Some(arr) = log.as_array_mut() {
                                arr.push(change_record);
                            }
                        } else {
                            loan_val["visibility_change_log"] = serde_json::json!([change_record]);
                        }

                        loan_val["terms_visibility"] = new_vis;

                        let updated = serde_json::to_vec(&loan_val)
                            .map_err(|_| ChronxError::SerializationError)?;
                        self.db.save_loan(&id_bytes, &updated)?;

                        info!(obligation = %hex::encode(id_bytes),
                              from = %prev_visibility,
                              to = %new_vis_str,
                              "[TERMS VISIBILITY] visibility changed");
                        Ok(())
                    } else {
                        Err(ChronxError::SerializationError)
                    }
                } else {
                    Err(ChronxError::Other("Obligation not found".into()))
                }
            }


            // -- Escalation/failure scaffold handlers (store only) -----------------

            Action::EscalateConditional(ref action) => {
                let record = serde_json::json!({
                    "conditional_id": action.conditional_id,
                    "escalator_pubkey": hex::encode(&action.escalator_pubkey),
                    "escalation_type": action.escalation_type,
                    "evidence_hash": hex::encode(&action.evidence_hash),
                    "memo": action.memo,
                    "escalated_at": now as u64
                });
                let data = serde_json::to_vec(&record)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_escalation(&action.conditional_id, &data)?;
                info!(conditional = %action.conditional_id,
                      escalation_type = %action.escalation_type,
                      "[ESCALATE CONDITIONAL] recorded");
                Ok(())
            }

            Action::DeclareAttestorFailure(ref action) => {
                let now_u64 = now as u64;
                let record = serde_json::json!({"group_id": action.group_id, "declaring_wallet": action.declaring_wallet, "failure_type": action.failure_type, "evidence_hash": hex::encode(&action.evidence_hash), "memo": action.memo, "declared_at": now_u64});
                let data = serde_json::to_vec(&record).map_err(|_| ChronxError::SerializationError)?;
                self.db.save_attestor_failure(&action.group_id, &data)?;
                info!(group_id = %action.group_id, failure_type = %action.failure_type, "[ATTESTOR FAILURE] declared — beginning cascade");
                let affected = self.db.get_conditionals_by_attestor_group(&action.group_id)?;
                let mut escalated = 0u32;
                let mut errors = 0u32;
                for cond in &affected {
                    let lid = hex::encode(cond.type_v_id);
                    let r: Result<(), ChronxError> = (|| {
                        self.db.set_conditional_attestors_suspended(&cond.type_v_id, true)?;
                        if let Some(ref ew) = cond.escalation_wallet {
                            self.db.set_conditional_escalation_active(&cond.type_v_id, true)?;
                            let esc = serde_json::json!({"conditional_id": lid, "escalation_type": "AttestorIncapacity", "escalated_to": ew, "triggered_by": action.group_id, "evidence_hash": hex::encode(&action.evidence_hash), "escalated_at": now_u64, "auto_generated": true});
                            self.db.save_escalation(&lid, &serde_json::to_vec(&esc).map_err(|_| ChronxError::SerializationError)?)?;
                            escalated += 1;
                        }
                        Ok(())
                    })();
                    if let Err(e) = r {
                        errors += 1;
                        let err_rec = serde_json::json!({"lock_id": lid, "error": format!("{}", e), "at": now_u64});
                        let _ = self.db.save_escalation_error(&lid, &serde_json::to_vec(&err_rec).unwrap_or_default());
                        warn!(lock_id = %lid, error = %e, "[CASCADE ERROR] continuing");
                    }
                }
                let dr = serde_json::json!({"group_id": action.group_id, "reason": action.memo, "evidence_hash": hex::encode(&action.evidence_hash), "lock_until": now_u64 + 2592000, "queued_at": now_u64, "auto_generated": true, "affected": affected.len(), "escalated": escalated, "errors": errors});
                self.db.save_pending_drawrequest(&format!("dr:{}:{}", action.group_id, now_u64), &serde_json::to_vec(&dr).map_err(|_| ChronxError::SerializationError)?)?;
                info!(group_id = %action.group_id, affected = affected.len(), escalated = escalated, errors = errors, "[ATTESTOR FAILURE CASCADE] complete");
                Ok(())
            }

            Action::BondSlashCascade(ref action) => {
                let record = serde_json::json!({
                    "tier1_bond_id": action.tier1_bond_id,
                    "slash_amount_chronos": action.slash_amount_chronos,
                    "kxgc_assumption": action.kxgc_assumption,
                    "memo": action.memo,
                    "slashed_at": now as u64
                });
                let data = serde_json::to_vec(&record)
                    .map_err(|_| ChronxError::SerializationError)?;
                self.db.save_bond_slash(&action.tier1_bond_id, &data)?;
                info!(bond_id = %action.tier1_bond_id,
                      slash_chronos = action.slash_amount_chronos,
                      "[BOND SLASH CASCADE] recorded");
                Ok(())
            }

            Action::PartialExit { .. } => {
                Err(ChronxError::FeatureNotActive(
                    "Partial loan exit requires governance activation.".into()
                ))
            }

            // ── Savings account ──────────────────────────────────────────
            Action::CreateSavingsDeposit { amount_chronos } => {
                self.handle_savings_deposit(sender, *amount_chronos, now)
            }

            Action::WithdrawSavings { amount_chronos } => {
                self.handle_savings_withdrawal(sender, *amount_chronos, now)
            }

            // ── TYPE_Y: Explicit deposit default declaration ─────────
            Action::DepositDefault { ref deposit_id } => {
                let deposit = self.db.get_deposit(deposit_id)?
                    .ok_or_else(|| ChronxError::DepositNotFound(hex::encode(deposit_id)))?;
                if !matches!(deposit.status, DepositStatus::Active | DepositStatus::Matured) {
                    return Err(ChronxError::Other("Deposit is not active or matured".into()));
                }
                // Verify sender is depositor or obligor
                let sender_id = sender.account_id.to_b58();
                let depositor_id = chronx_crypto::hash::account_id_from_pubkey(&deposit.depositor_pubkey).to_b58();
                let obligor_id = chronx_crypto::hash::account_id_from_pubkey(&deposit.obligor_pubkey).to_b58();
                let is_depositor = sender_id == depositor_id;
                let is_obligor = sender_id == obligor_id;
                if !is_depositor && !is_obligor {
                    return Err(ChronxError::Other("Only depositor or obligor can declare default".into()));
                }
                // Must be past maturity + grace period
                let grace = DEPOSIT_DEFAULT_GRACE_SECONDS;
                let now_u64 = now as u64;
                if now_u64 < deposit.maturity_timestamp + grace {
                    return Err(ChronxError::Other(format!(
                        "Cannot declare default until {} seconds after maturity",
                        deposit.maturity_timestamp + grace - now_u64
                    )));
                }
                self.db.update_deposit_status(deposit_id, DepositStatus::Defaulted, None)?;
                info!(deposit_id = %hex::encode(deposit_id), "[DEPOSIT DEFAULT] Declared by party");
                Ok(())
            }

            // ── FriendlyLoanCreate ─────────────────────────────────────────
            Action::FriendlyLoanCreate {
                ref borrower_email_hash,
                ref borrower_wallet,
                principal_usd,
                term_days,
                kx_collateral_chronos,
                locked_kx_usd_rate,
                ref repayment_base_address,
                ref memo,
                ref loan_currency,
                ref claim_token,
            } => {
                let now_u64 = now as u64;
                // Governance checks
                let max_usd: f64 = self.db.get_meta("friendly_loan_max_usd")
                    .ok().flatten()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(250.0);
                let max_days: u32 = self.db.get_meta("friendly_loan_max_days")
                    .ok().flatten()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30);
                let min_days: u32 = self.db.get_meta("friendly_loan_min_days")
                    .ok().flatten()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                let fee_pct: f64 = self.db.get_meta("friendly_loan_fee_pct")
                    .ok().flatten()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1.0);
                let min_fee: f64 = self.db.get_meta("friendly_loan_min_fee_usd")
                    .ok().flatten()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.01);
                let grace_days: u32 = self.db.get_meta("friendly_loan_grace_days")
                    .ok().flatten()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3);

                if *principal_usd > max_usd {
                    return Err(ChronxError::Other(format!("friendly loan principal ${} exceeds max ${}", principal_usd, max_usd)));
                }
                if *term_days < min_days || *term_days > max_days {
                    return Err(ChronxError::Other(format!("friendly loan term {} days outside {}-{} range", term_days, min_days, max_days)));
                }

                let settlement_addr = self.db.get_meta("hedgekx_settlement_base_address")
                    .ok().flatten()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                    .unwrap_or_default();
                if settlement_addr.is_empty() {
                    return Err(ChronxError::Other("HedgeKX settlement address not configured".into()));
                }

                let collateral = *kx_collateral_chronos as u128;
                if sender.balance < collateral {
                    return Err(ChronxError::InsufficientBalance { need: collateral, have: sender.balance });
                }
                sender.balance -= collateral;

                let fee_usd = f64::max(principal_usd * (fee_pct / 100.0) * (*term_days as f64 / 30.0), min_fee);
                let total_repayment_usd = principal_usd + fee_usd;

                // Acceptance timeout (default 3 days)
                let timeout_days: u64 = self.db.get_meta("friendly_loan_address_timeout_days")
                    .ok().flatten()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3);
                let base_address_expires_at = now_u64 + timeout_days * 86400;

                // Derive loan_id from tx_id + action_idx like TimeLockCreate
                let loan_id = if action_idx == 0 {
                    tx_id.0
                } else {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&tx_id.0);
                    hasher.update(&(action_idx as u32).to_le_bytes());
                    let h = hasher.finalize();
                    *h.as_bytes()
                };

                // Generate claim_token: BLAKE3(tx_id || "claim" || loan_id)
                let generated_token = if let Some(ref ct) = claim_token {
                    if ct.is_empty() { hex::encode(&loan_id[..16]) } else { ct.clone() }
                } else {
                    let mut h = blake3::Hasher::new();
                    h.update(&tx_id.0);
                    h.update(b"claim");
                    h.update(&loan_id);
                    hex::encode(&h.finalize().as_bytes()[..16])
                };

                let currency_str = match loan_currency {
                    Some(chronx_core::transaction::LoanCurrency::Kx) => "Kx",
                    _ => "Usdc",
                };

                // Due date is set when borrower accepts (0 = pending)
                let record = FriendlyLoanRecord {
                    loan_id,
                    lender: sender.account_id.to_b58(),
                    borrower_email_hash: hex::encode(borrower_email_hash),
                    borrower_wallet: borrower_wallet.as_ref().map(|w| w.to_b58()),
                    principal_usd: *principal_usd,
                    fee_usd,
                    total_repayment_usd,
                    term_days: *term_days,
                    grace_days,
                    kx_collateral_chronos: *kx_collateral_chronos,
                    locked_kx_usd_rate: *locked_kx_usd_rate,
                    repayment_base_address: repayment_base_address.clone(),
                    created_at: now_u64,
                    due_at: 0,           // Set when borrower accepts
                    write_off_at: 0,     // Set when borrower accepts
                    status: "PendingAcceptance".to_string(),
                    repayment_usdc: None,
                    base_tx_hash: None,
                    write_off_tx_id: None,
                    memo: memo.clone(),
                    loan_currency: currency_str.to_string(),
                    claim_token: generated_token.clone(),
                    friend_address: None,
                    base_address_expires_at,
                    base_address_provided_at: None,
                };
                self.db.put_friendly_loan(&record)?;
                info!(loan_id = %hex::encode(loan_id), principal_usd, term_days, fee_usd,
                      currency = currency_str, "Friendly loan created — PendingAcceptance");
                Ok(())
            }

            // ── FriendlyLoanRepay ──────────────────────────────────────────
            Action::FriendlyLoanRepay {
                ref loan_id,
                repayment_usdc,
                ref base_tx_hash,
            } => {
                let mut record = self.db.get_friendly_loan(loan_id)?
                    .ok_or_else(|| ChronxError::Other(format!("friendly loan not found: {}", hex::encode(loan_id))))?;
                if record.status != "Active" {
                    return Err(ChronxError::Other(format!("friendly loan {} is not Active", hex::encode(loan_id))));
                }
                if *repayment_usdc < record.total_repayment_usd {
                    return Err(ChronxError::Other(format!("repayment ${} < required ${}", repayment_usdc, record.total_repayment_usd)));
                }
                // Release collateral back to lender
                let lender_account_id = chronx_core::types::AccountId::from_b58(&record.lender)
                    .map_err(|_| ChronxError::Other("invalid lender address".into()))?;
                let mut lender = self.db.get_account(&lender_account_id)?
                    .ok_or_else(|| ChronxError::UnknownAccount(record.lender.clone()))?;
                lender.balance += record.kx_collateral_chronos as u128;
                staged.accounts.push(lender);

                record.status = "Repaid".to_string();
                record.repayment_usdc = Some(*repayment_usdc);
                record.base_tx_hash = Some(base_tx_hash.clone());
                self.db.put_friendly_loan(&record)?;
                info!(loan_id = %hex::encode(loan_id), "Friendly loan repaid");
                Ok(())
            }

            // ── TimeLockExtend (Genesis Zero) ─────────────────────────────
            Action::TimeLockExtend {
                ref lock_id,
                extension_seconds,
                ref trigger,
                ref signature,
                ref memo,
            } => {
                use chronx_core::transaction::{ExtensionTrigger, LockExtensionOfferRecord, LockExtensionRequestRecord};
                let _ = signature; // Validated at transaction level
                let now_u64 = now as u64;
                let lock_txid = chronx_core::types::TxId(*lock_id);
                let mut contract = self.db.get_timelock(&lock_txid)?
                    .ok_or_else(|| ChronxError::Other(format!("Lock not found: {}", hex::encode(lock_id))))?;

                // Verify lock is still Pending (active)
                if !matches!(contract.status, TimeLockStatus::Pending) {
                    return Err(ChronxError::Other("Lock is not active (Pending)".into()));
                }

                // Governance: max extension duration
                let max_ext_years: u64 = self.db.get_meta("max_lock_extension_years")
                    .ok().flatten()
                    .and_then(|v| String::from_utf8(v).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(100);
                let max_ext_secs = max_ext_years * 365 * 86400;
                if *extension_seconds > max_ext_secs {
                    return Err(ChronxError::Other(format!(
                        "Extension {} secs exceeds max {} years", extension_seconds, max_ext_years
                    )));
                }

                // Governance: max number of extensions
                let max_extensions_gov: u32 = self.db.get_meta("max_lock_extensions")
                    .ok().flatten()
                    .and_then(|v| String::from_utf8(v).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                let lock_max = contract.max_extensions.unwrap_or(max_extensions_gov);
                let used = contract.extensions_used.unwrap_or(0);
                if used >= lock_max {
                    return Err(ChronxError::Other(format!(
                        "Lock has used {}/{} extensions", used, lock_max
                    )));
                }

                match trigger {
                    ExtensionTrigger::LenderOffer { ref offered_by, acceptance_window_secs, .. } => {
                        // Verify offered_by = lock grantor (sender)
                        if *offered_by != contract.sender {
                            return Err(ChronxError::Other("LenderOffer: offered_by must be lock grantor".into()));
                        }
                        // Record offer with expiry — borrower must accept in a subsequent tx
                        let offer_window = self.db.get_meta("lock_extension_offer_window_days")
                            .ok().flatten()
                            .and_then(|v| String::from_utf8(v).ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(30);
                        let window_secs = if *acceptance_window_secs > 0 {
                            (*acceptance_window_secs).min(offer_window * 86400)
                        } else {
                            offer_window * 86400
                        };
                        let record = LockExtensionOfferRecord {
                            lock_id: *lock_id,
                            extension_seconds: *extension_seconds,
                            offered_by: offered_by.to_b58(),
                            offered_at: now_u64,
                            expires_at: now_u64 + window_secs,
                            status: "pending".to_string(),
                            tx_id: hex::encode(tx_id.0),
                        };
                        self.db.put_lock_extension_offer(&record)?;
                        info!(lock = %hex::encode(lock_id), ext_secs = *extension_seconds,
                              "TimeLockExtend: LenderOffer recorded, awaiting borrower acceptance");
                        Ok(())
                    }

                    ExtensionTrigger::BorrowerRequest { ref requested_by, pre_authorized } => {
                        // Verify signature = lock beneficiary (recipient)
                        let recipient_id = contract.recipient_account_id.clone();
                        if *requested_by != recipient_id {
                            return Err(ChronxError::Other("BorrowerRequest: requested_by must be lock recipient".into()));
                        }

                        if *pre_authorized {
                            // Check extension_right was set at creation
                            if contract.extension_right != Some(true) {
                                return Err(ChronxError::Other(
                                    "BorrowerRequest pre_authorized=true but lock has no extension_right".into()
                                ));
                            }
                            // Execute immediately — no lender approval required
                            contract.unlock_at += *extension_seconds as i64;
                            contract.extensions_used = Some(used + 1);
                            self.db.put_timelock(&contract)?;
                            if let Some(m) = memo {
                                info!(lock = %hex::encode(lock_id), ext_secs = *extension_seconds,
                                      memo = %m, "TimeLockExtend: BorrowerRequest pre-authorized, executed immediately");
                            } else {
                                info!(lock = %hex::encode(lock_id), ext_secs = *extension_seconds,
                                      "TimeLockExtend: BorrowerRequest pre-authorized, executed immediately");
                            }
                        } else {
                            // Record pending request — lender must co-sign in subsequent tx
                            let record = LockExtensionRequestRecord {
                                lock_id: *lock_id,
                                extension_seconds: *extension_seconds,
                                requested_by: requested_by.to_b58(),
                                requested_at: now_u64,
                                status: "pending".to_string(),
                                tx_id: hex::encode(tx_id.0),
                            };
                            self.db.put_lock_extension_request(&record)?;
                            info!(lock = %hex::encode(lock_id), ext_secs = *extension_seconds,
                                  "TimeLockExtend: BorrowerRequest pending lender co-signature");
                        }
                        Ok(())
                    }

                    ExtensionTrigger::OracleCondition { ref oracle_id, ref condition } => {
                        // Oracle-conditioned extensions are processed by the sweep engine.
                        // This action records the oracle condition on the DAG for audit.
                        let oracle_enabled: bool = self.db.get_meta("lock_extension_oracle_enabled")
                            .ok().flatten()
                            .and_then(|v| String::from_utf8(v).ok())
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(true);
                        if !oracle_enabled {
                            return Err(ChronxError::FeatureNotActive(
                                "Oracle-conditioned lock extensions are not enabled".into()
                            ));
                        }
                        // Execute extension based on oracle attestation
                        contract.unlock_at += *extension_seconds as i64;
                        contract.extensions_used = Some(used + 1);
                        self.db.put_timelock(&contract)?;
                        info!(lock = %hex::encode(lock_id), ext_secs = *extension_seconds,
                              oracle = %oracle_id, condition = %condition,
                              "Lock {} extended by oracle condition: {}", hex::encode(lock_id), condition);
                        Ok(())
                    }
                }
            }

            // ── LoanChargeOff (Genesis Zero) ─────────────────────────────────
            //
            // IMPORTANT: ChargeOff does NOT cancel the legal obligation. The DAG
            // record of the original loan, draw, and charge-off remains permanent
            // and immutable. It is an accounting declaration only — not debt
            // forgiveness. The immutable DAG record provides auditor-quality
            // documentation for bad debt deduction purposes.
            Action::LoanChargeOff {
                ref loan_id,
                charged_off_amount_usd,
                charged_off_amount_kx,
                ref reason,
                ref supporting_evidence,
                ref lender_signature,
                charged_off_at,
                ref memo,
            } => {
                use chronx_core::transaction::ChargeOffRecord;
                let _ = lender_signature; // Validated at transaction level

                let chargeoff_enabled: bool = self.db.get_meta("loan_chargeoff_enabled")
                    .ok().flatten()
                    .and_then(|v| String::from_utf8(v).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(true);
                if !chargeoff_enabled {
                    return Err(ChronxError::FeatureNotActive("Loan charge-off is not enabled".into()));
                }

                // Try loan tree first, then friendly_loans tree
                let (lender_wallet_b58, loan_status, loan_created_at) = if let Some(raw) = self.db.get_loan(loan_id)? {
                    let val: serde_json::Value = serde_json::from_slice(&raw)
                        .map_err(|e| ChronxError::Other(format!("Failed to parse loan: {}", e)))?;
                    let lw = val.get("lender_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let st = val.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let ca = val.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
                    (lw, st, ca)
                } else if let Some(fl) = self.db.get_friendly_loan(loan_id)? {
                    (fl.lender.clone(), fl.status.clone(), fl.created_at)
                } else if let Some(cf) = self.db.get_credit_facility(loan_id)? {
                    (cf.lender_wallet.clone(), cf.status.clone(), cf.created_at)
                } else {
                    return Err(ChronxError::Other(format!("Loan not found: {}", hex::encode(loan_id))));
                };

                // Verify sender is the lender
                let sender_b58 = sender.account_id.to_b58();
                if sender_b58 != lender_wallet_b58 {
                    return Err(ChronxError::Other("Only the original lender may charge off a loan".into()));
                }

                // Verify loan is Active or Overdue (defaulted), not already charged off
                let status_lower = loan_status.to_lowercase();
                if status_lower != "active" && status_lower != "overdue"
                    && status_lower != "defaulted" && status_lower != "accepted" {
                    return Err(ChronxError::Other(format!(
                        "Loan status '{}' is not eligible for charge-off (must be Active/Overdue/Defaulted)", loan_status
                    )));
                }

                // Governance: minimum age before charge-off
                let min_age_days: u64 = self.db.get_meta("loan_chargeoff_min_age_days")
                    .ok().flatten()
                    .and_then(|v| String::from_utf8(v).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(365);
                let min_age_secs = min_age_days * 86400;
                if *charged_off_at < loan_created_at + min_age_secs {
                    return Err(ChronxError::Other(format!(
                        "Charge-off too early: must wait {} days from loan creation", min_age_days
                    )));
                }

                // Record the charge-off permanently on the DAG
                let record = ChargeOffRecord {
                    loan_id: *loan_id,
                    charged_off_amount_usd: *charged_off_amount_usd,
                    charged_off_amount_kx: *charged_off_amount_kx,
                    reason: reason.clone(),
                    supporting_evidence: supporting_evidence.clone(),
                    lender_wallet: sender_b58.clone(),
                    charged_off_at: *charged_off_at,
                    memo: memo.clone(),
                    tx_id: hex::encode(tx_id.0),
                };
                self.db.put_charge_off(&record)?;

                // Update loan status to ChargedOff in the loan tree
                if let Some(raw) = self.db.get_loan(loan_id)? {
                    if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(&raw) {
                        val["status"] = serde_json::Value::String("ChargedOff".to_string());
                        val["charged_off_at"] = serde_json::json!(charged_off_at);
                        val["charge_off_reason"] = serde_json::json!(reason.to_string());
                        let updated = serde_json::to_vec(&val).map_err(|e| ChronxError::Other(e.to_string()))?;
                        self.db.save_loan(loan_id, &updated)?;
                    }
                } else if let Some(mut fl) = self.db.get_friendly_loan(loan_id)? {
                    fl.status = "ChargedOff".to_string();
                    self.db.put_friendly_loan(&fl)?;
                } else if let Some(mut cf) = self.db.get_credit_facility(loan_id)? {
                    cf.status = "ChargedOff".to_string();
                    self.db.put_credit_facility(&cf)?;
                }

                info!(
                    loan_id = %hex::encode(loan_id),
                    reason = %reason,
                    usd = charged_off_amount_usd,
                    kx = charged_off_amount_kx,
                    "Loan {} charged off by lender. Reason: {}. Amount: {} USD / {} KX.",
                    hex::encode(loan_id), reason, charged_off_amount_usd, charged_off_amount_kx
                );
                Ok(())
            }

            // ── FriendlyLoanAccept ────────────────────────────────────────
            Action::FriendlyLoanAccept {
                ref loan_id,
                ref claim_token,
                ref disbursement_election,
            } => {
                use chronx_core::transaction::DisbursementElection;
                let now_u64 = now as u64;
                let mut record = self.db.get_friendly_loan(loan_id)?
                    .ok_or_else(|| ChronxError::Other(format!("friendly loan not found: {}", hex::encode(loan_id))))?;
                if record.status != "PendingAcceptance" {
                    return Err(ChronxError::Other(format!("friendly loan {} is not PendingAcceptance (is {})", hex::encode(loan_id), record.status)));
                }
                if now_u64 > record.base_address_expires_at {
                    return Err(ChronxError::Other("Loan offer has expired".into()));
                }
                if *claim_token != record.claim_token {
                    return Err(ChronxError::Other("Invalid claim token".into()));
                }

                let address = match disbursement_election {
                    DisbursementElection::Usdc { ref base_address } => {
                        if !base_address.starts_with("0x") || base_address.len() != 42 {
                            return Err(ChronxError::Other("Invalid Base address format (must be 0x + 40 hex chars)".into()));
                        }
                        base_address.clone()
                    }
                    DisbursementElection::Kx { ref chronx_address } => {
                        chronx_address.clone()
                    }
                };

                // Set loan to Active, start the clock
                let grace_days = record.grace_days as u64;
                record.friend_address = Some(address);
                record.base_address_provided_at = Some(now_u64);
                record.status = "Active".to_string();
                record.due_at = now_u64 + (record.term_days as u64) * 86400;
                record.write_off_at = record.due_at + grace_days * 86400;
                self.db.put_friendly_loan(&record)?;

                info!(loan_id = %hex::encode(loan_id), "Friendly loan accepted — status Active, clock started");
                Ok(())
            }

            // ── FriendlyLoanCancel ───────────────────────────────────────────
            Action::FriendlyLoanCancel {
                ref loan_id,
                ref reason,
            } => {
                let now_u64 = now as u64;
                let _ = now_u64;
                let mut record = self.db.get_friendly_loan(loan_id)?
                    .ok_or_else(|| ChronxError::Other(format!("friendly loan not found: {}", hex::encode(loan_id))))?;
                if record.status != "PendingAcceptance" {
                    return Err(ChronxError::Other(format!(
                        "Cannot cancel — loan {} is {} (can only cancel PendingAcceptance)", hex::encode(loan_id), record.status
                    )));
                }
                // Verify sender is the lender
                let sender_b58 = sender.account_id.to_b58();
                if sender_b58 != record.lender {
                    return Err(ChronxError::Other("Only the lender can cancel a friend loan".into()));
                }
                // Return KX collateral to lender
                sender.balance += record.kx_collateral_chronos as u128;
                record.status = "Cancelled".to_string();
                if let Some(ref r) = reason {
                    record.memo = Some(format!("Cancelled: {}", r));
                }
                self.db.put_friendly_loan(&record)?;
                info!(loan_id = %hex::encode(loan_id), "Friendly loan cancelled by lender — KX returned");
                Ok(())
            }

            // ── FriendlyLoanWriteOff ───────────────────────────────────────
            Action::FriendlyLoanWriteOff { ref loan_id } => {
                let now_u64 = now as u64;
                let mut record = self.db.get_friendly_loan(loan_id)?
                    .ok_or_else(|| ChronxError::Other(format!("friendly loan not found: {}", hex::encode(loan_id))))?;
                if record.status != "Active" {
                    return Err(ChronxError::Other(format!("friendly loan {} is not Active", hex::encode(loan_id))));
                }
                if now_u64 < record.write_off_at {
                    return Err(ChronxError::Other(format!("friendly loan {} grace period not expired", hex::encode(loan_id))));
                }
                // Collateral is lost — lender accepted credit risk
                // KX stays in protocol (already deducted at creation)
                record.status = "WrittenOff".to_string();
                record.write_off_tx_id = Some(hex::encode(tx_id.0));
                self.db.put_friendly_loan(&record)?;
                info!(loan_id = %hex::encode(loan_id), "Friendly loan written off — grace period expired");
                Ok(())
            }

            // ── CreditFacilityCreate (KXGC institutional) ───────────────────
            Action::CreditFacilityCreate {
                ref facility_id,
                ref borrower_wallet,
                ref borrower_entity_name,
                ref cpnx_badge_id,
                facility_limit_usd,
                commitment_fee_bps,
                drawn_interest_rate_bps,
                ref draw_condition,
                ref facility_currency,
                kx_collateral_chronos,
                ref extension_right,
                ref max_extensions,
                ref memo,
            } => {
                use chronx_core::transaction::CreditFacilityRecord;
                let now_u64 = now as u64;

                // Governance checks
                let max_usd: f64 = self.db.get_meta("kxgc_max_facility_usd")
                    .ok().flatten()
                    .and_then(|v| String::from_utf8(v).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(999_999_999.0);
                let kyc_threshold: f64 = self.db.get_meta("kxgc_kyc_required_above_usd")
                    .ok().flatten()
                    .and_then(|v| String::from_utf8(v).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10_000.0);
                let min_interest_bps: u32 = self.db.get_meta("kxgc_min_drawn_interest_bps")
                    .ok().flatten()
                    .and_then(|v| String::from_utf8(v).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(400);

                if *facility_limit_usd > max_usd {
                    return Err(ChronxError::Other(format!("Facility limit ${} exceeds governance max ${}", facility_limit_usd, max_usd)));
                }
                if *facility_limit_usd > kyc_threshold && cpnx_badge_id.is_none() {
                    return Err(ChronxError::Other(format!("CPNX KYC badge required for facilities above ${}", kyc_threshold)));
                }
                if *drawn_interest_rate_bps < min_interest_bps {
                    return Err(ChronxError::Other(format!(
                        "Drawn interest rate {} bps below AFR floor {} bps", drawn_interest_rate_bps, min_interest_bps
                    )));
                }

                // Deduct KX collateral from lender
                let collateral = *kx_collateral_chronos;
                if sender.balance < collateral {
                    return Err(ChronxError::InsufficientBalance { need: collateral, have: sender.balance });
                }
                sender.balance -= collateral;

                let currency_str = match facility_currency {
                    chronx_core::transaction::LoanCurrency::Kx => "Kx",
                    chronx_core::transaction::LoanCurrency::Usdc => "Usdc",
                };

                let record = CreditFacilityRecord {
                    facility_id: *facility_id,
                    lender_wallet: sender.account_id.to_b58(),
                    borrower_wallet: borrower_wallet.to_b58(),
                    borrower_entity_name: borrower_entity_name.clone(),
                    cpnx_badge_id: cpnx_badge_id.clone(),
                    facility_limit_usd: *facility_limit_usd,
                    commitment_fee_bps: *commitment_fee_bps,
                    drawn_interest_rate_bps: *drawn_interest_rate_bps,
                    draw_condition: draw_condition.clone(),
                    facility_currency: currency_str.to_string(),
                    kx_collateral_chronos: *kx_collateral_chronos,
                    extension_right: *extension_right,
                    max_extensions: *max_extensions,
                    extensions_used: 0,
                    created_at: now_u64,
                    facility_type: "StandbyRevolving".to_string(),
                    repayment_right: "BorrowerOnly".to_string(),
                    maturity_date: None,
                    discharge_on_dissolution: true,
                    total_drawn_usd: 0.0,
                    total_repaid_usd: 0.0,
                    outstanding_usd: 0.0,
                    status: "Active".to_string(),
                    termination_notice_at: None,
                    termination_notice_by: None,
                    termination_reason: None,
                    terminated_at: None,
                    notice_days: None,
                    partial_refund_eligible: false,
                    memo: memo.clone(),
                    tx_id: hex::encode(tx_id.0),
                };
                self.db.put_credit_facility(&record)?;
                info!(facility_id = %hex::encode(facility_id), limit_usd = facility_limit_usd,
                      interest_bps = drawn_interest_rate_bps, entity = %borrower_entity_name,
                      "CreditFacility created — StandbyRevolving, no fixed maturity");
                Ok(())
            }

            // ── CreditFacilityDraw ──────────────────────────────────────────
            Action::CreditFacilityDraw {
                ref facility_id,
                draw_amount_usd,
                ref proof_hash,
                ref memo,
            } => {
                let now_u64 = now as u64;
                let _ = (proof_hash, memo, now_u64);
                let mut record = self.db.get_credit_facility(facility_id)?
                    .ok_or_else(|| ChronxError::Other(format!("Credit facility not found: {}", hex::encode(facility_id))))?;
                if record.status != "Active" {
                    return Err(ChronxError::Other(format!("Facility {} is {} — cannot draw", hex::encode(facility_id), record.status)));
                }
                let new_outstanding = record.outstanding_usd + *draw_amount_usd;
                if new_outstanding > record.facility_limit_usd {
                    return Err(ChronxError::Other(format!(
                        "Draw ${} would exceed facility limit ${} (outstanding: ${})",
                        draw_amount_usd, record.facility_limit_usd, record.outstanding_usd
                    )));
                }
                record.total_drawn_usd += *draw_amount_usd;
                record.outstanding_usd = new_outstanding;
                self.db.put_credit_facility(&record)?;
                info!(facility_id = %hex::encode(facility_id), draw = draw_amount_usd,
                      outstanding = record.outstanding_usd, "CreditFacility draw");
                Ok(())
            }

            // ── CreditFacilityRepay ─────────────────────────────────────────
            Action::CreditFacilityRepay {
                ref facility_id,
                repayment_amount_usd,
                ref base_tx_hash,
                ref memo,
            } => {
                let _ = (base_tx_hash, memo);
                let mut record = self.db.get_credit_facility(facility_id)?
                    .ok_or_else(|| ChronxError::Other(format!("Credit facility not found: {}", hex::encode(facility_id))))?;
                if record.status != "Active" && record.status != "TerminationNotice" {
                    return Err(ChronxError::Other(format!("Facility {} is {} — cannot repay", hex::encode(facility_id), record.status)));
                }
                record.total_repaid_usd += *repayment_amount_usd;
                record.outstanding_usd = (record.outstanding_usd - *repayment_amount_usd).max(0.0);
                self.db.put_credit_facility(&record)?;
                info!(facility_id = %hex::encode(facility_id), repayment = repayment_amount_usd,
                      outstanding = record.outstanding_usd, "CreditFacility repayment");
                Ok(())
            }

            // ── CreditFacilityTerminate ──────────────────────────────────────
            Action::CreditFacilityTerminate {
                ref facility_id,
                ref initiated_by,
                ref reason,
                abort,
                partial_refund_eligible,
                ref notice_days,
                ref memo,
            } => {
                let now_u64 = now as u64;
                let _ = memo;
                let mut record = self.db.get_credit_facility(facility_id)?
                    .ok_or_else(|| ChronxError::Other(format!("Credit facility not found: {}", hex::encode(facility_id))))?;

                if *abort {
                    // Abort a pending termination — both parties must have agreed
                    if record.status != "TerminationNotice" {
                        return Err(ChronxError::Other("No pending termination to abort".into()));
                    }
                    record.status = "Active".to_string();
                    record.termination_notice_at = None;
                    record.termination_notice_by = None;
                    record.termination_reason = None;
                    record.notice_days = None;
                    record.partial_refund_eligible = false;
                    self.db.put_credit_facility(&record)?;
                    info!(facility_id = %hex::encode(facility_id), "CreditFacility termination aborted — facility reactivated");
                } else {
                    // Initiate termination notice
                    if record.status != "Active" {
                        return Err(ChronxError::Other(format!("Facility {} is {} — cannot terminate", hex::encode(facility_id), record.status)));
                    }
                    let days = notice_days.unwrap_or(30).max(7); // min 7 days, default 30
                    record.status = "TerminationNotice".to_string();
                    record.termination_notice_at = Some(now_u64);
                    record.termination_notice_by = Some(initiated_by.clone());
                    record.termination_reason = Some(reason.to_string());
                    record.notice_days = Some(days);
                    record.partial_refund_eligible = *partial_refund_eligible;
                    self.db.put_credit_facility(&record)?;
                    info!(facility_id = %hex::encode(facility_id), by = %initiated_by,
                          reason = %reason, notice_days = days,
                          "CreditFacility termination notice — {} day notice period", days);
                }
                Ok(())
            }

            // ── Child Chain Infrastructure ──────────────────────────────────
            Action::ChildChainRecord {
                ref namespace,
                ref record_id,
                ref payload,
                ref payload_hash,
                owner_signature: _,
                ref previous_record_id,
            } => {
                // 1. Check child_chains_enabled
                let enabled: bool = self.db.get_meta("child_chains_enabled")
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(false);
                if !enabled {
                    return Err(ChronxError::Other("Child chains not enabled".into()));
                }

                // 2. Look up namespace in child_chain_approved_namespaces
                let ns_list: Vec<serde_json::Value> = self.db.get_meta("child_chain_approved_namespaces")
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_default();
                let ns_entry = ns_list.iter().find(|e| {
                    e.get("namespace").and_then(|v| v.as_str()) == Some(namespace)
                });
                let ns_entry = match ns_entry {
                    Some(e) => e.clone(),
                    None => return Err(ChronxError::Other("Namespace not registered".into())),
                };

                // 3. Check namespace status == "active"
                let status = ns_entry.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if status != "active" {
                    return Err(ChronxError::Other("Namespace not active".into()));
                }

                // 4. Verify sender is namespace owner (owner_pubkey match)
                let owner_pubkey_hex = ns_entry.get("owner_pubkey").and_then(|v| v.as_str()).unwrap_or("");
                let sender_pubkey_hex = if let chronx_core::account::AuthPolicy::SingleSig { ref public_key } = sender.auth_policy {
                    hex::encode(&public_key.0)
                } else {
                    String::new()
                };
                if sender_pubkey_hex != owner_pubkey_hex {
                    return Err(ChronxError::Other("Signature does not match namespace owner key".into()));
                }

                // 5. Verify payload_hash matches BLAKE3(payload.as_bytes())
                let computed_hash = blake3::hash(payload.as_bytes());
                if computed_hash.as_bytes() != payload_hash {
                    return Err(ChronxError::Other("Payload hash mismatch".into()));
                }

                // 6. Check payload size
                let max_size: usize = self.db.get_meta("child_chain_max_record_size_bytes")
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(4096);
                if payload.len() > max_size {
                    return Err(ChronxError::Other("Payload exceeds maximum size".into()));
                }

                // 7. Per-block rate limit (use rate-limit key per block window)
                let block_window = now / 10; // 10-second block windows
                let block_key = format!("rl:child_block:{}", block_window);
                let block_count: u64 = self.db.get_meta(&block_key)
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(0);
                let max_per_block: u64 = self.db.get_meta("child_chain_max_records_per_block")
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(1000);
                if block_count >= max_per_block {
                    return Err(ChronxError::Other("Rate limit exceeded".into()));
                }
                let _ = self.db.put_meta(&block_key, &serde_json::to_vec(&(block_count + 1)).unwrap_or_default());

                // 8. Namespace daily limit
                let day_start = (now as u64) / 86400 * 86400;
                let daily_count = self.db.get_child_records_count_since(namespace, day_start)?;
                let max_per_day = ns_entry.get("max_records_per_day").and_then(|v| v.as_u64()).unwrap_or(100000);
                if daily_count >= max_per_day {
                    return Err(ChronxError::Other("Namespace daily limit exceeded".into()));
                }

                // 9-10. Store the record and index
                let now_u64 = now as u64;
                let entry = crate::db::ChildChainRecordEntry {
                    namespace: namespace.clone(),
                    record_id: record_id.clone(),
                    payload: payload.clone(),
                    payload_hash: *payload_hash,
                    stored_at: now_u64,
                    dag_vertex_id: tx_id.to_hex(),
                    previous_record_id: previous_record_id.clone(),
                };
                self.db.put_child_record(&entry)?;

                info!(namespace = %namespace, record_id = %record_id, "ChildChainRecord stored");
                Ok(())
            }

            Action::ChildChainRegister {
                ref namespace,
                ref display_name,
                ref description,
                ref owner_pubkey,
                ref bond_lock_id,
                applicant_signature: _,
            } => {
                // 1. Check child_chains_enabled
                let enabled: bool = self.db.get_meta("child_chains_enabled")
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(false);
                if !enabled {
                    return Err(ChronxError::Other("Child chains not enabled".into()));
                }

                // 2. Verify namespace is available and matches format
                if namespace.is_empty() || namespace.len() > 32
                    || !namespace.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    || namespace.starts_with('-')
                {
                    return Err(ChronxError::Other("Invalid namespace format: lowercase alphanumeric + hyphens, max 32 chars".into()));
                }

                let ns_list: Vec<serde_json::Value> = self.db.get_meta("child_chain_approved_namespaces")
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_default();
                if ns_list.iter().any(|e| e.get("namespace").and_then(|v| v.as_str()) == Some(namespace)) {
                    return Err(ChronxError::Other("Namespace already registered".into()));
                }

                let pending: Vec<serde_json::Value> = self.db.get_meta("child_chain_pending_applications")
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_default();
                if pending.iter().any(|e| e.get("namespace").and_then(|v| v.as_str()) == Some(namespace)) {
                    return Err(ChronxError::Other("Namespace already has a pending application".into()));
                }

                // 3. Verify bond_lock_id exists and is valid
                let lock_id_txid = chronx_core::types::TxId::from_bytes(*bond_lock_id);
                let lock = self.db.get_timelock(&lock_id_txid)?
                    .ok_or_else(|| ChronxError::Other("Bond lock not found".into()))?;
                let bond_kx: u64 = self.db.get_meta("child_chain_bond_kx")
                    .ok().flatten()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(1_000_000);
                let bond_chronos = bond_kx * 1_000_000; // CHRONOS_PER_KX
                if lock.amount != bond_chronos as u128 {
                    return Err(ChronxError::Other("Bond amount does not match required child_chain_bond_kx".into()));
                }

                // 4. Verify applicant_signature — sender must sign
                // (Already validated by outer tx signature check.)

                // 5. Add to pending_applications
                let now_u64 = now as u64;
                let application = serde_json::json!({
                    "namespace": namespace,
                    "display_name": display_name,
                    "description": description,
                    "owner_pubkey": hex::encode(owner_pubkey),
                    "bond_lock_id": hex::encode(bond_lock_id),
                    "applied_at": now_u64,
                    "status": "pending"
                });
                let mut pending = pending;
                pending.push(application);
                let _ = self.db.put_meta(
                    "child_chain_pending_applications",
                    &serde_json::to_vec(&pending).unwrap_or_default(),
                );

                info!(namespace = %namespace, display_name = %display_name, "ChildChainRegister application submitted");
                Ok(())
            }
        }
    }
}


/// Calculate the total amount due at maturity for an interest-bearing deposit.
/// Uses integer arithmetic to avoid floating-point imprecision.
fn calculate_deposit_total_due(
    principal: u64,
    rate_basis_points: u64,
    term_seconds: u64,
    compounding: &Compounding,
) -> u64 {
    let p = principal as u128;
    let r_bp = rate_basis_points as u128;
    let term_days = (term_seconds as u128) / 86400;
    let term_years_x1000 = (term_days * 1000) / 365;

    match compounding {
        Compounding::Simple => {
            // total = P * (1 + r * t)
            // r is rate_basis_points / 10000, t is term in years
            let interest = (p * r_bp * term_years_x1000) / (10_000 * 1000);
            (p + interest) as u64
        }
        _ => {
            // For compound interest, use iterative approach
            // periods per year: Daily=365, Monthly=12, Annually=1
            let periods_per_year: u128 = match compounding {
                Compounding::Daily => 365,
                Compounding::Monthly => 12,
                Compounding::Annually => 1,
                _ => 1
            };
            let total_periods = (term_days * periods_per_year) / 365;
            if total_periods == 0 {
                return principal;
            }
            // rate per period in basis points
            let rate_per_period_bp = r_bp / periods_per_year;
            // Iterative compounding: amount = P * (1 + r/n)^(n*t)
            // Using fixed-point with 1e12 scale
            let scale: u128 = 1_000_000_000_000;
            let mut amount_scaled = p * scale;
            let factor = scale + (rate_per_period_bp * scale) / 10_000;
            for _ in 0..total_periods.min(3650) {
                amount_scaled = (amount_scaled * factor) / scale;
            }
            (amount_scaled / scale) as u64
        }
    }
}

// ── Background sweep for expired email locks ──────────────────────────────────

impl StateEngine {
    /// Scan all Pending email locks and revert any whose claim window has expired
    /// and whose `unclaimed_action` is `RevertToSender`.
    ///
    /// Called periodically by the node (every 5 minutes). This is NOT a
    /// transaction — it directly modifies the DB. Each revert credits the
    /// protocol: fire Day 91 triggers on unclaimed matured locks.
    /// Currently a no-op stub — no locks are old enough to trigger yet.
    pub fn sweep_genesis7_triggers(&self, _now: i64) -> Result<u32, ChronxError> {
        Ok(0)
    }

    /// protocol: sweep unclaimed locks past the 100-year expiry window and
    /// route them to the Humanity Stake Pool. Currently a no-op stub — no locks
    /// are old enough to trigger (earliest maturity is 2036).
    pub fn sweep_genesis7_expiry(&self, _now: i64, _pool_address: &str) -> Result<u32, ChronxError> {
        // No locks can be 100+ years past maturity yet. Stub for forward compatibility.
        Ok(0)
    }

    /// Auto-deliver matured wallet-to-wallet locks.
    ///
    /// Finds all Pending locks where:
    /// - NOT an email lock (no 0xC5 marker in lock_marker)
    /// - unlock_at <= now
    /// For each: credits recipient balance, sets status to Claimed.
    ///
    /// Returns the number of locks auto-delivered.
    pub fn sweep_matured_wallet_locks(&self, now: i64) -> Result<u32, ChronxError> {
        let all_locks = self.db.iter_all_timelocks()?;
        let mut delivered_count = 0u32;

        for lock in all_locks {
            if lock.status != TimeLockStatus::Pending {
                continue;
            }
            // Skip email locks (0xC5 marker).
            let is_email = lock
                .lock_marker
                .as_ref()
                .map(|d| d.len() == 33 && d[0] == 0xC5)
                .unwrap_or(false);
            if is_email {
                continue;
            }
            // Must be matured.
            if now < lock.unlock_at {
                continue;
            }

            // Check for PAY_AS delivery
            let convert_to = self.db.get_convert_to_suggestion(&lock.id)
                .ok().flatten().unwrap_or_default();
            let is_pay_as = !convert_to.is_empty()
                && (convert_to.eq_ignore_ascii_case("usdc") || convert_to.eq_ignore_ascii_case("usd"));

            if is_pay_as {
                // PAY_AS delivery: query oracle for KX/USDC rate
                // The pay_as_amount is stored alongside the lock.
                // For now, we check the convert_to_suggestion sled tree.
                // If oracle is unreachable, skip and retry next sweep.
                // TODO: integrate with XChan oracle endpoint at runtime
                // For Phase 1, PAY_AS locks deliver full amount (same as plain KX)
                // with a log noting the PAY_AS intent. Full oracle integration is Phase 2.
                info!(
                    lock_id = %lock.id,
                    convert_to = %convert_to,
                    amount_chronos = lock.amount,
                    "[PAY_AS] delivering lock with PAY_AS intent — full amount (oracle integration pending)"
                );
            }

            // Credit recipient balance
            let mut recipient = match self.db.get_account(&lock.recipient_account_id)? {
                Some(a) => a,
                None => continue,
            };

            let delivery_amount = lock.amount; // Full amount for now; PAY_AS oracle adjusts in Phase 2
            recipient.balance += delivery_amount;
            self.db.put_account(&recipient)?;

            let mut delivered_lock = lock.clone();
            delivered_lock.status = TimeLockStatus::Claimed { claimed_at: now };
            self.db.put_timelock(&delivered_lock)?;

            info!(
                amount_kx = delivery_amount / 1_000_000,
                lock_id = %lock.id,
                recipient = %lock.recipient_account_id,
                "Auto-delivered wallet-to-wallet lock"
            );

            delivered_count += 1;
        }

        if delivered_count > 0 {
            self.db.flush()?;
        }
        Ok(delivered_count)
    }

    /// sender's balance and sets the lock status to `Reverted`.
    ///
    /// Returns the number of locks reverted in this sweep.
    pub fn sweep_expired_email_locks(&self, now: i64) -> Result<u32, ChronxError> {
        let all_locks = self.db.iter_all_timelocks()?;
        let mut reverted_count = 0u32;

        for lock in all_locks {
            // Only process Pending locks.
            if lock.status != TimeLockStatus::Pending {
                continue;
            }
            // Must be an email lock (0xC5 marker).
            let is_email = lock
                .lock_marker
                .as_ref()
                .map(|d| d.len() == 33 && d[0] == 0xC5)
                .unwrap_or(false);
            if !is_email {
                continue;
            }
            // Must have a claim window.
            let window_secs = match lock.claim_window_secs {
                Some(w) => w,
                None => continue
            };
            // Check if the claim window has expired.
            if now <= lock.created_at + window_secs as i64 {
                continue;
            }
            // Must have RevertToSender action.
            match &lock.unclaimed_action {
                Some(chronx_core::account::UnclaimedAction::RevertToSender) => {}
                _ => continue
            }

            // Revert: credit sender, update lock status.
            let mut sender = match self.db.get_account(&lock.sender)? {
                Some(a) => a,
                None => continue, // orphaned lock — skip
            };
            sender.balance += lock.amount;
            self.db.put_account(&sender)?;

            let mut reverted_lock = lock;
            reverted_lock.status = TimeLockStatus::Reverted { reverted_at: now };
            self.db.put_timelock(&reverted_lock)?;

            reverted_count += 1;
        }

        if reverted_count > 0 {
            self.db.flush()?;
        }
        Ok(reverted_count)
    }

    /// Finalize any PendingExecutor withdrawals whose delay has elapsed.
    ///
    /// Called periodically by the node (every 60 seconds). For each pending
    /// withdrawal whose finalize_at <= now:
    /// 1. Transfer the lock's KX to the executor wallet
    /// 2. Set lock status to ExecutorWithdrawn
    /// 3. Mark the withdrawal record as "Finalized"
    ///
    /// Returns the number of withdrawals finalized.
    pub fn sweep_executor_withdrawals(&self, now: i64) -> Result<u32, ChronxError> {
        let pending = self.db.iter_pending_executor_withdrawals()?;
        let mut finalized_count = 0u32;

        for record in pending {
            if now < record.finalize_at {
                continue; // Not yet ready to finalize.
            }

            // Parse the lock_id from the record.
            let lock_id_hex = &record.lock_id;
            let lock_txid = match chronx_core::types::TxId::from_hex(lock_id_hex) {
                Ok(id) => id,
                Err(_) => continue
            };

            // Load the lock.
            let mut contract = match self.db.get_timelock(&lock_txid)? {
                Some(c) => c,
                None => continue
            };

            // Only finalize if still in PendingExecutor status.
            if !matches!(contract.status, TimeLockStatus::PendingExecutor { .. }) {
                // Already cancelled or something else happened — mark record as done.
                let mut updated_record = record.clone();
                updated_record.status = "Cancelled".to_string();
                self.db.put_executor_withdrawal(lock_id_hex, &updated_record)?;
                continue;
            }

            // Transfer KX to executor wallet.
            let dest_id = match chronx_core::types::AccountId::from_b58(&record.destination) {
                Ok(id) => id,
                Err(_) => continue
            };
            let mut dest_account = match self.db.get_account(&dest_id)? {
                Some(a) => a,
                None => continue, // Executor wallet account doesn't exist — skip.
            };

            dest_account.balance += contract.amount;
            self.db.put_account(&dest_account)?;

            // Update lock status.
            contract.status = TimeLockStatus::ExecutorWithdrawn { withdrawn_at: now };
            self.db.put_timelock(&contract)?;

            // Mark withdrawal record as finalized.
            let mut updated_record = record.clone();
            updated_record.status = "Finalized".to_string();
            self.db.put_executor_withdrawal(lock_id_hex, &updated_record)?;

            info!(
                lock_id = %lock_id_hex,
                amount_chronos = record.amount_chronos,
                destination = %record.destination,
                "ExecutorWithdraw finalized — KX transferred to executor wallet"
            );

            finalized_count += 1;
        }

        if finalized_count > 0 {
            self.db.flush()?;
        }
        Ok(finalized_count)
    }
    /// Sweep invoices, credits, deposits, and conditionals for status transitions.
    /// Called periodically by the node (every 60 seconds).
    pub fn sweep_genesis8_expiry(&self, now: i64) -> Result<u32, ChronxError> {
        let now_u64 = now as u64;
        let mut count = 0u32;

        // Lapse expired Open invoices
        for invoice in self.db.iter_all_invoices()? {
            if matches!(invoice.status, InvoiceStatus::Open) && now_u64 >= invoice.expiry {
                self.db.update_invoice_status(&invoice.invoice_id, InvoiceStatus::Lapsed, None, None)?;
                count += 1;
            }
        }

        // Lapse expired Open credits
        for credit in self.db.iter_all_credits()? {
            if matches!(credit.status, CreditStatus::Open) && now_u64 >= credit.expiry {
                self.db.update_credit_status(&credit.credit_id, CreditStatus::Lapsed)?;
                count += 1;
            }
        }

        // Mature and default deposits
        for deposit in self.db.iter_all_deposits()? {
            match deposit.status {
                DepositStatus::Active if now_u64 >= deposit.maturity_timestamp => {
                    self.db.update_deposit_status(&deposit.deposit_id, DepositStatus::Matured, None)?;
                    count += 1;
                }
                DepositStatus::Matured if now_u64 >= deposit.maturity_timestamp + DEPOSIT_DEFAULT_GRACE_SECONDS => {
                    self.db.update_deposit_status(&deposit.deposit_id, DepositStatus::Defaulted, None)?;
                    count += 1;
                }
                _ => {}
            }
        }

        // Execute fallback for expired Pending conditionals
        for cond in self.db.iter_all_conditionals()? {
            if matches!(cond.status, ConditionalStatus::Pending) && now_u64 >= cond.valid_until {
                let amount = cond.amount_chronos as u128;
                match cond.fallback.as_str() {
                    "Void" => {
                        // Check for success_payment (hedge premium on clean expiry)
                        let mut success_paid: u128 = 0;
                        if let (Some(spw), Some(spc)) = (&cond.success_payment_wallet, cond.success_payment_chronos) {
                            if spc > 0 && !spw.is_empty() && (spc as u128) <= amount {
                                if let Ok(sp_id) = chronx_core::types::AccountId::from_b58(spw) {
                                    if let Ok(Some(mut sp_acc)) = self.db.get_account(&sp_id) {
                                        sp_acc.balance += spc as u128;
                                        self.db.put_account(&sp_acc)?;
                                        success_paid = spc as u128;
                                        info!(wallet = %spw, amount = spc,
                                              "[SUCCESS PAYMENT] hedge premium paid on clean expiry");
                                    }
                                }
                            }
                        }
                        // Return remaining funds to sender
                        let sender_account_id = chronx_crypto::hash::account_id_from_pubkey(&cond.sender_pubkey);
                        if let Ok(Some(mut sender)) = self.db.get_account(&sender_account_id) {
                            sender.balance += amount - success_paid;
                            self.db.put_account(&sender)?;
                        }
                        self.db.update_conditional_status(&cond.type_v_id, ConditionalStatus::Voided)?;
                        count += 1;
                    }
                    "Return" => {
                        // Check for success_payment (hedge premium on clean expiry)
                        let mut success_paid: u128 = 0;
                        if let (Some(spw), Some(spc)) = (&cond.success_payment_wallet, cond.success_payment_chronos) {
                            if spc > 0 && !spw.is_empty() && (spc as u128) <= amount {
                                if let Ok(sp_id) = chronx_core::types::AccountId::from_b58(spw) {
                                    if let Ok(Some(mut sp_acc)) = self.db.get_account(&sp_id) {
                                        sp_acc.balance += spc as u128;
                                        self.db.put_account(&sp_acc)?;
                                        success_paid = spc as u128;
                                        info!(wallet = %spw, amount = spc,
                                              "[SUCCESS PAYMENT] hedge premium paid on clean expiry");
                                    }
                                }
                            }
                        }
                        // Return remaining funds to sender
                        let sender_account_id = chronx_crypto::hash::account_id_from_pubkey(&cond.sender_pubkey);
                        if let Ok(Some(mut sender)) = self.db.get_account(&sender_account_id) {
                            sender.balance += amount - success_paid;
                            self.db.put_account(&sender)?;
                        }
                        self.db.update_conditional_status(&cond.type_v_id, ConditionalStatus::Returned)?;
                        count += 1;
                    }
                    "Escrow" => {
                        // Transfer to Verifas vault
                        if let Ok(Some(vault_addr)) = self.db.get_verifas_vault_address() {
                            let vault_id = chronx_core::types::AccountId::from_b58(&vault_addr).ok();
                            if let Some(vid) = vault_id {
                                if let Ok(Some(mut vault)) = self.db.get_account(&vid) {
                                    vault.balance += amount;
                                    self.db.put_account(&vault)?;
                                }
                            }
                        }
                        self.db.update_conditional_status(&cond.type_v_id, ConditionalStatus::Escrowed)?;
                        count += 1;
                    }
                    _ => {}
                }
            }
        }

        if count > 0 {
            self.db.flush()?;
            info!(transitions = count, "Sweep completed");
        }
        Ok(count)
    }
    /// Check sign-of-life attestations and trigger grace periods or transitions.
    pub fn sweep_sign_of_life(&self, now: i64) -> Result<u32, ChronxError> {
        let now_u64 = now as u64;
        let mut count = 0u32;
        for mut sol in self.db.iter_active_sign_of_life()? {
            match sol.status.as_str() {
                "Active" if now_u64 >= sol.next_due => {
                    // Missed sign of life — enter grace period
                    sol.status = "GracePeriod".to_string();
                    sol.grace_expires = Some(sol.next_due + sol.grace_days * 86400);
                    self.db.put_sign_of_life(&sol.lock_id, &sol)?;
                    count += 1;
                    info!(lock_id = %sol.lock_id, "Sign of life missed — grace period started");
                }
                "GracePeriod" => {
                    if let Some(grace_exp) = sol.grace_expires {
                        if now_u64 >= grace_exp {
                            // Grace period expired — trigger guardian transition
                            sol.status = "Transitioned".to_string();
                            sol.responsible = "Guardian".to_string();
                            self.db.put_sign_of_life(&sol.lock_id, &sol)?;
                            count += 1;
                            info!(lock_id = %sol.lock_id, "Guardian transition triggered");
                        }
                    }
                }
                _ => {}
            }
        }
        if count > 0 {
            self.db.flush()?;
        }
        Ok(count)
    }

    /// Anchor promise chains periodically.
    pub fn sweep_promise_chain_anchors(&self, now: i64) -> Result<u32, ChronxError> {
        let now_u64 = now as u64;
        let mut count = 0u32;
        for mut chain in self.db.iter_all_promise_chains()? {
            let interval = chronx_core::constants::PROMISE_CHAIN_ANCHOR_INTERVAL_SECONDS;
            let last = chain.last_anchor_at.unwrap_or(chain.created_at);
            if now_u64 >= last + interval && !chain.entries.is_empty() {
                // Compute anchor hash = BLAKE3 of all entry hashes concatenated
                let mut data = Vec::new();
                for eid in &chain.entries {
                    data.extend_from_slice(eid);
                }
                if let Some(prev) = chain.last_anchor_hash {
                    data.extend_from_slice(&prev);
                }
                let anchor_hash = *blake3::hash(&data).as_bytes();
                chain.last_anchor_hash = Some(anchor_hash);
                chain.last_anchor_at = Some(now_u64);
                self.db.put_promise_chain(&chain)?;
                count += 1;
            }
        }
        if count > 0 {
            self.db.flush()?;
        }
        Ok(count)
    }



    // ── A4: Loan payment sweep (settles accrued interest on raw JSON loans) ──
    pub fn sweep_loan_payments(&self, now: i64, min_settlement: u64) -> Result<u32, ChronxError> {
        use chronx_core::types::AccountId;
        let mut settled_count = 0u32;

        // Iterate all raw loan entries
        let entries: Vec<_> = self.db.iter_loans().collect();
        for (key, val) in entries {
            let mut loan: serde_json::Value = match serde_json::from_slice(&val) {
                Ok(v) => v, Err(_) => continue
            };

            // Only active main-chain loans
            let status = loan.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status != "active" { continue; }
            // Skip channel loans
            if loan.get("channel_id").and_then(|v| v.as_str()).is_some() { continue; }

            // Get interest rate (bps from interest_rate.Fixed)
            let rate_bps = loan.get("interest_rate")
                .and_then(|v| v.get("Fixed"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if rate_bps == 0 { continue; }

            // Principal in chronos
            let principal_kx = loan.get("principal_kx").and_then(|v| v.as_u64()).unwrap_or(0);
            let principal_chronos = loan.get("principal_chronos").and_then(|v| v.as_u64())
                .unwrap_or(principal_kx * 1_000_000);
            if principal_chronos == 0 { continue; }

            // Time since last settlement
            let last_at = loan.get("last_settlement_at").and_then(|v| v.as_i64())
                .or_else(|| loan.get("accepted_at").and_then(|v| v.as_i64()))
                .or_else(|| loan.get("created_at").and_then(|v| v.as_i64()))
                .unwrap_or(0);
            let elapsed = (now - last_at).max(0) as u64;
            if elapsed == 0 { continue; }

            // Accrued interest: principal * rate_bps / 10000 * elapsed / 31536000
            let accrued = (principal_chronos as u128)
                .checked_mul(rate_bps as u128).unwrap_or(0)
                .checked_mul(elapsed as u128).unwrap_or(0)
                / (10_000u128 * 31_536_000u128);
            let accrued = accrued as u64;
            if accrued < min_settlement { continue; }

            // Borrower & lender wallets
            let borrower_str = loan.get("borrower_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let lender_str = loan.get("lender_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if borrower_str.is_empty() || lender_str.is_empty() { continue; }

            let borrower_id = match AccountId::from_b58(&borrower_str) { Ok(id) => id, Err(_) => continue };
            let lender_id = match AccountId::from_b58(&lender_str) { Ok(id) => id, Err(_) => continue };

            // Check borrower balance
            let mut borrower_acc = match self.db.get_account(&borrower_id)? {
                Some(a) => a, None => continue
            };
            if borrower_acc.balance < accrued as u128 {
                loan["status"] = serde_json::json!("payment_failed");
                let updated = serde_json::to_vec(&loan).map_err(|_| ChronxError::SerializationError)?;
                if key.len() == 32 { let mut lid = [0u8;32]; lid.copy_from_slice(&key); self.db.save_loan(&lid, &updated)?; }
                warn!(loan_id = %loan.get("loan_id_hex").and_then(|v|v.as_str()).unwrap_or("?"),
                      "[LOAN SWEEP] payment failed insufficient balance");
                continue;
            }

            // Calculate payment status (on time vs late)
            let renewal_secs = loan.get("loan_type")
                .and_then(|v| v.get("Revolving"))
                .and_then(|v| v.get("renewal_period_seconds"))
                .and_then(|v| v.as_i64())
                .unwrap_or(86400); // default daily
            let due_at = loan.get("last_payment_at").and_then(|v| v.as_i64())
                .or_else(|| loan.get("accepted_at").and_then(|v| v.as_i64()))
                .unwrap_or(last_at)
                + renewal_secs;
            let periods_late = if now > due_at && renewal_secs > 0 {
                ((now - due_at) / renewal_secs) as u32
            } else { 0u32 };
            let status_str = if periods_late == 0 {
                "On Time".to_string()
            } else {
                format!("{} period(s) late", periods_late)
            };
            let loan_id_prefix = loan.get("loan_id_hex").and_then(|v| v.as_str()).unwrap_or("?")
                .chars().take(8).collect::<String>();

            // Debit borrower, credit lender
            borrower_acc.balance -= accrued as u128;
            self.db.put_account(&borrower_acc)?;
            let mut lender_acc = match self.db.get_account(&lender_id)? {
                Some(a) => a, None => continue
            };
            lender_acc.balance += accrued as u128;
            self.db.put_account(&lender_acc)?;

            // Update loan record with settlement + payment timestamps
            loan["last_settlement_at"] = serde_json::json!(now);
            loan["last_payment_at"] = serde_json::json!(now);
            let updated = serde_json::to_vec(&loan).map_err(|_| ChronxError::SerializationError)?;
            if key.len() == 32 { let mut lid = [0u8;32]; lid.copy_from_slice(&key); self.db.save_loan(&lid, &updated)?; }

            info!(accrued_chronos = accrued,
                  loan_id = %loan_id_prefix,
                  status = %status_str,
                  borrower = %borrower_str, lender = %lender_str,
                  "[LOAN SWEEP] {} — {} KX — {}", loan_id_prefix, accrued / 1_000_000, status_str);
            settled_count += 1;
        }
        if settled_count > 0 { self.db.flush()?; }
        Ok(settled_count)
    }

    // ── One-time migration: create escrow records for pre-fix rescission loans ──
    /// For any loan in accepted_pending_rescission without an escrow record,
    /// debit the lender and create the escrow deposit. Idempotent.
    /// Re-serialize all accounts to include new savings fields (bincode migration).
    pub fn migrate_account_savings_fields(&self) -> Result<u32, ChronxError> {
        let mut count = 0u32;
        let entries = self.db.iter_accounts_raw();

        for (key, val) in entries {
            match bincode::deserialize::<chronx_core::account::Account>(&val) {
                Ok(acc) => {
                    if let Ok(new_val) = bincode::serialize(&acc) {
                        if new_val.len() != val.len() {
                            self.db.put_account_raw(&key, &new_val)?;
                            count += 1;
                        }
                    }
                }
                Err(_) => {
                    // Old format — append default savings bytes
                    let mut extended = val.to_vec();
                    extended.extend_from_slice(&[0u8; 16]); // savings_balance: u128 = 0
                    extended.push(0); // savings_invested: bool = false
                    extended.push(0); // savings_withdrawal_pending: bool = false

                    match bincode::deserialize::<chronx_core::account::Account>(&extended) {
                        Ok(acc) => {
                            if let Ok(new_val) = bincode::serialize(&acc) {
                                self.db.put_account_raw(&key, &new_val)?;
                                count += 1;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to migrate account {}: {}", hex::encode(&key), e);
                        }
                    }
                }
            }
        }
        if count > 0 { self.db.flush()?; }
        Ok(count)
    }

    pub fn migrate_rescission_escrows(&self) -> Result<u32, ChronxError> {
        use chronx_core::types::AccountId;
        let mut count = 0u32;

        let entries: Vec<_> = self.db.iter_loans().collect();
        for (key, val) in entries {
            let loan: serde_json::Value = match serde_json::from_slice(&val) {
                Ok(v) => v, Err(_) => continue
            };

            let status = loan.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status != "accepted_pending_rescission" { continue; }

            if key.len() != 32 { continue; }
            let mut lid = [0u8; 32];
            lid.copy_from_slice(&key);

            // Skip if escrow already exists
            if let Ok(Some(_)) = self.db.get_loan_escrow(&lid) { continue; }

            let lender_str = loan.get("lender_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let principal_kx = loan.get("principal_kx").and_then(|v| v.as_u64()).unwrap_or(0);
            let principal_chronos = loan.get("principal_chronos").and_then(|v| v.as_u64())
                .unwrap_or(principal_kx * 1_000_000) as u128;
            let expires = loan.get("rescission_expires_at").and_then(|v| v.as_i64()).unwrap_or(0);

            if principal_chronos == 0 || lender_str.is_empty() { continue; }

            let lender_id = match AccountId::from_b58(&lender_str) { Ok(id) => id, Err(_) => continue };
            let mut lender_acc = match self.db.get_account(&lender_id)? {
                Some(a) => a, None => continue
            };

            if lender_acc.balance < principal_chronos {
                warn!(loan_id = %hex::encode(lid),
                      "[ESCROW MIGRATION] lender balance {} < principal {}, skipping",
                      lender_acc.balance, principal_chronos);
                continue;
            }

            lender_acc.balance -= principal_chronos;
            self.db.put_account(&lender_acc)?;
            self.db.put_loan_escrow(&lid, &lender_str, principal_chronos, expires)?;

            info!(loan_id = %hex::encode(lid),
                  principal_kx = principal_chronos / 1_000_000,
                  lender = %lender_str,
                  "[ESCROW MIGRATION] Retroactively locked lender funds in escrow");
            count += 1;
        }
        if count > 0 { self.db.flush()?; }
        Ok(count)
    }

    // ── Savings account actions ─────────────────────────────────────────────

    fn handle_savings_deposit(&self, sender: &chronx_core::account::Account, amount_chronos: u64, _now: i64) -> Result<(), ChronxError> {
        let amount = amount_chronos as u128;
        if amount == 0 {
            return Err(ChronxError::Other("Savings deposit amount must be > 0".into()));
        }

        // Check governance: savings_enabled
        let savings_enabled = self.db.get_meta("governance:savings_enabled")
            .ok().flatten()
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| s == "true")
            .unwrap_or(true); // default enabled
        if !savings_enabled {
            return Err(ChronxError::FeatureNotActive("Savings deposits require governance activation.".into()));
        }

        // Check min deposit (100 KX = 100_000_000 chronos)
        let min_deposit: u128 = 100_000_000;
        if amount < min_deposit {
            return Err(ChronxError::Other(format!("Minimum savings deposit is 100 KX (got {} KX)", amount / 1_000_000)));
        }

        // Check spendable balance
        let spendable = sender.spendable_balance();
        if spendable < amount {
            return Err(ChronxError::InsufficientBalance { need: amount, have: spendable });
        }

        // Check per-wallet cap ($50 USD at $0.003077/KX = ~16,249 KX = 16,249,000,000 chronos)
        let max_savings_chronos: u128 = 16_249_000_000;
        let new_total = sender.savings_balance + amount;
        if new_total > max_savings_chronos {
            return Err(ChronxError::Other(format!(
                "Savings cap exceeded. Max ~16,249 KX ($50). Current: {} KX, deposit: {} KX",
                sender.savings_balance / 1_000_000, amount / 1_000_000
            )));
        }

        // Transfer: spendable -> savings
        let mut acc = sender.clone();
        acc.balance -= amount;
        acc.savings_balance += amount;
        self.db.put_account(&acc)?;

        info!(wallet = %acc.account_id, amount_kx = amount / 1_000_000,
              savings_total_kx = acc.savings_balance / 1_000_000,
              "[SAVINGS DEPOSIT] KX moved to savings bucket");
        Ok(())
    }

    fn handle_savings_withdrawal(&self, sender: &chronx_core::account::Account, amount_chronos: u64, _now: i64) -> Result<(), ChronxError> {
        let amount = amount_chronos as u128;
        if amount == 0 {
            return Err(ChronxError::Other("Withdrawal amount must be > 0".into()));
        }

        if sender.savings_balance < amount {
            return Err(ChronxError::Other(format!(
                "Insufficient savings. Have: {} KX, requested: {} KX",
                sender.savings_balance / 1_000_000, amount / 1_000_000
            )));
        }

        // If invested in HedgeKX, queue withdrawal instead of immediate
        if sender.savings_invested {
            let mut acc = sender.clone();
            acc.savings_withdrawal_pending = true;
            self.db.put_account(&acc)?;
            info!(wallet = %acc.account_id, amount_kx = amount / 1_000_000,
                  "[SAVINGS WITHDRAW] Queued — will process at next instrument expiry");
            return Ok(());
        }

        // Immediate withdrawal: savings -> spendable
        let mut acc = sender.clone();
        acc.savings_balance -= amount;
        acc.balance += amount;
        self.db.put_account(&acc)?;

        info!(wallet = %acc.account_id, amount_kx = amount / 1_000_000,
              savings_remaining_kx = acc.savings_balance / 1_000_000,
              "[SAVINGS WITHDRAW] KX returned to spendable");
        Ok(())
    }

    // ── One-time fix: credit borrower for waived loans that never transferred KX ──
    /// For active loans with rescission_waived_at set where borrower never received
    /// principal (old code bug), debit lender and credit borrower. Idempotent via
    /// escrow_released marker on loan JSON.
    pub fn fix_waived_loan_transfers(&self) -> Result<u32, ChronxError> {
        use chronx_core::types::AccountId;
        let mut count = 0u32;

        let entries: Vec<_> = self.db.iter_loans().collect();
        for (key, val) in entries {
            let mut loan: serde_json::Value = match serde_json::from_slice(&val) {
                Ok(v) => v, Err(_) => continue
            };

            let status = loan.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status != "active" { continue; }

            // Only fix loans that were waived (not sweep-activated)
            if loan.get("rescission_waived_at").is_none() { continue; }

            // Skip if already fixed (idempotency marker)
            if loan.get("escrow_released").and_then(|v| v.as_bool()).unwrap_or(false) { continue; }
            // Also skip if escrow_released is a timestamp (already done)
            if loan.get("escrow_released").and_then(|v| v.as_u64()).is_some() { continue; }

            let lender_str = loan.get("lender_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let borrower_str = loan.get("borrower_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let principal_kx = loan.get("principal_kx").and_then(|v| v.as_u64()).unwrap_or(0);
            let principal_chronos = loan.get("principal_chronos").and_then(|v| v.as_u64())
                .unwrap_or(principal_kx * 1_000_000) as u128;

            if principal_chronos == 0 || lender_str.is_empty() || borrower_str.is_empty() { continue; }
            if key.len() != 32 { continue; }

            let lender_id = match AccountId::from_b58(&lender_str) { Ok(id) => id, Err(_) => continue };
            let borrower_id = match AccountId::from_b58(&borrower_str) { Ok(id) => id, Err(_) => continue };

            // Debit lender
            let mut lender_acc = match self.db.get_account(&lender_id) {
                Ok(Some(a)) => a, _ => continue
            };
            if lender_acc.balance < principal_chronos {
                warn!(loan_id = %hex::encode(&key),
                      "[WAIVE FIX] lender balance {} < principal {}, skipping",
                      lender_acc.balance, principal_chronos);
                continue;
            }
            lender_acc.balance -= principal_chronos;
            self.db.put_account(&lender_acc)?;

            // Credit borrower
            let mut borrower_acc = match self.db.get_account(&borrower_id) {
                Ok(Some(a)) => a, _ => continue
            };
            borrower_acc.balance += principal_chronos;
            self.db.put_account(&borrower_acc)?;

            // Mark as fixed
            loan["escrow_released"] = serde_json::json!(true);
            let mut lid = [0u8; 32];
            lid.copy_from_slice(&key);
            let updated = serde_json::to_vec(&loan).unwrap_or_default();
            let _ = self.db.save_loan(&lid, &updated);

            info!(loan_id = %hex::encode(&key),
                  principal_kx = principal_chronos / 1_000_000,
                  lender = %lender_str, borrower = %borrower_str,
                  "[WAIVE FIX] Credited borrower with principal from waived loan");
            count += 1;
        }
        if count > 0 { self.db.flush()?; }
        Ok(count)
    }

    // ── Rescission sweep: activate loans past their rescission window ─────────
    /// Sweep loans past their rescission window: transfer principal, set status Active
    pub fn sweep_loan_rescissions(&self, now: i64) -> Result<u32, ChronxError> {
        use chronx_core::types::AccountId;
        let mut count = 0u32;

        let entries: Vec<_> = self.db.iter_loans().collect();
        for (key, val) in entries {
            let mut loan: serde_json::Value = match serde_json::from_slice(&val) {
                Ok(v) => v, Err(_) => continue
            };

            let status = loan.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status != "accepted_pending_rescission" { continue; }

            let expires = loan.get("rescission_expires_at")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if expires > now { continue; }

            // Rescission window expired — activate loan and transfer principal
            let lender_str = loan.get("lender_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let borrower_str = loan.get("borrower_wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let principal_kx = loan.get("principal_kx").and_then(|v| v.as_u64()).unwrap_or(0);
            let principal_chronos = loan.get("principal_chronos").and_then(|v| v.as_u64())
                .unwrap_or(principal_kx * 1_000_000) as u128;

            // Release from escrow to borrower (funds already debited from lender at acceptance)
            if key.len() == 32 {
                let mut lid = [0u8; 32];
                lid.copy_from_slice(&key);
                if let Ok(Some(escrow_val)) = self.db.get_loan_escrow(&lid) {
                    let escrow_amount: u128 = escrow_val.get("amount_chronos")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    if escrow_amount > 0 && !borrower_str.is_empty() {
                        let borrower_id = match AccountId::from_b58(&borrower_str) { Ok(id) => id, Err(_) => continue };
                        let mut borrower_acc = match self.db.get_account(&borrower_id)? {
                            Some(a) => a, None => continue
                        };
                        borrower_acc.balance += escrow_amount;
                        self.db.put_account(&borrower_acc)?;
                        let _ = self.db.remove_loan_escrow(&lid);
                        info!(loan_id_hex = %loan.get("loan_id_hex").and_then(|v|v.as_str()).unwrap_or("?"),
                              amount_kx = escrow_amount / 1_000_000,
                              "[ESCROW RELEASE] Sweep: funds released to borrower");
                    }
                } else if principal_chronos > 0 && !lender_str.is_empty() && !borrower_str.is_empty() {
                    // Fallback for pre-fix loans without escrow record
                    let lender_id = match AccountId::from_b58(&lender_str) { Ok(id) => id, Err(_) => continue };
                    let borrower_id = match AccountId::from_b58(&borrower_str) { Ok(id) => id, Err(_) => continue };
                    let mut lender_acc = match self.db.get_account(&lender_id)? {
                        Some(a) => a, None => continue
                    };
                    if lender_acc.balance < principal_chronos {
                        warn!(loan_id = %loan.get("loan_id_hex").and_then(|v|v.as_str()).unwrap_or("?"),
                              "[RESCISSION SWEEP] lender insufficient balance, skipping");
                        continue;
                    }
                    lender_acc.balance -= principal_chronos;
                    self.db.put_account(&lender_acc)?;
                    let mut borrower_acc = match self.db.get_account(&borrower_id)? {
                        Some(a) => a, None => continue
                    };
                    borrower_acc.balance += principal_chronos;
                    self.db.put_account(&borrower_acc)?;
                }
            }

            loan["status"] = serde_json::json!("active");
            loan["activated_at"] = serde_json::json!(now);
            let updated = serde_json::to_vec(&loan).map_err(|_| ChronxError::SerializationError)?;
            if key.len() == 32 {
                let mut lid = [0u8; 32];
                lid.copy_from_slice(&key);
                self.db.save_loan(&lid, &updated)?;
            }

            info!(loan_id = %loan.get("loan_id_hex").and_then(|v|v.as_str()).unwrap_or("?"),
                  "[RESCISSION SWEEP] rescission window expired, loan activated");
            count += 1;
        }
        if count > 0 { self.db.flush()?; }
        Ok(count)
    }
    /// Sweep conditionals with condition_type="OracleTrigger".
    /// Reads latest oracle price from oracle_cache sled tree.
    /// If price crosses threshold in the configured direction, auto-triggers.
    /// On clean expiry: success_payment then fallback.

    /// Process pending draw requests from the pending_drawrequests sled tree.
    /// Draws that have passed their lock_until timestamp are eligible for execution.
    pub fn sweep_pending_drawrequests(&self, now: i64) -> Result<u32, ChronxError> {
        let now_u64 = now as u64;
        let mut count = 0u32;
        let mut to_remove: Vec<String> = Vec::new();

        for (key, val) in self.db.iter_pending_drawrequests()? {
            let lock_until = val.get("lock_until").and_then(|v| v.as_u64()).unwrap_or(0);
            if lock_until > 0 && now_u64 < lock_until {
                continue; // Not yet eligible
            }

            let bond_wallet = val.get("bond_wallet").and_then(|v| v.as_str()).unwrap_or("");
            let amount_chronos = val.get("amount_chronos").and_then(|v| v.as_u64()).unwrap_or(0);
            let reason = val.get("reason").and_then(|v| v.as_str()).unwrap_or("scheduled");

            if amount_chronos == 0 || bond_wallet.is_empty() {
                to_remove.push(key.clone());
                continue;
            }

            // Execute the draw: transfer from bond wallet to recipient
            if let Ok(bond_id) = chronx_core::types::AccountId::from_b58(bond_wallet) {
                if let Ok(Some(mut bond_acc)) = self.db.get_account(&bond_id) {
                    if bond_acc.balance >= amount_chronos as u128 {
                        let dest_wallet = val.get("destination_wallet").and_then(|v| v.as_str()).unwrap_or("");
                        if !dest_wallet.is_empty() {
                            if let Ok(dest_id) = chronx_core::types::AccountId::from_b58(dest_wallet) {
                                if let Ok(Some(mut dest_acc)) = self.db.get_account(&dest_id) {
                                    bond_acc.balance -= amount_chronos as u128;
                                    dest_acc.balance += amount_chronos as u128;
                                    self.db.put_account(&bond_acc)?;
                                    self.db.put_account(&dest_acc)?;
                                    count += 1;
                                    info!(bond = %bond_wallet, dest = %dest_wallet,
                                          amount_kx = amount_chronos / 1_000_000,
                                          reason = %reason,
                                          "[DRAW REQUEST] executed");
                                }
                            }
                        }
                        to_remove.push(key.clone());
                    } else {
                        info!(bond = %bond_wallet, needed = amount_chronos,
                              balance = %bond_acc.balance,
                              "[DRAW REQUEST] insufficient bond balance, deferring");
                    }
                }
            }
        }

        for key in to_remove {
            let _ = self.db.remove_pending_drawrequest(&key);
        }

        if count > 0 {
            self.db.flush()?;
        }
        Ok(count)
    }

    pub fn sweep_oracle_triggers(&self, now: i64) -> Result<u32, ChronxError> {
        // Check governance flag
        let enabled = self.db.get_meta("hedgekx_oracle_trigger_enabled")
            .ok().flatten()
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| s == "true")
            .unwrap_or(false);
        if !enabled { return Ok(0); }

        let now_u64 = now as u64;
        let mut count = 0u32;

        // Get latest KX/USD price from oracle_cache
        let current_price: Option<f64> = self.db.get_meta("oracle_price_kx_usd")
            .ok().flatten()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok());

        let price = match current_price {
            Some(p) if p > 0.0 => p,
            _ => {
                // No valid price — skip this cycle, retry next
                return Ok(0);
            }
        };

        for cond in self.db.iter_all_conditionals()? {
            // Only process OracleTrigger conditionals that are Pending
            if !matches!(cond.status, ConditionalStatus::Pending | ConditionalStatus::PartiallyReleased) {
                continue;
            }
            let cond_type = cond.condition_type.as_deref().unwrap_or("SingleAttestation");
            if cond_type != "OracleTrigger" { continue; }

            // Check expiry first
            if now_u64 >= cond.valid_until {
                // Clean expiry — condition never fired
                // Execute success_payment if configured
                let _amount = cond.amount_chronos as u128;
                let remaining = (cond.amount_chronos - cond.released_so_far_chronos) as u128;
                let mut success_paid: u128 = 0;

                if let (Some(ref spw), Some(spc)) = (&cond.success_payment_wallet, cond.success_payment_chronos) {
                    if spc > 0 && !spw.is_empty() && (spc as u128) <= remaining {
                        if let Ok(sp_id) = chronx_core::types::AccountId::from_b58(spw) {
                            if let Ok(Some(mut sp_acc)) = self.db.get_account(&sp_id) {
                                sp_acc.balance += spc as u128;
                                self.db.put_account(&sp_acc)?;
                                success_paid = spc as u128;
                                info!(wallet = %spw, amount = spc,
                                      "[ORACLE TRIGGER] success_payment on clean expiry");
                            }
                        }
                    }
                }

                // Return remaining to sender (standard fallback)
                let return_amount = remaining - success_paid;
                if return_amount > 0 {
                    let sender_id = chronx_crypto::hash::account_id_from_pubkey(&cond.sender_pubkey);
                    if let Ok(Some(mut sender)) = self.db.get_account(&sender_id) {
                        sender.balance += return_amount;
                        self.db.put_account(&sender)?;
                    }
                }
                self.db.update_conditional_status(&cond.type_v_id, ConditionalStatus::Voided)?;
                count += 1;
                info!(lock = %hex::encode(cond.type_v_id), "[ORACLE TRIGGER] clean expiry — no trigger fired");
                continue;
            }

            // Check oracle trigger condition
            let creation_price = match cond.oracle_creation_price {
                Some(cp) if cp > 0.0 => cp,
                _ => continue, // No creation price recorded — skip
            };
            let threshold = match cond.oracle_trigger_threshold {
                Some(t) if t > 0.0 => t,
                _ => continue, // No threshold set
            };
            let direction = cond.oracle_trigger_direction.as_deref().unwrap_or("Below");
            let trigger_price = creation_price * threshold;

            let triggered = match direction {
                "Below" => price <= trigger_price,
                "Above" => price >= trigger_price,
                _ => false,
            };

            if triggered {
                // Oracle trigger fired — release remaining funds to recipient
                let remaining = cond.amount_chronos.saturating_sub(cond.released_so_far_chronos);
                if remaining == 0 { continue; }

                let recipient_id = chronx_crypto::hash::account_id_from_pubkey(&cond.recipient_pubkey);
                if let Ok(Some(mut recipient)) = self.db.get_account(&recipient_id) {
                    recipient.balance += remaining as u128;
                    self.db.put_account(&recipient)?;
                } else {
                    // Auto-create recipient
                    let new_acc = chronx_core::account::Account {
                        account_id: recipient_id.clone(), balance: remaining as u128,
                        auth_policy: chronx_core::account::AuthPolicy::SingleSig {
                            public_key: chronx_core::types::DilithiumPublicKey(cond.recipient_pubkey.clone())
                        },
                        nonce: 0, recovery_state: Default::default(), post_recovery_restriction: None,
                        verifier_stake: 0, is_verifier: false, account_version: 3, created_at: Some(now),
                        display_name_hash: None, incoming_locks_count: 0, outgoing_locks_count: 0,
                        total_locked_incoming_chronos: 0, total_locked_outgoing_chronos: 0,
                        preferred_fiat_currency: None, lock_marker: None,
                                            savings_balance: 0, savings_invested: false, savings_withdrawal_pending: false
                    };
                    self.db.put_account(&new_acc)?;
                }

                self.db.update_conditional_status(&cond.type_v_id, ConditionalStatus::Released)?;
                count += 1;
                info!(lock = %hex::encode(cond.type_v_id),
                      price = price, trigger = trigger_price, direction = direction,
                      "[ORACLE TRIGGER] FIRED — {} KX released to recipient", remaining / 1_000_000);
            }
        }

        if count > 0 {
            self.db.flush()?;
        }
        Ok(count)
    }

    /// Sweep matured deposits: auto-renew or mark as Matured.
    /// Called periodically by the node. Modifies sled only — no DAG vertex.
    pub fn sweep_matured_deposits(&self, now: i64) -> Result<u32, ChronxError> {
        let now_u64 = now as u64;
        let all_deposits = self.db.iter_all_deposits()?;
        let mut count = 0u32;

        for deposit in all_deposits {
            if !matches!(deposit.status, DepositStatus::Active) {
                continue;
            }
            if now_u64 < deposit.maturity_timestamp {
                continue;
            }

            let mut updated = deposit.clone();
            if deposit.auto_renew {
                // Auto-renew: roll into next term
                updated.maturity_timestamp += deposit.term_seconds;
                updated.renewal_count += 1;
                updated.status = DepositStatus::Active;
                info!(
                    deposit_id = %hex::encode(deposit.deposit_id),
                    renewal = updated.renewal_count,
                    next_maturity = updated.maturity_timestamp,
                    "Deposit auto-renewed"
                );
            } else {
                // Mark as matured — user must call SettleDeposit manually
                updated.status = DepositStatus::Matured;
                info!(
                    deposit_id = %hex::encode(deposit.deposit_id),
                    "Deposit matured (no auto-renew)"
                );
            }
            self.db.put_deposit(&updated)?;
            count += 1;
        }

        if count > 0 {
            self.db.flush()?;
        }
        Ok(count)
    }

    /// Sweep friendly loans past write-off date.
    pub fn sweep_friendly_loan_writeoffs(&self, now: i64) -> Result<u32, ChronxError> {
        let now_u64 = now as u64;
        let mut count = 0u32;

        // 1. Write off Active loans past grace period
        let active = self.db.iter_active_friendly_loans()?;
        for record in active {
            if record.write_off_at > 0 && now_u64 >= record.write_off_at {
                let mut updated = record.clone();
                updated.status = "WrittenOff".to_string();
                self.db.put_friendly_loan(&updated)?;
                info!(
                    loan_id = %hex::encode(record.loan_id),
                    lender = %record.lender,
                    principal_usd = record.principal_usd,
                    "Friendly loan written off by sweep — grace period expired"
                );
                count += 1;
            }
        }

        // 2. Expire PendingAcceptance loans past acceptance window
        let pending = self.db.iter_pending_friendly_loans()?;
        for record in pending {
            if record.base_address_expires_at > 0 && now_u64 >= record.base_address_expires_at {
                // Return KX collateral to lender
                if let Ok(lender_id) = chronx_core::types::AccountId::from_b58(&record.lender) {
                    if let Ok(Some(mut lender_acc)) = self.db.get_account(&lender_id) {
                        lender_acc.balance += record.kx_collateral_chronos as u128;
                        self.db.put_account(&lender_acc)?;
                    }
                }
                let mut updated = record.clone();
                updated.status = "Expired".to_string();
                self.db.put_friendly_loan(&updated)?;
                info!(
                    loan_id = %hex::encode(record.loan_id),
                    lender = %record.lender,
                    "Friendly loan offer expired — borrower did not accept, KX returned"
                );
                count += 1;
            }
        }

        if count > 0 {
            self.db.flush()?;
        }
        Ok(count)
    }

    /// Sweep active TWAP orders: execute partial KX→USDC conversions at each interval.
    /// Called periodically by the node (default: every hour).
    pub fn sweep_twap_orders(&self, now: i64) -> Result<u32, ChronxError> {
        let now_u64 = now as u64;
        let orders = self.db.iter_active_twap_orders()?;
        let mut executed_count = 0u32;

        let min_execution_kx: u128 = self.db.get_meta("pay_as_twap_min_execution_kx")
            .ok().flatten()
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        for mut order in orders {
            let interval_secs = (order.interval_hours as u64) * 3600;
            if now_u64 < order.last_executed_at + interval_secs {
                continue; // Not yet time for next execution
            }

            // Calculate max KX for this interval based on daily volume cap
            // Simplified: use max_daily_pct of total order as proxy (real impl would query XChan volume)
            let intervals_per_day = 24 / order.interval_hours.max(1);
            let max_this_interval = (order.kx_total as f64 * order.max_daily_pct / 100.0 / intervals_per_day as f64) as u128;
            let execute_amount = order.kx_remaining.min(max_this_interval);

            if execute_amount < min_execution_kx * 1_000_000 && order.kx_remaining >= min_execution_kx * 1_000_000 {
                continue; // Below minimum execution threshold
            }

            // Execute the partial conversion (deduct from remaining)
            order.kx_remaining = order.kx_remaining.saturating_sub(execute_amount);
            order.last_executed_at = now_u64;

            if order.kx_remaining == 0 {
                order.status = "Complete".to_string();
                info!(
                    order_id = %hex::encode(order.order_id),
                    "TWAP order completed — all KX converted"
                );
            } else {
                info!(
                    order_id = %hex::encode(order.order_id),
                    executed = execute_amount,
                    remaining = order.kx_remaining,
                    "TWAP order partial execution"
                );
            }

            self.db.put_twap_order(&order)?;
            executed_count += 1;
        }

        if executed_count > 0 {
            self.db.flush()?;
        }
        Ok(executed_count)
    }

}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chronx_core::account::{AuthPolicy, TimeLockContract, TimeLockStatus};
    use chronx_core::constants::{
        CHRONOS_PER_KX, MIN_RECOVERY_BOND_CHRONOS, MIN_VERIFIER_STAKE_CHRONOS,
        PROVIDER_BOND_CHRONOS,
    };
    use chronx_core::transaction::{Action, AuthScheme, Transaction};
    use chronx_core::types::{EvidenceHash, TimeLockId, TxId};
    use chronx_crypto::hash::account_id_from_pubkey;
    use chronx_crypto::{mine_pow, tx_id_from_body, KeyPair};
    use std::sync::Arc;

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
            sender_public_key: Some(kp.public_key.clone()),
        };
        let body_bytes = tx.body_bytes();
        tx.tx_id = tx_id_from_body(&body_bytes);
        tx.signatures = vec![kp.sign(&body_bytes)];
        tx
    }

    fn seed_account(db: &StateDb, kp: &KeyPair, balance: u128) {
        let mut acc = Account::new(
            kp.account_id.clone(),
            AuthPolicy::SingleSig {
                public_key: kp.public_key.clone(),
            },
        );
        acc.balance = balance;
        db.put_account(&acc).unwrap();
    }

    fn seed_timelock(
        db: &StateDb,
        lock_id: TxId,
        sender: &KeyPair,
        recipient: &KeyPair,
        amount: u128,
        unlock_at: i64,
    ) {
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
            lock_marker: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
            transferable: false,
            transfer_policy: None,
            current_beneficiary: None,
            transfer_history: Vec::new(),
            earliest_transfer_date: None,
            email_recipient_hash: None,
            claim_window_secs: None,
            unclaimed_action: None,
            notification_sent: false,
            // ── V3.2 Conditional Payment fields ──────────────────────────
            condition_description: None,
            condition_expiry: None,
            condition_oracle: None,
            condition_precision: None,
            condition_status: None,
            condition_attestation_id: None,
            condition_disputed: false,
            condition_dispute_window_secs: None,
            lock_type: None,
            yield_opt_out: None,
            lock_metadata: None,
            extension_right: None,
            max_extensions: None,
            extensions_used: None,
        };
        db.put_timelock(&contract).unwrap();
    }

    /// Seed a V1 lock (with claim_policy set and org_identifier to avoid ambiguity).
    fn seed_v1_timelock(
        db: &StateDb,
        lock_id: TxId,
        sender: &KeyPair,
        recipient: &KeyPair,
        amount: u128,
        unlock_at: i64,
    ) {
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
            lock_marker: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
            transferable: false,
            transfer_policy: None,
            current_beneficiary: None,
            transfer_history: Vec::new(),
            earliest_transfer_date: None,
            email_recipient_hash: None,
            claim_window_secs: None,
            unclaimed_action: None,
            notification_sent: false,
            // ── V3.2 Conditional Payment fields ──────────────────────────
            condition_description: None,
            condition_expiry: None,
            condition_oracle: None,
            condition_precision: None,
            condition_status: None,
            condition_attestation_id: None,
            condition_disputed: false,
            condition_dispute_window_secs: None,
            lock_type: None,
            yield_opt_out: None,
            lock_metadata: None,
            extension_right: None,
            max_extensions: None,
            extensions_used: None,
        };
        db.put_timelock(&contract).unwrap();
    }

    /// Seed an oracle snapshot so open_claim can read it.
    /// Build a minimal `Action::TimeLockCreate` with all new fields set to None/defaults.
    fn tlc_action(
        recipient: chronx_core::types::DilithiumPublicKey,
        amount: u128,
        unlock_at: i64,
        memo: Option<String>,
    ) -> Action {
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
            lock_marker: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
            email_recipient_hash: None,
            claim_window_secs: None,
            unclaimed_action: None,
        
            transferable: None,
            current_owner_account: None,
            transfer_history: None,
            terms_visibility: None,
            tranche_info: None,
            retirement_status: None,
            retired_fraction: None,

            escalation_wallet: None,
            escalation_lock_seconds: None,
            min_attestors_pct: None,
            required_hedge_ids: None,
            success_payment_wallet: None,
            success_payment_chronos: None,
            condition_type: None,
            oracle_pair: None,
            oracle_trigger_threshold: None,
            oracle_trigger_direction: None,
            linked_instrument_id: None,
            extension_right: None,
            max_extensions: None,
            pay_as_execution: None,
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

    fn make_tx_with_parents(
        kp: &KeyPair,
        nonce: u64,
        parents: Vec<TxId>,
        actions: Vec<Action>,
    ) -> Transaction {
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
            sender_public_key: Some(kp.public_key.clone()),
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

        let tx = make_tx(
            &sender,
            0,
            vec![Action::Transfer {
                to: recipient.account_id.clone(),
                amount: 10 * CHRONOS_PER_KX,
            }],
        );
        engine.apply(&tx, NOW).unwrap();

        let s = engine.db.get_account(&sender.account_id).unwrap().unwrap();
        let r = engine
            .db
            .get_account(&recipient.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(s.balance, 90 * CHRONOS_PER_KX);
        assert_eq!(r.balance, 10 * CHRONOS_PER_KX);
        assert_eq!(s.nonce, 1);
    }

    #[test]
    fn transfer_self_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("t_self")), 0);
        let kp = KeyPair::generate();
        seed_account(&engine.db, &kp, 100 * CHRONOS_PER_KX);
        let tx = make_tx(
            &kp,
            0,
            vec![Action::Transfer {
                to: kp.account_id.clone(),
                amount: CHRONOS_PER_KX,
            }],
        );
        assert!(matches!(
            engine.apply(&tx, NOW).unwrap_err(),
            ChronxError::SelfTransfer
        ));
    }

    #[test]
    fn transfer_insufficient_balance() {
        let engine = StateEngine::new(Arc::new(temp_db("t_insuf")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 5 * CHRONOS_PER_KX);
        let tx = make_tx(
            &sender,
            0,
            vec![Action::Transfer {
                to: recipient.account_id.clone(),
                amount: 10 * CHRONOS_PER_KX,
            }],
        );
        assert!(matches!(
            engine.apply(&tx, NOW).unwrap_err(),
            ChronxError::InsufficientBalance { .. }
        ));
    }

    #[test]
    fn transfer_bad_nonce() {
        let engine = StateEngine::new(Arc::new(temp_db("t_nonce")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);
        let tx = make_tx(
            &sender,
            99,
            vec![Action::Transfer {
                to: recipient.account_id.clone(),
                amount: CHRONOS_PER_KX,
            }],
        );
        assert!(matches!(
            engine.apply(&tx, NOW).unwrap_err(),
            ChronxError::InvalidNonce { .. }
        ));
    }

    // ── Key registration (P2PKH first-spend) ─────────────────────────────────

    /// An account created by receiving a Transfer has an empty public key.
    /// Its first outgoing transaction MUST include `sender_public_key`.
    /// The engine registers the key, then validates the signature normally.
    #[test]
    fn transfer_recipient_can_spend_after_key_registration() {
        use chronx_core::account::AuthPolicy;

        let engine = StateEngine::new(Arc::new(temp_db("key_reg")), 0);
        let funder = KeyPair::generate();
        let new_user = KeyPair::generate();
        seed_account(&engine.db, &funder, 200 * CHRONOS_PER_KX);

        // Step 1: funder transfers 100 KX to new_user — creates account with empty key
        let fund_tx = make_tx(
            &funder,
            0,
            vec![Action::Transfer {
                to: new_user.account_id.clone(),
                amount: 100 * CHRONOS_PER_KX,
            }],
        );
        engine.apply(&fund_tx, NOW).unwrap();

        // Verify new_user's account has empty auth_policy key
        let acc = engine
            .db
            .get_account(&new_user.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(acc.balance, 100 * CHRONOS_PER_KX);
        if let AuthPolicy::SingleSig { public_key } = &acc.auth_policy {
            assert!(public_key.0.is_empty(), "new account should have empty key");
        }

        // Step 2: new_user sends a tx WITH sender_public_key — key gets registered
        let third = KeyPair::generate();
        let spend_tx = make_tx(
            &new_user,
            0,
            vec![Action::Transfer {
                to: third.account_id.clone(),
                amount: 10 * CHRONOS_PER_KX,
            }],
        );
        engine.apply(&spend_tx, NOW).unwrap();

        // Verify new_user's key is now registered, balance reduced, nonce incremented
        let acc2 = engine
            .db
            .get_account(&new_user.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(acc2.balance, 90 * CHRONOS_PER_KX);
        assert_eq!(acc2.nonce, 1);
        if let AuthPolicy::SingleSig { public_key } = &acc2.auth_policy {
            assert!(!public_key.0.is_empty(), "key should now be registered");
            assert_eq!(public_key.0, new_user.public_key.0);
        }

        // Step 3: new_user sends another tx — no sender_public_key needed now
        let mut tx3 = make_tx(
            &new_user,
            1,
            vec![Action::Transfer {
                to: third.account_id.clone(),
                amount: 5 * CHRONOS_PER_KX,
            }],
        );
        tx3.sender_public_key = None; // omit — key already registered
        let body = tx3.body_bytes();
        tx3.tx_id = chronx_crypto::hash::tx_id_from_body(&body);
        tx3.signatures = vec![new_user.sign(&body)];
        engine.apply(&tx3, NOW).unwrap();

        let acc3 = engine
            .db
            .get_account(&new_user.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(acc3.balance, 85 * CHRONOS_PER_KX);
        assert_eq!(acc3.nonce, 2);
    }

    // ── TimeLockCreate ────────────────────────────────────────────────────────

    #[test]
    fn timelock_create_valid() {
        let engine = StateEngine::new(Arc::new(temp_db("tlc_valid")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let unlock_at = NOW + 86_400;
        let tx = make_tx(
            &sender,
            0,
            vec![tlc_action(
                recipient.public_key.clone(),
                50 * CHRONOS_PER_KX,
                unlock_at,
                Some("test".into()),
            )],
        );
        engine.apply(&tx, NOW).unwrap();

        let s = engine.db.get_account(&sender.account_id).unwrap().unwrap();
        assert_eq!(s.balance, 50 * CHRONOS_PER_KX);

        let contract = engine.db.get_timelock(&tx.tx_id).unwrap().unwrap();
        assert_eq!(contract.amount, 50 * CHRONOS_PER_KX);
        assert_eq!(contract.unlock_at, unlock_at);
        assert_eq!(contract.status, TimeLockStatus::Pending);
        assert_eq!(
            contract.lock_version, 0,
            "new locks from TimeLockCreate must be V0"
        );
    }

    #[test]
    fn timelock_create_past_unlock_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("tlc_past")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);
        let tx = make_tx(
            &sender,
            0,
            vec![tlc_action(
                recipient.public_key.clone(),
                CHRONOS_PER_KX,
                NOW - 1,
                None,
            )],
        );
        assert!(matches!(
            engine.apply(&tx, NOW).unwrap_err(),
            ChronxError::UnlockTimestampInPast
        ));
    }

    #[test]
    fn timelock_create_zero_amount_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("tlc_zero")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);
        let tx = make_tx(
            &sender,
            0,
            vec![tlc_action(
                recipient.public_key.clone(),
                0,
                NOW + 86_400,
                None,
            )],
        );
        assert!(matches!(
            engine.apply(&tx, NOW).unwrap_err(),
            ChronxError::ZeroAmount
        ));
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
        seed_timelock(
            &engine.db,
            lock_id.clone(),
            &sender,
            &recipient,
            50 * CHRONOS_PER_KX,
            NOW - 1,
        );

        let tx = make_tx(
            &recipient,
            0,
            vec![Action::TimeLockClaim {
                lock_id: TimeLockId(lock_id),
            }],
        );
        engine.apply(&tx, NOW).unwrap();

        let r = engine
            .db
            .get_account(&recipient.account_id)
            .unwrap()
            .unwrap();
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
        seed_timelock(
            &engine.db,
            lock_id.clone(),
            &sender,
            &recipient,
            50 * CHRONOS_PER_KX,
            NOW + 86_400,
        );
        let tx = make_tx(
            &recipient,
            0,
            vec![Action::TimeLockClaim {
                lock_id: TimeLockId(lock_id),
            }],
        );
        assert!(matches!(
            engine.apply(&tx, NOW).unwrap_err(),
            ChronxError::TimeLockNotMatured { .. }
        ));
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
        seed_timelock(
            &engine.db,
            lock_id.clone(),
            &sender,
            &recipient,
            50 * CHRONOS_PER_KX,
            NOW - 1,
        );
        let tx = make_tx(
            &impostor,
            0,
            vec![Action::TimeLockClaim {
                lock_id: TimeLockId(lock_id),
            }],
        );
        assert!(matches!(
            engine.apply(&tx, NOW).unwrap_err(),
            ChronxError::AuthPolicyViolation
        ));
    }

    // ── Recovery ──────────────────────────────────────────────────────────────

    #[test]
    fn recovery_start_valid() {
        let engine = StateEngine::new(Arc::new(temp_db("rec_start")), 0);
        let requester = KeyPair::generate();
        let target_kp = KeyPair::generate();
        let new_owner = KeyPair::generate();
        seed_account(
            &engine.db,
            &requester,
            MIN_RECOVERY_BOND_CHRONOS + CHRONOS_PER_KX,
        );
        engine
            .db
            .put_account(&Account::new(
                target_kp.account_id.clone(),
                AuthPolicy::SingleSig {
                    public_key: target_kp.public_key.clone(),
                },
            ))
            .unwrap();

        let tx = make_tx(
            &requester,
            0,
            vec![Action::StartRecovery {
                target_account: target_kp.account_id.clone(),
                proposed_owner_key: new_owner.public_key.clone(),
                evidence_hash: EvidenceHash([0xABu8; 32]),
                bond_amount: MIN_RECOVERY_BOND_CHRONOS,
            }],
        );
        engine.apply(&tx, NOW).unwrap();

        let req = engine
            .db
            .get_account(&requester.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(req.balance, CHRONOS_PER_KX);
        let tgt = engine
            .db
            .get_account(&target_kp.account_id)
            .unwrap()
            .unwrap();
        assert!(tgt.recovery_state.active);
    }

    #[test]
    fn recovery_bond_too_low() {
        let engine = StateEngine::new(Arc::new(temp_db("rec_bond_low")), 0);
        let requester = KeyPair::generate();
        let target_kp = KeyPair::generate();
        let new_owner = KeyPair::generate();
        seed_account(&engine.db, &requester, MIN_RECOVERY_BOND_CHRONOS * 2);
        engine
            .db
            .put_account(&Account::new(
                target_kp.account_id.clone(),
                AuthPolicy::SingleSig {
                    public_key: target_kp.public_key.clone(),
                },
            ))
            .unwrap();
        let tx = make_tx(
            &requester,
            0,
            vec![Action::StartRecovery {
                target_account: target_kp.account_id.clone(),
                proposed_owner_key: new_owner.public_key.clone(),
                evidence_hash: EvidenceHash([0u8; 32]),
                bond_amount: MIN_RECOVERY_BOND_CHRONOS - 1,
            }],
        );
        assert!(matches!(
            engine.apply(&tx, NOW).unwrap_err(),
            ChronxError::RecoveryBondTooLow { .. }
        ));
    }

    #[test]
    fn register_verifier_valid() {
        let engine = StateEngine::new(Arc::new(temp_db("reg_verifier")), 0);
        let kp = KeyPair::generate();
        seed_account(&engine.db, &kp, MIN_VERIFIER_STAKE_CHRONOS + CHRONOS_PER_KX);
        let tx = make_tx(
            &kp,
            0,
            vec![Action::RegisterVerifier {
                stake_amount: MIN_VERIFIER_STAKE_CHRONOS,
            }],
        );
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
        engine
            .db
            .put_account(&Account::new(
                target_kp.account_id.clone(),
                AuthPolicy::SingleSig {
                    public_key: target_kp.public_key.clone(),
                },
            ))
            .unwrap();
        for v in &verifiers {
            seed_account(&engine.db, v, MIN_VERIFIER_STAKE_CHRONOS + CHRONOS_PER_KX);
        }

        engine
            .apply(
                &make_tx(
                    &requester,
                    0,
                    vec![Action::StartRecovery {
                        target_account: target_kp.account_id.clone(),
                        proposed_owner_key: new_owner.public_key.clone(),
                        evidence_hash: EvidenceHash([0x01u8; 32]),
                        bond_amount: MIN_RECOVERY_BOND_CHRONOS,
                    }],
                ),
                NOW,
            )
            .unwrap();

        for v in &verifiers {
            engine
                .apply(
                    &make_tx(
                        v,
                        0,
                        vec![Action::RegisterVerifier {
                            stake_amount: MIN_VERIFIER_STAKE_CHRONOS,
                        }],
                    ),
                    NOW,
                )
                .unwrap();
        }

        for v in &verifiers {
            engine
                .apply(
                    &make_tx(
                        v,
                        1,
                        vec![Action::VoteRecovery {
                            target_account: target_kp.account_id.clone(),
                            approve: true,
                            fee_bid: 0,
                        }],
                    ),
                    NOW,
                )
                .unwrap();
        }

        let mut tgt = engine
            .db
            .get_account(&target_kp.account_id)
            .unwrap()
            .unwrap();
        tgt.recovery_state.recovery_execute_after = Some(NOW - 1);
        engine.db.put_account(&tgt).unwrap();

        engine
            .apply(
                &make_tx(
                    &requester,
                    1,
                    vec![Action::FinalizeRecovery {
                        target_account: target_kp.account_id.clone(),
                    }],
                ),
                NOW,
            )
            .unwrap();

        let final_tgt = engine
            .db
            .get_account(&target_kp.account_id)
            .unwrap()
            .unwrap();
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

        let tx = make_tx(
            &sender,
            0,
            vec![Action::Transfer {
                to: recipient.account_id.clone(),
                amount: CHRONOS_PER_KX,
            }],
        );
        engine.apply(&tx, NOW).unwrap();

        assert!(
            engine.db.vertex_exists(&tx.tx_id),
            "vertex not persisted after apply"
        );
        let v = engine.db.get_vertex(&tx.tx_id).unwrap().unwrap();
        assert_eq!(v.depth, 0);
    }

    #[test]
    fn chained_tx_parent_accepted() {
        let engine = StateEngine::new(Arc::new(temp_db("dag_chain")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let tx1 = make_tx(
            &sender,
            0,
            vec![Action::Transfer {
                to: recipient.account_id.clone(),
                amount: CHRONOS_PER_KX,
            }],
        );
        engine.apply(&tx1, NOW).unwrap();

        let tx2 = make_tx_with_parents(
            &sender,
            1,
            vec![tx1.tx_id.clone()],
            vec![Action::Transfer {
                to: recipient.account_id.clone(),
                amount: CHRONOS_PER_KX,
            }],
        );
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

        let tx = make_tx(
            &sender,
            0,
            vec![Action::Transfer {
                to: recipient.account_id.clone(),
                amount: CHRONOS_PER_KX,
            }],
        );
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
        seed_v1_timelock(
            &engine.db,
            lock_id.clone(),
            &lock_sender,
            &agent,
            lock_amount,
            NOW - 1,
        );
        seed_oracle(&engine.db, 100); // $1 per KX → 5 KX = $5 → trivial lane

        // 1. OpenClaim
        engine
            .apply(
                &make_tx(
                    &agent,
                    0,
                    vec![Action::OpenClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                    }],
                ),
                NOW,
            )
            .unwrap();
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(
            matches!(c.status, TimeLockStatus::ClaimOpen { .. }),
            "expected ClaimOpen after open_claim"
        );

        // 2. SubmitClaimCommit
        let payload = b"I am the beneficiary - Alice Smith";
        let salt = [0xAAu8; 32];
        let commit_hash = {
            let mut h = blake3::Hasher::new();
            h.update(payload);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        engine
            .apply(
                &make_tx(
                    &agent,
                    1,
                    vec![Action::SubmitClaimCommit {
                        lock_id: TimeLockId(lock_id.clone()),
                        commit_hash,
                        bond_amount: bond,
                    }],
                ),
                NOW,
            )
            .unwrap();
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(
            matches!(c.status, TimeLockStatus::ClaimCommitted { .. }),
            "expected ClaimCommitted"
        );

        // 3. RevealClaim (within window)
        engine
            .apply(
                &make_tx(
                    &agent,
                    2,
                    vec![Action::RevealClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                        payload: payload.to_vec(),
                        salt,
                        certificates: vec![],
                    }],
                ),
                NOW + 1,
            )
            .unwrap();
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(
            matches!(c.status, TimeLockStatus::ClaimRevealed { .. }),
            "expected ClaimRevealed"
        );

        // 4. FinalizeClaim (after challenge window — trivial: 7 days)
        let after_window = NOW + 1 + 7 * 24 * 3600 + 1;
        engine
            .apply(
                &make_tx(
                    &agent,
                    3,
                    vec![Action::FinalizeClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                    }],
                ),
                after_window,
            )
            .unwrap();

        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(
            matches!(c.status, TimeLockStatus::ClaimFinalized { .. }),
            "expected ClaimFinalized, got {:?}",
            c.status
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
        seed_v1_timelock(
            &engine.db,
            lock_id.clone(),
            &lock_sender,
            &agent,
            5 * CHRONOS_PER_KX,
            NOW - 1,
        );
        seed_oracle(&engine.db, 100);

        // OpenClaim + SubmitClaimCommit with a valid commit_hash.
        engine
            .apply(
                &make_tx(
                    &agent,
                    0,
                    vec![Action::OpenClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                    }],
                ),
                NOW,
            )
            .unwrap();

        let real_payload = b"real payload";
        let salt = [0xBBu8; 32];
        let commit_hash = {
            let mut h = blake3::Hasher::new();
            h.update(real_payload);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        engine
            .apply(
                &make_tx(
                    &agent,
                    1,
                    vec![Action::SubmitClaimCommit {
                        lock_id: TimeLockId(lock_id.clone()),
                        commit_hash,
                        bond_amount: bond,
                    }],
                ),
                NOW,
            )
            .unwrap();

        // Reveal with WRONG payload — hash mismatch → slash committed as Ok.
        engine
            .apply(
                &make_tx(
                    &agent,
                    2,
                    vec![Action::RevealClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                        payload: b"tampered payload".to_vec(),
                        salt,
                        certificates: vec![],
                    }],
                ),
                NOW + 1,
            )
            .unwrap();

        // Status should be ClaimSlashed.
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(
            c.status,
            TimeLockStatus::ClaimSlashed {
                reason: SlashReason::RevealHashMismatch,
                ..
            }
        ));
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
        seed_v1_timelock(
            &engine.db,
            lock_id.clone(),
            &lock_sender,
            &agent,
            lock_amount,
            NOW - 1,
        );
        seed_oracle(&engine.db, 100);

        // 1. OpenClaim
        engine
            .apply(
                &make_tx(
                    &agent,
                    0,
                    vec![Action::OpenClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                    }],
                ),
                NOW,
            )
            .unwrap();

        // 2. SubmitClaimCommit
        let payload = b"agent claim";
        let salt = [0xCCu8; 32];
        let commit_hash = {
            let mut h = blake3::Hasher::new();
            h.update(payload);
            h.update(&salt);
            *h.finalize().as_bytes()
        };
        engine
            .apply(
                &make_tx(
                    &agent,
                    1,
                    vec![Action::SubmitClaimCommit {
                        lock_id: TimeLockId(lock_id.clone()),
                        commit_hash,
                        bond_amount: bond,
                    }],
                ),
                NOW,
            )
            .unwrap();

        // 3. RevealClaim (valid hash)
        engine
            .apply(
                &make_tx(
                    &agent,
                    2,
                    vec![Action::RevealClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                        payload: payload.to_vec(),
                        salt,
                        certificates: vec![],
                    }],
                ),
                NOW + 1,
            )
            .unwrap();

        // 4. ChallengeClaimReveal (within 7-day window)
        engine
            .apply(
                &make_tx(
                    &challenger,
                    0,
                    vec![Action::ChallengeClaimReveal {
                        lock_id: TimeLockId(lock_id.clone()),
                        evidence_hash: [0xDDu8; 32],
                        bond_amount: bond,
                    }],
                ),
                NOW + 2,
            )
            .unwrap();
        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(c.status, TimeLockStatus::ClaimChallenged { .. }));

        // 5. FinalizeClaim — challenger wins (MVP)
        engine
            .apply(
                &make_tx(
                    &agent,
                    3,
                    vec![Action::FinalizeClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                    }],
                ),
                NOW + 3,
            )
            .unwrap();

        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(matches!(
            c.status,
            TimeLockStatus::ClaimSlashed {
                reason: SlashReason::SuccessfulChallenge,
                ..
            }
        ));

        // Challenger gets back their bond + agent's bond.
        let ch_acc = engine
            .db
            .get_account(&challenger.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            ch_acc.balance,
            bond * 2 - bond + bond + bond,
            "challenger: initial - bond + bond_back + agent_bond"
        );
        // Sender gets lock_amount returned.
        let s_acc = engine
            .db
            .get_account(&lock_sender.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            s_acc.balance,
            lock_amount * 2,
            "sender gets lock_amount back on top of seeded balance"
        );
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
            claim_policy: Some(1),               // has a policy
            beneficiary_anchor_commitment: None, // no commitment
            org_identifier: None,                // no org
            cancellation_window_secs: None,
            notify_recipient: true,
            tags: None,
            private: false,
            expiry_policy: None,
            split_policy: None,
            claim_attempts_max: None,
            recurring: None,
            lock_marker: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
            transferable: false,
            transfer_policy: None,
            current_beneficiary: None,
            transfer_history: Vec::new(),
            earliest_transfer_date: None,
            email_recipient_hash: None,
            claim_window_secs: None,
            unclaimed_action: None,
            notification_sent: false,
            // ── V3.2 Conditional Payment fields ──────────────────────────
            condition_description: None,
            condition_expiry: None,
            condition_oracle: None,
            condition_precision: None,
            condition_status: None,
            condition_attestation_id: None,
            condition_disputed: false,
            condition_dispute_window_secs: None,
            lock_type: None,
            yield_opt_out: None,
            lock_metadata: None,
            extension_right: None,
            max_extensions: None,
            extensions_used: None,
        };
        engine.db.put_timelock(&contract).unwrap();

        // OpenClaim should transition to Ambiguous, not ClaimOpen.
        engine
            .apply(
                &make_tx(
                    &agent,
                    0,
                    vec![Action::OpenClaim {
                        lock_id: TimeLockId(lock_id.clone()),
                    }],
                ),
                NOW,
            )
            .unwrap();

        let c = engine.db.get_timelock(&lock_id).unwrap().unwrap();
        assert!(
            matches!(c.status, TimeLockStatus::Ambiguous { .. }),
            "expected Ambiguous for lock with no unique identifier, got {:?}",
            c.status
        );
    }

    // ── V2 Claims: Oracle oracle manipulation attempt rejected ────────────────

    #[test]
    fn oracle_submission_rejected_for_non_oracle_provider() {
        let engine = StateEngine::new(Arc::new(temp_db("oracle_manip")), 0);
        let submitter = KeyPair::generate();
        seed_account(
            &engine.db,
            &submitter,
            PROVIDER_BOND_CHRONOS + CHRONOS_PER_KX,
        );

        // Register as "kyc" provider (not "oracle").
        engine
            .apply(
                &make_tx(
                    &submitter,
                    0,
                    vec![Action::RegisterProvider {
                        provider_class: "kyc".to_string(),
                        jurisdictions: vec!["US".to_string()],
                        bond_amount: PROVIDER_BOND_CHRONOS,
                    }],
                ),
                NOW,
            )
            .unwrap();

        // Attempt to submit oracle price — should fail.
        let err = engine
            .apply(
                &make_tx(
                    &submitter,
                    1,
                    vec![Action::SubmitOraclePrice {
                        pair: "KX/USD".to_string(),
                        price_cents: 999_999_999, // malicious inflated price
                    }],
                ),
                NOW,
            )
            .unwrap_err();
        assert!(
            matches!(err, ChronxError::AuthPolicyViolation),
            "non-oracle provider must not submit oracle prices"
        );
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
        seed_v1_timelock(
            &engine.db,
            lock_id.clone(),
            &lock_sender,
            &recipient,
            CHRONOS_PER_KX,
            NOW - 1,
        );

        // Attempting direct TimeLockClaim must fail.
        let err = engine
            .apply(
                &make_tx(
                    &recipient,
                    0,
                    vec![Action::TimeLockClaim {
                        lock_id: TimeLockId(lock_id),
                    }],
                ),
                NOW,
            )
            .unwrap_err();
        assert!(
            matches!(err, ChronxError::LockRequiresClaimsFramework),
            "V1 lock must not be directly claimable"
        );
    }
}
