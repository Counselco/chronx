use chronx_core::account::{Account, AuthPolicy, TimeLockContract, TimeLockStatus};
use chronx_core::constants::{
    MIN_CHALLENGE_BOND_CHRONOS, MIN_RECOVERY_BOND_CHRONOS, MIN_VERIFIER_STAKE_CHRONOS,
    RECOVERY_CHALLENGE_WINDOW_SECS, RECOVERY_EXECUTION_DELAY_SECS, RECOVERY_VERIFIER_THRESHOLD,
};
use chronx_core::error::ChronxError;
use chronx_core::transaction::{Action, Transaction};
use chronx_core::types::Timestamp;
use chronx_crypto::hash::account_id_from_pubkey;
use chronx_dag::validation::{validate_signatures, validate_vertex};
use tracing::{info, warn};

use crate::db::StateDb;

/// The state transition engine.
///
/// Validates and applies transactions to the persistent state database.
/// Each `apply` call is atomic: either all actions succeed or none do
/// (using a staged write approach — accounts are read, mutations staged,
/// then written only on full success).
pub struct StateEngine {
    pub db: StateDb,
    pub pow_difficulty: u8,
}

impl StateEngine {
    pub fn new(db: StateDb, pow_difficulty: u8) -> Self {
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
        // We collect all mutations before writing to allow atomic rollback.
        let mut accounts_to_write: Vec<Account> = Vec::new();
        let mut timelocks_to_write: Vec<TimeLockContract> = Vec::new();

        // Work on a clone of sender to stage mutations.
        let mut staged_sender = sender.clone();

        for action in &tx.actions {
            self.apply_action(
                action,
                &mut staged_sender,
                &mut accounts_to_write,
                &mut timelocks_to_write,
                now,
                &tx.tx_id,
            )?;
        }

        // Increment nonce after all actions succeed.
        staged_sender.nonce += 1;
        accounts_to_write.push(staged_sender);

        // ── Commit ────────────────────────────────────────────────────────────
        for acc in &accounts_to_write {
            self.db.put_account(acc)?;
        }
        for tlc in &timelocks_to_write {
            self.db.put_timelock(tlc)?;
        }

        // Update DAG tips: remove parents that are now covered, add this vertex.
        for parent_id in &tx.parents {
            let _ = self.db.remove_tip(parent_id);
        }
        self.db.add_tip(&tx.tx_id)?;

        info!(tx_id = %tx.tx_id, "applied transaction");
        Ok(())
    }

    fn apply_action(
        &self,
        action: &Action,
        sender: &mut Account,
        accounts_to_write: &mut Vec<Account>,
        timelocks_to_write: &mut Vec<TimeLockContract>,
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
                accounts_to_write.push(recipient);
                Ok(())
            }

            // ── TimeLockCreate ────────────────────────────────────────────────
            Action::TimeLockCreate { recipient, amount, unlock_at, memo } => {
                if *amount == 0 {
                    return Err(ChronxError::ZeroAmount);
                }
                if *unlock_at <= now {
                    return Err(ChronxError::UnlockTimestampInPast);
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
                };
                timelocks_to_write.push(contract);
                Ok(())
            }

            // ── TimeLockClaim ─────────────────────────────────────────────────
            Action::TimeLockClaim { lock_id } => {
                let mut contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                if contract.status != TimeLockStatus::Pending {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }
                if now < contract.unlock_at {
                    return Err(ChronxError::TimeLockNotMatured {
                        unlock_time: contract.unlock_at,
                    });
                }

                // Verify sender is the registered recipient.
                let expected_id = account_id_from_pubkey(&contract.recipient_key.0);
                if sender.account_id != expected_id {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                sender.balance += contract.amount;
                contract.status = TimeLockStatus::Claimed { claimed_at: now };
                timelocks_to_write.push(contract);
                Ok(())
            }

            // ── TimeLockSell ─────────────────────────────────────────────────
            // Secondary market scaffold: validates and marks ForSale.
            // Order matching / execution is NOT active at V1.
            Action::TimeLockSell { lock_id, ask_price: _ } => {
                let contract = self
                    .db
                    .get_timelock(&lock_id.0)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.to_string()))?;

                if contract.status != TimeLockStatus::Pending {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }

                // Only the recipient may list for sale.
                let expected_id = account_id_from_pubkey(&contract.recipient_key.0);
                if sender.account_id != expected_id {
                    return Err(ChronxError::AuthPolicyViolation);
                }

                // Feature not yet active.
                warn!("TimeLockSell submitted — secondary market not active at V1");
                return Err(ChronxError::FeatureNotActive(
                    "secondary market (TimeLockSell) is not active in V1".into(),
                ));
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

                accounts_to_write.push(target);
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

                accounts_to_write.push(target);
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

                // Rotate owner key.
                target.auth_policy = AuthPolicy::RecoveryEnabled {
                    owner_key: new_key,
                    recovery_config: chronx_core::account::RecoveryConfig::default(),
                };

                target.recovery_state = chronx_core::account::RecoveryState::default();

                accounts_to_write.push(target);
                Ok(())
            }

            // ── RegisterVerifier ─────────────────────────────────────────────
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

                // Check for duplicate vote.
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

                accounts_to_write.push(target);
                Ok(())
            }
        }
    }
}
