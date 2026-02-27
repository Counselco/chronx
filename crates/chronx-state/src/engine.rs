use chronx_core::account::{Account, AuthPolicy, TimeLockContract, TimeLockStatus};
use chronx_core::constants::{
    MIN_CHALLENGE_BOND_CHRONOS, MIN_RECOVERY_BOND_CHRONOS, MIN_VERIFIER_STAKE_CHRONOS,
    RECOVERY_CHALLENGE_WINDOW_SECS, RECOVERY_EXECUTION_DELAY_SECS, RECOVERY_VERIFIER_THRESHOLD,
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

/// The state transition engine.
///
/// Validates and applies transactions to the persistent state database.
/// Each `apply` call is atomic: either all actions succeed or none do
/// (using a staged write approach — accounts are read, mutations staged,
/// then written only on full success).
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

        // Persist the vertex so that vertex_exists() returns true for future
        // duplicate checks and parent-existence validation.
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use chronx_core::account::{AuthPolicy, TimeLockContract, TimeLockStatus};
    use chronx_core::constants::{
        CHRONOS_PER_KX, MIN_RECOVERY_BOND_CHRONOS, MIN_VERIFIER_STAKE_CHRONOS,
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

    /// Build a genesis-style (no parents) signed transaction.
    /// Empty parents bypass PoW validation and parent-existence checks.
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
        };
        let body_bytes = tx.body_bytes();
        tx.tx_id = tx_id_from_body(&body_bytes);
        tx.signatures = vec![kp.sign(&body_bytes)];
        tx
    }

    /// Seed a funded account in the DB.
    fn seed_account(db: &StateDb, kp: &KeyPair, balance: u128) {
        let mut acc = Account::new(
            kp.account_id.clone(),
            AuthPolicy::SingleSig { public_key: kp.public_key.clone() },
        );
        acc.balance = balance;
        db.put_account(&acc).unwrap();
    }

    /// Seed a matured timelock directly in the DB.
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
        };
        db.put_timelock(&contract).unwrap();
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
        let tx = make_tx(&sender, 0, vec![Action::TimeLockCreate {
            recipient: recipient.public_key.clone(),
            amount: 50 * CHRONOS_PER_KX,
            unlock_at,
            memo: Some("test".into()),
        }]);
        engine.apply(&tx, NOW).unwrap();

        let s = engine.db.get_account(&sender.account_id).unwrap().unwrap();
        assert_eq!(s.balance, 50 * CHRONOS_PER_KX);

        let contract = engine.db.get_timelock(&tx.tx_id).unwrap().unwrap();
        assert_eq!(contract.amount, 50 * CHRONOS_PER_KX);
        assert_eq!(contract.unlock_at, unlock_at);
        assert_eq!(contract.status, TimeLockStatus::Pending);
    }

    #[test]
    fn timelock_create_past_unlock_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("tlc_past")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let tx = make_tx(&sender, 0, vec![Action::TimeLockCreate {
            recipient: recipient.public_key.clone(),
            amount: CHRONOS_PER_KX,
            unlock_at: NOW - 1,
            memo: None,
        }]);
        assert!(matches!(engine.apply(&tx, NOW).unwrap_err(), ChronxError::UnlockTimestampInPast));
    }

    #[test]
    fn timelock_create_zero_amount_rejected() {
        let engine = StateEngine::new(Arc::new(temp_db("tlc_zero")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let tx = make_tx(&sender, 0, vec![Action::TimeLockCreate {
            recipient: recipient.public_key.clone(),
            amount: 0,
            unlock_at: NOW + 86_400,
            memo: None,
        }]);
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
        let target_acc = Account::new(
            target_kp.account_id.clone(),
            AuthPolicy::SingleSig { public_key: target_kp.public_key.clone() },
        );
        engine.db.put_account(&target_acc).unwrap();

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
        let target_acc = Account::new(
            target_kp.account_id.clone(),
            AuthPolicy::SingleSig { public_key: target_kp.public_key.clone() },
        );
        engine.db.put_account(&target_acc).unwrap();

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
        // StartRecovery → RegisterVerifier × 3 → VoteRecovery × 3 → FinalizeRecovery
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

        // 1. StartRecovery
        engine.apply(&make_tx(&requester, 0, vec![Action::StartRecovery {
            target_account: target_kp.account_id.clone(),
            proposed_owner_key: new_owner.public_key.clone(),
            evidence_hash: EvidenceHash([0x01u8; 32]),
            bond_amount: MIN_RECOVERY_BOND_CHRONOS,
        }]), NOW).unwrap();

        // 2. RegisterVerifier × 3
        for v in &verifiers {
            engine.apply(&make_tx(v, 0, vec![Action::RegisterVerifier {
                stake_amount: MIN_VERIFIER_STAKE_CHRONOS,
            }]), NOW).unwrap();
        }

        // 3. VoteRecovery × 3 (approve)
        for v in &verifiers {
            engine.apply(&make_tx(v, 1, vec![Action::VoteRecovery {
                target_account: target_kp.account_id.clone(),
                approve: true,
                fee_bid: 0,
            }]), NOW).unwrap();
        }

        // 4. Fast-forward execute_after to the past
        let mut tgt = engine.db.get_account(&target_kp.account_id).unwrap().unwrap();
        tgt.recovery_state.recovery_execute_after = Some(NOW - 1);
        engine.db.put_account(&tgt).unwrap();

        // 5. FinalizeRecovery
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

    // ── DAG vertex persistence (bug regression) ───────────────────────────────

    /// Build a signed transaction that lists `parents` (difficulty 0 PoW).
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
        };
        let body_bytes = tx.body_bytes();
        // difficulty = 0 means any nonce works; mine_pow returns 0 immediately.
        tx.pow_nonce = mine_pow(&body_bytes, 0);
        tx.tx_id = tx_id_from_body(&body_bytes);
        tx.signatures = vec![kp.sign(&body_bytes)];
        tx
    }

    #[test]
    fn vertex_written_to_db_after_apply() {
        // Regression: apply() must write to the `vertices` tree, not just `dag_tips`.
        let engine = StateEngine::new(Arc::new(temp_db("dag_vertex_persist")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        let tx = make_tx(&sender, 0, vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        engine.apply(&tx, NOW).unwrap();

        // The vertex must now be retrievable from the vertices tree.
        assert!(engine.db.vertex_exists(&tx.tx_id), "vertex not persisted after apply");
        let v = engine.db.get_vertex(&tx.tx_id).unwrap().unwrap();
        assert_eq!(v.depth, 0);
    }

    #[test]
    fn chained_tx_parent_accepted() {
        // Regression: a second tx that references the first as parent must be accepted.
        // Before the fix this always failed with UnknownParent.
        let engine = StateEngine::new(Arc::new(temp_db("dag_chain")), 0);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        seed_account(&engine.db, &sender, 100 * CHRONOS_PER_KX);

        // tx1 — genesis-style (no parents).
        let tx1 = make_tx(&sender, 0, vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        engine.apply(&tx1, NOW).unwrap();

        // tx2 — references tx1 as a parent.
        let tx2 = make_tx_with_parents(&sender, 1, vec![tx1.tx_id.clone()], vec![Action::Transfer {
            to: recipient.account_id.clone(),
            amount: CHRONOS_PER_KX,
        }]);
        engine.apply(&tx2, NOW).unwrap();

        let v2 = engine.db.get_vertex(&tx2.tx_id).unwrap().unwrap();
        assert_eq!(v2.depth, 1, "chained tx depth should be parent_depth + 1");

        let s = engine.db.get_account(&sender.account_id).unwrap().unwrap();
        assert_eq!(s.balance, 98 * CHRONOS_PER_KX);
        assert_eq!(s.nonce, 2);
    }

    #[test]
    fn duplicate_tx_rejected() {
        // Regression: applying the same tx twice must return DuplicateVertex.
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
        assert!(matches!(err, ChronxError::DuplicateVertex(_)), "expected DuplicateVertex, got {err:?}");
    }
}
