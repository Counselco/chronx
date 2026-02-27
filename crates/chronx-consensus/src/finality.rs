use chronx_core::types::{AccountId, TxId};
use chronx_dag::vertex::VertexStatus;
use chronx_state::StateDb;
use std::collections::HashMap;
use tracing::{debug, info};

use crate::validator::ValidatorSet;

/// Emitted when a vertex reaches finality.
#[derive(Debug, Clone)]
pub struct ConfirmationEvent {
    pub tx_id: TxId,
    pub confirming_validator: AccountId,
    pub confirmation_count: u32,
    pub is_final: bool,
}

/// Tracks confirmation votes from validators and upgrades vertex status to Final.
///
/// Each validator sends a signed confirmation message for a vertex.
/// Once a vertex has >= finality_threshold confirmations, it is marked Final
/// in the state DB.
pub struct FinalityTracker {
    /// tx_id → set of validator AccountIds that confirmed it.
    pending: HashMap<TxId, Vec<AccountId>>,
}

impl FinalityTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Record a confirmation from `validator` for `tx_id`.
    ///
    /// Returns a `ConfirmationEvent` describing the outcome.
    /// If the vertex reaches the finality threshold, `is_final = true` and
    /// the vertex status is updated in the DB.
    pub fn record_confirmation(
        &mut self,
        tx_id: TxId,
        validator: AccountId,
        validators: &ValidatorSet,
        db: &StateDb,
    ) -> Option<ConfirmationEvent> {
        // Ignore confirmations from non-validators.
        if !validators.is_validator(&validator) {
            debug!(
                validator = %validator,
                "ignoring confirmation from non-validator"
            );
            return None;
        }

        let confirmations = self.pending.entry(tx_id.clone()).or_default();

        // Deduplicate: each validator may only confirm once per vertex.
        if confirmations.contains(&validator) {
            return None;
        }
        confirmations.push(validator.clone());

        let count = confirmations.len() as u32;
        let threshold = validators.finality_threshold();
        let is_final = count >= threshold;

        if is_final {
            // Mark final in the state DB.
            if let Ok(Some(mut vertex)) = db.get_vertex(&tx_id) {
                vertex.status = VertexStatus::Final;
                vertex.confirmation_count = count;
                let _ = db.put_vertex(&vertex);
                info!(tx_id = %tx_id, confirmations = count, "vertex finalized");
            }
            // Clean up tracking state.
            self.pending.remove(&tx_id);
        }

        Some(ConfirmationEvent {
            tx_id,
            confirming_validator: validator,
            confirmation_count: count,
            is_final,
        })
    }

    /// Number of vertices currently awaiting finality.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

impl Default for FinalityTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::{ValidatorInfo, ValidatorSet};

    fn make_validator_set(n: usize) -> (ValidatorSet, Vec<AccountId>) {
        let mut vs = ValidatorSet::new();
        let mut ids = Vec::new();
        for i in 0..n {
            let id = AccountId::from_bytes([i as u8; 32]);
            vs.add(ValidatorInfo {
                account_id: id.clone(),
                stake: 1_000_000,
                online: true,
                confirmations_issued: 0,
            });
            ids.push(id);
        }
        (vs, ids)
    }

    #[test]
    fn threshold_reached_marks_final() {
        let (vs, ids) = make_validator_set(3);
        // threshold for 3 validators = ceil(2) = 2
        assert_eq!(vs.finality_threshold(), 2);

        let mut tracker = FinalityTracker::new();
        let tx_id = TxId::from_bytes([0xAB; 32]);

        // Use a temp sled DB.
        let dir = std::env::temp_dir().join("chronx_finality_test");
        let db = StateDb::open(&dir).unwrap();

        let e1 = tracker.record_confirmation(tx_id.clone(), ids[0].clone(), &vs, &db).unwrap();
        assert!(!e1.is_final);
        assert_eq!(e1.confirmation_count, 1);

        let e2 = tracker.record_confirmation(tx_id.clone(), ids[1].clone(), &vs, &db).unwrap();
        assert!(e2.is_final);
        assert_eq!(e2.confirmation_count, 2);

        // After finalization, tracker should be cleaned up.
        assert_eq!(tracker.pending_count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_confirmation_ignored() {
        let (vs, ids) = make_validator_set(5);
        let mut tracker = FinalityTracker::new();
        let tx_id = TxId::from_bytes([0xCC; 32]);
        let dir = std::env::temp_dir().join("chronx_dup_test");
        let db = StateDb::open(&dir).unwrap();

        tracker.record_confirmation(tx_id.clone(), ids[0].clone(), &vs, &db);
        let dup = tracker.record_confirmation(tx_id.clone(), ids[0].clone(), &vs, &db);
        assert!(dup.is_none(), "duplicate confirmation should be ignored");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
