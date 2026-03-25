use chronx_core::account::{TimeLockContract, TimeLockStatus};
use chronx_core::error::ChronxError;
use chronx_core::types::{Timestamp, TxId};
use chronx_state::StateDb;

/// Query helpers for time-lock contracts.
pub struct TimeLockQuery<'a> {
    db: &'a StateDb,
}

impl<'a> TimeLockQuery<'a> {
    pub fn new(db: &'a StateDb) -> Self {
        Self { db }
    }

    /// Fetch a single contract by its ID.
    pub fn get(&self, id: &TxId) -> Result<Option<TimeLockContract>, ChronxError> {
        self.db.get_timelock(id)
    }

    /// Returns true if the contract has matured (unlock_at <= now).
    pub fn is_matured(&self, id: &TxId, now: Timestamp) -> Result<bool, ChronxError> {
        match self.db.get_timelock(id)? {
            Some(c) => Ok(now >= c.unlock_at),
            None => Err(ChronxError::TimeLockNotFound(id.to_hex())),
        }
    }

    /// Human-readable summary of a contract's state.
    pub fn describe(&self, id: &TxId, now: Timestamp) -> Result<String, ChronxError> {
        let c = self
            .db
            .get_timelock(id)?
            .ok_or_else(|| ChronxError::TimeLockNotFound(id.to_hex()))?;

        let status_str = match &c.status {
            TimeLockStatus::Pending => {
                let secs_remaining = c.unlock_at - now;
                if secs_remaining > 0 {
                    let days = secs_remaining / 86_400;
                    format!("Pending — unlocks in {} days", days)
                } else {
                    "Pending — matured, ready to claim".to_string()
                }
            }
            TimeLockStatus::Claimed { claimed_at } => {
                format!("Claimed at Unix timestamp {}", claimed_at)
            }
            TimeLockStatus::ForSale { ask_price, .. } => {
                format!(
                    "For sale — ask {} Chronos (secondary market inactive at V1)",
                    ask_price
                )
            }
            TimeLockStatus::Ambiguous { flagged_at } => {
                format!(
                    "Ambiguous — flagged at {} (outcome certificate required)",
                    flagged_at
                )
            }
            TimeLockStatus::ClaimOpen { opened_at } => {
                format!("Claim open since {} — awaiting commit", opened_at)
            }
            TimeLockStatus::ClaimCommitted { committed_at } => {
                format!("Claim committed at {} — awaiting reveal", committed_at)
            }
            TimeLockStatus::ClaimRevealed { revealed_at } => {
                format!("Claim revealed at {} — in challenge window", revealed_at)
            }
            TimeLockStatus::ClaimChallenged { challenged_at } => {
                format!(
                    "Claim challenged at {} — awaiting finalization",
                    challenged_at
                )
            }
            TimeLockStatus::ClaimFinalized {
                paid_to,
                finalized_at,
            } => {
                format!("Claim finalized at {} — paid to {}", finalized_at, paid_to)
            }
            TimeLockStatus::ClaimSlashed { reason, slashed_at } => {
                format!("Claim slashed at {} — reason: {:?}", slashed_at, reason)
            }
            TimeLockStatus::Cancelled { cancelled_at } => {
                format!("Cancelled at Unix timestamp {}", cancelled_at)
            }
            TimeLockStatus::Reverted { reverted_at } => {
                format!("Reverted at Unix timestamp {}", reverted_at)
            }
            TimeLockStatus::PendingExecutor {
                submitted_at,
                finalize_at,
            } => {
                format!(
                    "PendingExecutor — submitted at {}, finalizes at {}",
                    submitted_at, finalize_at
                )
            }
            TimeLockStatus::ExecutorWithdrawn { withdrawn_at } => {
                format!("ExecutorWithdrawn at Unix timestamp {}", withdrawn_at)
            }
            TimeLockStatus::PartiallyReleased { released_chronos, remaining_chronos, release_count } => {
                format!("PartiallyReleased: {} released, {} remaining, {} releases", released_chronos, remaining_chronos, release_count)
            }
            TimeLockStatus::OracleTriggered { price_at_trigger, triggered_at } => {
                format!("OracleTriggered at price {} at Unix timestamp {}", price_at_trigger, triggered_at)
            }
            TimeLockStatus::OracleExpiredClean { expiry_price } => {
                format!("OracleExpiredClean at price {}", expiry_price)
            }
            TimeLockStatus::AttestorFailed { ref failed_group_id, ref escalated_to } => {
                format!("AttestorFailed group={} escalated_to={:?}", failed_group_id, escalated_to)
            }
        };

        Ok(format!(
            "TimeLock {} | {} Chronos | sender: {} | {}",
            &id.to_hex()[..16],
            c.amount,
            c.sender,
            status_str
        ))
    }
}
