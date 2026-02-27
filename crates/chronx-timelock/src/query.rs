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
                format!("For sale — ask {} Chronos (secondary market inactive at V1)", ask_price)
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
