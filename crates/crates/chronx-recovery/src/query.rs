use chronx_core::error::ChronxError;
use chronx_core::types::{AccountId, Timestamp};
use chronx_state::StateDb;

/// Query helpers for the recovery state machine.
pub struct RecoveryQuery<'a> {
    db: &'a StateDb,
}

impl<'a> RecoveryQuery<'a> {
    pub fn new(db: &'a StateDb) -> Self {
        Self { db }
    }

    /// Returns true if a recovery is currently active for `account`.
    pub fn is_active(&self, account: &AccountId) -> Result<bool, ChronxError> {
        Ok(self
            .db
            .get_account(account)?
            .map(|a| a.recovery_state.active)
            .unwrap_or(false))
    }

    /// Returns true if the execution delay has elapsed and the recovery
    /// is approved — i.e. it can be finalized now.
    pub fn can_finalize(&self, account: &AccountId, now: Timestamp) -> Result<bool, ChronxError> {
        let acc = self
            .db
            .get_account(account)?
            .ok_or_else(|| ChronxError::UnknownAccount(account.to_string()))?;

        let rs = &acc.recovery_state;
        if !rs.active {
            return Ok(false);
        }
        let delay_elapsed = now >= rs.recovery_execute_after.unwrap_or(i64::MAX);
        let approved = rs.votes_approve.len() >= 3; // mirrors RECOVERY_VERIFIER_THRESHOLD
        Ok(delay_elapsed && approved)
    }

    /// Returns a human-readable status description for an account's recovery.
    pub fn describe(&self, account: &AccountId, now: Timestamp) -> Result<String, ChronxError> {
        let acc = self
            .db
            .get_account(account)?
            .ok_or_else(|| ChronxError::UnknownAccount(account.to_string()))?;

        let rs = &acc.recovery_state;
        if !rs.active {
            return Ok(format!("Account {} — no active recovery", account));
        }

        let execute_after = rs.recovery_execute_after.unwrap_or(0);
        let days_remaining = (execute_after - now).max(0) / 86_400;
        let votes = rs.votes_approve.len();
        let challenge = if rs.challenge_active {
            " [CHALLENGED]"
        } else {
            ""
        };

        Ok(format!(
            "Recovery for {} — {}/{} approvals | {} days until executable{} | decision: {:?}",
            account,
            votes,
            3, // RECOVERY_VERIFIER_THRESHOLD
            days_remaining,
            challenge,
            rs.decision_status
        ))
    }
}
