use chronx_core::constants::RECOVERY_VERIFIER_THRESHOLD;
use chronx_core::error::ChronxError;
use chronx_core::types::{AccountId, Balance};
use chronx_state::StateDb;

/// Distribute the recovery bond to winning verifiers on finalization.
///
/// The bond is split equally among the `winning_verifiers` who voted on the
/// correct side. Any rounding remainder goes to the first verifier.
///
/// # Arguments
/// * `db` - mutable reference to the state database
/// * `bond` - total bond amount in Chronos to distribute
/// * `winning_verifiers` - accounts that voted correctly (must be non-empty)
///
/// # Errors
/// Returns `ChronxError::UnknownAccount` if any verifier account is missing.
pub fn distribute_recovery_fees(
    db: &StateDb,
    bond: Balance,
    winning_verifiers: &[AccountId],
) -> Result<(), ChronxError> {
    if winning_verifiers.is_empty() {
        return Ok(());
    }

    let n = winning_verifiers.len() as u128;
    let share = bond / n;
    let remainder = bond - share * n;

    for (i, verifier_id) in winning_verifiers.iter().enumerate() {
        let mut acc = db
            .get_account(verifier_id)?
            .ok_or_else(|| ChronxError::UnknownAccount(verifier_id.to_string()))?;

        let payout = if i == 0 { share + remainder } else { share };
        acc.balance = acc.balance.saturating_add(payout);
        db.put_account(&acc)?;
    }

    Ok(())
}

/// Returns the minimum number of verifier votes required for approval.
/// This mirrors `RECOVERY_VERIFIER_THRESHOLD` from the protocol constants.
pub fn required_votes() -> u32 {
    RECOVERY_VERIFIER_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_votes_is_threshold() {
        assert_eq!(required_votes(), 3);
    }
}
