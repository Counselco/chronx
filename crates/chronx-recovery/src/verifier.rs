use chronx_core::constants::MIN_VERIFIER_STAKE_CHRONOS;
use chronx_core::error::ChronxError;
use chronx_core::types::AccountId;
use chronx_state::StateDb;

/// Read-only view over verifier registry state stored in the `StateDb`.
///
/// The canonical source of verifier registration is the `Account` struct
/// (`is_verifier`, `verifier_stake`). This struct provides convenience
/// methods for querying that state without going through the full engine.
pub struct VerifierRegistry<'a> {
    db: &'a StateDb,
}

impl<'a> VerifierRegistry<'a> {
    pub fn new(db: &'a StateDb) -> Self {
        Self { db }
    }

    /// Returns true if `account` is currently a registered verifier.
    pub fn is_registered(&self, account: &AccountId) -> Result<bool, ChronxError> {
        Ok(self
            .db
            .get_account(account)?
            .map(|a| a.is_verifier)
            .unwrap_or(false))
    }

    /// Returns the verifier stake for `account` (0 if not a verifier).
    pub fn stake_of(&self, account: &AccountId) -> Result<u128, ChronxError> {
        Ok(self
            .db
            .get_account(account)?
            .map(|a| a.verifier_stake)
            .unwrap_or(0))
    }

    /// Returns true if `account` meets the minimum stake requirement.
    pub fn meets_stake_requirement(&self, account: &AccountId) -> Result<bool, ChronxError> {
        let stake = self.stake_of(account)?;
        Ok(stake >= MIN_VERIFIER_STAKE_CHRONOS)
    }

    /// Returns the minimum verifier stake in Chronos.
    pub fn min_stake() -> u128 {
        MIN_VERIFIER_STAKE_CHRONOS
    }
}
