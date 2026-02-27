use chronx_core::types::{AccountId, Balance};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Information about a single active validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub account_id: AccountId,
    /// Total KX staked (determines governance weight and validator rank).
    pub stake: Balance,
    /// Whether this validator is currently online (updated via P2P heartbeats).
    pub online: bool,
    /// Number of vertices this validator has confirmed.
    pub confirmations_issued: u64,
}

/// The active validator set for the current epoch.
///
/// Validators are the top-N staked accounts that have opted in.
/// They confirm vertices; 2/3 confirmations = finality.
#[derive(Debug, Clone, Default)]
pub struct ValidatorSet {
    validators: HashMap<AccountId, ValidatorInfo>,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, info: ValidatorInfo) {
        self.validators.insert(info.account_id.clone(), info);
    }

    pub fn remove(&mut self, id: &AccountId) {
        self.validators.remove(id);
    }

    pub fn get(&self, id: &AccountId) -> Option<&ValidatorInfo> {
        self.validators.get(id)
    }

    pub fn is_validator(&self, id: &AccountId) -> bool {
        self.validators.contains_key(id)
    }

    pub fn active_count(&self) -> usize {
        self.validators.values().filter(|v| v.online).count()
    }

    pub fn total_count(&self) -> usize {
        self.validators.len()
    }

    /// Finality threshold: ceil(2/3 * active_count).
    pub fn finality_threshold(&self) -> u32 {
        let active = self.active_count() as u32;
        // ceil(2n/3) = (2n + 2) / 3
        (2 * active + 2) / 3
    }

    /// Mark a validator as online/offline.
    pub fn set_online(&mut self, id: &AccountId, online: bool) {
        if let Some(v) = self.validators.get_mut(id) {
            v.online = online;
        }
    }

    /// Return validators sorted by stake descending.
    pub fn ranked(&self) -> Vec<&ValidatorInfo> {
        let mut list: Vec<_> = self.validators.values().collect();
        list.sort_by(|a, b| b.stake.cmp(&a.stake));
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(stake: Balance) -> ValidatorInfo {
        ValidatorInfo {
            account_id: AccountId::from_bytes([stake as u8; 32]),
            stake,
            online: true,
            confirmations_issued: 0,
        }
    }

    #[test]
    fn finality_threshold_two_thirds() {
        let mut vs = ValidatorSet::new();
        for i in 1u128..=9 {
            vs.add(make_validator(i));
        }
        // 9 active validators → threshold = ceil(6) = 6
        assert_eq!(vs.finality_threshold(), 6);
    }

    #[test]
    fn ranked_by_stake() {
        let mut vs = ValidatorSet::new();
        vs.add(make_validator(100));
        vs.add(make_validator(500));
        vs.add(make_validator(250));
        let ranked = vs.ranked();
        assert_eq!(ranked[0].stake, 500);
        assert_eq!(ranked[1].stake, 250);
        assert_eq!(ranked[2].stake, 100);
    }
}
