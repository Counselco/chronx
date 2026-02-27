use serde::{Deserialize, Serialize};

use crate::types::{
    AccountId, Balance, DilithiumPublicKey, EvidenceHash, Nonce, Timestamp, TxId,
};

// ── AuthPolicy ────────────────────────────────────────────────────────────────

/// Defines how an account authenticates outgoing transactions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AuthPolicy {
    /// One Dilithium2 key, one signature required.
    SingleSig {
        public_key: DilithiumPublicKey,
    },

    /// k-of-n Dilithium2 multisig.
    MultiSig {
        threshold: u32,
        public_keys: Vec<DilithiumPublicKey>,
    },

    /// Owner key with protocol-level recovery capability.
    RecoveryEnabled {
        owner_key: DilithiumPublicKey,
        recovery_config: RecoveryConfig,
    },
}

/// Configuration for a RecoveryEnabled account.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RecoveryConfig {
    /// Custom execution delay override (None = protocol default).
    pub execution_delay_override: Option<i64>,
    /// Whether post-recovery spending restrictions are active.
    pub post_recovery_restrictions: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            execution_delay_override: None,
            post_recovery_restrictions: true,
        }
    }
}

// ── RecoveryState ─────────────────────────────────────────────────────────────

/// The state of an in-flight or completed recovery for one account.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum RecoveryDecisionStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RecoveryState {
    pub active: bool,
    pub proposed_owner_key: Option<DilithiumPublicKey>,
    pub recovery_start_time: Option<Timestamp>,
    pub recovery_execute_after: Option<Timestamp>,
    pub recovery_bond: Balance,
    pub challenge_bond: Balance,
    pub decision_status: RecoveryDecisionStatus,
    pub evidence_hash: Option<EvidenceHash>,
    pub counter_evidence_hash: Option<EvidenceHash>,
    /// TxIds of verifier votes received.
    pub votes_approve: Vec<TxId>,
    pub votes_reject: Vec<TxId>,
    /// Whether a challenge is active.
    pub challenge_active: bool,
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            active: false,
            proposed_owner_key: None,
            recovery_start_time: None,
            recovery_execute_after: None,
            recovery_bond: 0,
            challenge_bond: 0,
            decision_status: RecoveryDecisionStatus::Pending,
            evidence_hash: None,
            counter_evidence_hash: None,
            votes_approve: Vec::new(),
            votes_reject: Vec::new(),
            challenge_active: false,
        }
    }
}

// ── PostRecoveryRestriction ───────────────────────────────────────────────────

/// Temporary spending limits imposed after a recovery finalizes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PostRecoveryRestriction {
    /// Restriction expires at this timestamp.
    pub expires_at: Timestamp,
    /// Maximum Chronos transferable per day.
    pub daily_limit_chronos: Balance,
    /// Chronos transferred in the current UTC day.
    pub transferred_today: Balance,
    /// UTC date of last transfer (YYYY-MM-DD as days since epoch for simplicity).
    pub last_transfer_day: i32,
}

// ── Account ───────────────────────────────────────────────────────────────────

/// Full on-chain account state as stored in the state DB.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub account_id: AccountId,
    pub balance: Balance,
    pub auth_policy: AuthPolicy,
    pub nonce: Nonce,
    pub recovery_state: RecoveryState,
    pub post_recovery_restriction: Option<PostRecoveryRestriction>,
    /// Amount staked as verifier collateral (0 if not a verifier).
    pub verifier_stake: Balance,
    /// Whether this account is a registered recovery verifier.
    pub is_verifier: bool,
}

impl Account {
    pub fn new(account_id: AccountId, auth_policy: AuthPolicy) -> Self {
        Self {
            account_id,
            balance: 0,
            auth_policy,
            nonce: 0,
            recovery_state: RecoveryState::default(),
            post_recovery_restriction: None,
            verifier_stake: 0,
            is_verifier: false,
        }
    }

    /// Available spendable balance (total minus verifier stake).
    pub fn spendable_balance(&self) -> Balance {
        self.balance.saturating_sub(self.verifier_stake)
    }
}

// ── TimeLockContract ──────────────────────────────────────────────────────────

/// Status of a time-lock contract.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TimeLockStatus {
    /// Locked, awaiting unlock timestamp.
    Pending,
    /// Claimed by recipient after maturity.
    Claimed { claimed_at: Timestamp },
    /// Listed for secondary market sale (V1: scaffold only, not executable).
    ForSale { ask_price: Balance, listed_at: Timestamp },
}

/// A time-lock contract stored in the state DB.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeLockContract {
    pub id: TxId,
    pub sender: AccountId,
    /// Recipient's Dilithium2 public key (pre-registered at creation time).
    pub recipient_key: DilithiumPublicKey,
    /// Derived AccountId from recipient_key.
    pub recipient_account_id: AccountId,
    pub amount: Balance,
    /// Unlock timestamp (UTC Unix seconds).
    pub unlock_at: Timestamp,
    pub created_at: Timestamp,
    pub status: TimeLockStatus,
    /// Optional human-readable memo.
    pub memo: Option<String>,
}
