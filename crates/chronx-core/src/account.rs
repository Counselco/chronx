use serde::{Deserialize, Serialize};

use crate::types::{
    AccountId, Balance, DilithiumPublicKey, EvidenceHash, Nonce, Timestamp, TxId,
};

// ── Serde default helpers ──────────────────────────────────────────────────────

fn default_true() -> bool { true }
fn default_account_version() -> u16 { 1 }
fn default_lock_version_one() -> u16 { 1 }

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

    // ── V3 extensibility fields (serde(default) for backward compat) ─────────
    /// Account struct version. 1 = current.
    #[serde(default = "default_account_version")]
    pub account_version: u16,
    /// Unix timestamp of the first transaction involving this account.
    #[serde(default)]
    pub created_at: Option<i64>,
    /// Blake3 commitment to a human-readable name (not stored in plaintext).
    #[serde(default)]
    pub display_name_hash: Option<[u8; 32]>,
    /// Cached count of pending incoming time-locks (recipient = this account).
    #[serde(default)]
    pub incoming_locks_count: u32,
    /// Cached count of pending outgoing time-locks (sender = this account).
    #[serde(default)]
    pub outgoing_locks_count: u32,
    /// Cached sum of pending incoming lock amounts (Chronos).
    #[serde(default)]
    pub total_locked_incoming_chronos: u128,
    /// Cached sum of pending outgoing lock amounts (Chronos).
    #[serde(default)]
    pub total_locked_outgoing_chronos: u128,
    /// Preferred fiat currency for lane selection hint (e.g. "USD", "EUR").
    #[serde(default)]
    pub preferred_fiat_currency: Option<String>,
    /// Reserved for future protocol extensions. Ignored by current nodes.
    #[serde(default)]
    pub extension_data: Option<Vec<u8>>,
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
            account_version: 1,
            created_at: None,
            display_name_hash: None,
            incoming_locks_count: 0,
            outgoing_locks_count: 0,
            total_locked_incoming_chronos: 0,
            total_locked_outgoing_chronos: 0,
            preferred_fiat_currency: None,
            extension_data: None,
        }
    }

    /// Available spendable balance (total minus verifier stake).
    pub fn spendable_balance(&self) -> Balance {
        self.balance.saturating_sub(self.verifier_stake)
    }
}

// ── Extensibility enums ───────────────────────────────────────────────────────

/// What happens to lock funds if the beneficiary never claims after the grace period.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ExpiryPolicy {
    /// Return the locked funds to the original sender.
    ReturnToSender,
    /// Send funds to the protocol null address (burn).
    Burn,
    /// Redirect to a specified fallback account.
    RedirectTo(AccountId),
}

/// Recurring schedule for future repeating locks (scaffold, inactive in V1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum RecurringPolicy {
    None,
    Weekly  { count: u32 },
    Monthly { count: u32 },
    Annual  { count: u32 },
}

/// Future multi-recipient split lock (scaffold, inactive in V1).
/// `recipients` is a list of (AccountId, basis_points); values must sum to 10000.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SplitPolicy {
    pub recipients: Vec<(AccountId, u16)>,
}

// ── TimeLockContract ──────────────────────────────────────────────────────────

/// Status of a time-lock contract.
///
/// V0 locks use Pending → Claimed directly.
/// V1 locks (claim_policy set) use the claims state machine:
///   Pending → ClaimOpen → ClaimCommitted → ClaimRevealed
///           → ClaimFinalized | ClaimSlashed
/// Ambiguous path: Pending → Ambiguous → ClaimOpen (or ClaimSlashed on timeout).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TimeLockStatus {
    // ── V0 / Legacy ──────────────────────────────────────────────────────────
    /// Locked, awaiting unlock timestamp.
    Pending,
    /// Claimed directly by recipient after maturity (V0 path).
    Claimed { claimed_at: Timestamp },
    /// Listed for secondary market sale (scaffold, not active in V1).
    ForSale { ask_price: Balance, listed_at: Timestamp },

    // ── V2 Claims State Machine ───────────────────────────────────────────────
    /// Lock matured but no unique identifier found; waiting for outcome cert.
    Ambiguous { flagged_at: Timestamp },
    /// `open_claim` submitted; V_claim and lane are fixed in ClaimState.
    ClaimOpen { opened_at: Timestamp },
    /// Agent committed a hash + bond.
    ClaimCommitted { committed_at: Timestamp },
    /// Agent revealed payload + certificates.
    ClaimRevealed { revealed_at: Timestamp },
    /// Challenger contested the reveal; awaiting finalization.
    ClaimChallenged { challenged_at: Timestamp },
    /// Claim resolved; funds sent to beneficiary.
    ClaimFinalized { paid_to: AccountId, finalized_at: Timestamp },
    /// Claim was slashed.
    ClaimSlashed { reason: crate::claims::SlashReason, slashed_at: Timestamp },
    /// Lock was cancelled by sender within the cancellation window.
    Cancelled { cancelled_at: Timestamp },
}

impl TimeLockStatus {
    /// True if the lock is in a terminal state (no further transitions possible).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TimeLockStatus::Claimed { .. }
            | TimeLockStatus::ClaimFinalized { .. }
            | TimeLockStatus::ClaimSlashed { .. }
            | TimeLockStatus::Cancelled { .. }
        )
    }
}

/// A time-lock contract stored in the state DB.
///
/// V0 compatibility: all V2 fields use `#[serde(default)]` so that
/// previously serialized records deserialize correctly with None/0 defaults.
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

    // ── V2 Claims fields (serde(default) for backward compatibility) ──────────
    /// Schema version: 0 = V0 legacy, 1 = V2 claims framework.
    #[serde(default)]
    pub lock_version: u16,
    /// Reference to an on-chain ClaimPolicy (None → V0 direct-claim path).
    #[serde(default)]
    pub claim_policy: Option<crate::claims::PolicyId>,
    /// Commitment to beneficiary identity (e.g. Blake3 of name + DOB + national ID hash).
    /// Disambiguates between multiple possible recipients.
    #[serde(default)]
    pub beneficiary_anchor_commitment: Option<[u8; 32]>,
    /// Organisation identifier string (max 256 bytes).
    /// Used for org-directed locks; triggers ambiguity mode if absent.
    #[serde(default)]
    pub org_identifier: Option<String>,

    // ── V3 extensibility fields ───────────────────────────────────────────────
    /// Seconds after creation in which the sender may cancel. None = irrevocable.
    #[serde(default)]
    pub cancellation_window_secs: Option<u32>,
    /// Flag for off-chain notification systems; does not affect consensus.
    #[serde(default = "default_true")]
    pub notify_recipient: bool,
    /// User-defined labels (max 5, max 32 chars each).
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// If true, memo and amount should be hidden from public block explorers.
    #[serde(default)]
    pub private: bool,
    /// What happens to funds if the lock expires unclaimed.
    #[serde(default)]
    pub expiry_policy: Option<ExpiryPolicy>,
    /// Future multi-recipient split (scaffold, inactive in V1).
    #[serde(default)]
    pub split_policy: Option<SplitPolicy>,
    /// Maximum failed claim attempts before Ambiguous mode. None = unlimited.
    #[serde(default)]
    pub claim_attempts_max: Option<u8>,
    /// Recurring lock schedule (scaffold, inactive in V1).
    #[serde(default)]
    pub recurring: Option<RecurringPolicy>,
    /// Raw bytes reserved for future protocol extensions. Ignored by current nodes.
    #[serde(default)]
    pub extension_data: Option<Vec<u8>>,
    /// Suggested fiat currency for value oracle at claim time (e.g. "USD").
    #[serde(default)]
    pub oracle_hint: Option<String>,
    /// ISO country code hint for lane selection (e.g. "US").
    #[serde(default)]
    pub jurisdiction_hint: Option<String>,
    /// Optional link to a governance proposal ID.
    #[serde(default)]
    pub governance_proposal_id: Option<String>,
    /// Client-side reference ID for deduplication (16 bytes, opaque).
    #[serde(default)]
    pub client_ref: Option<[u8; 16]>,
}
