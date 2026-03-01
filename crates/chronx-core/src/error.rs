use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChronxError {
    // ── Transaction errors ───────────────────────────────────────────────────
    #[error("insufficient balance: need {need} Chronos, have {have}")]
    InsufficientBalance { need: u128, have: u128 },

    #[error("invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid proof-of-work")]
    InvalidPoW,

    #[error("unknown account: {0}")]
    UnknownAccount(String),

    #[error("self-transfer not allowed")]
    SelfTransfer,

    #[error("amount must be greater than zero")]
    ZeroAmount,

    // ── DAG errors ───────────────────────────────────────────────────────────
    #[error("vertex already exists: {0}")]
    DuplicateVertex(String),

    #[error("unknown parent vertex: {0}")]
    UnknownParent(String),

    #[error("too few parents: need at least {min}, got {got}")]
    TooFewParents { min: usize, got: usize },

    #[error("too many parents: max {max}, got {got}")]
    TooManyParents { max: usize, got: usize },

    // ── Time-lock errors ─────────────────────────────────────────────────────
    #[error("time-lock not yet matured (unlocks at {unlock_time})")]
    TimeLockNotMatured { unlock_time: i64 },

    #[error("time-lock already claimed")]
    TimeLockAlreadyClaimed,

    #[error("time-lock not found: {0}")]
    TimeLockNotFound(String),

    #[error("time-lock is irrevocable; cannot cancel after creation")]
    TimeLockIrrevocable,

    #[error("unlock timestamp must be in the future")]
    UnlockTimestampInPast,

    #[error("lock amount below minimum ({min} Chronos required)")]
    LockAmountTooSmall { min: u128 },

    #[error("lock duration too short: minimum {min_secs} seconds")]
    LockDurationTooShort { min_secs: i64 },

    #[error("lock duration too long: maximum {max_years} years")]
    LockDurationTooLong { max_years: u32 },

    #[error("memo exceeds maximum length of {max} bytes")]
    MemoTooLong { max: usize },

    #[error("too many tags: maximum {max} per lock")]
    TooManyTags { max: usize },

    #[error("tag too long: maximum {max} characters")]
    TagTooLong { max: usize },

    #[error("extension_data exceeds maximum size of {max} bytes")]
    ExtensionDataTooLarge { max: usize },

    #[error("cancellation window exceeds maximum of {max} seconds")]
    CancellationWindowTooLong { max: u32 },

    #[error("split policy basis points must sum to 10000; got {got}")]
    SplitPolicyBasisPointsMismatch { got: u32 },

    #[error("recurring count exceeds maximum of {max}")]
    RecurringCountTooLarge { max: u32 },

    #[error("cancellation window has expired")]
    CancellationWindowExpired,

    #[error("only the original sender may cancel a time-lock")]
    CancelNotBySender,

    #[error("transaction has expired (expires_at is in the past)")]
    TransactionExpired,

    // ── Recovery errors ──────────────────────────────────────────────────────
    #[error("recovery already active for account {0}")]
    RecoveryAlreadyActive(String),

    #[error("no active recovery for account {0}")]
    NoActiveRecovery(String),

    #[error("recovery bond below minimum ({min} Chronos required)")]
    RecoveryBondTooLow { min: u128 },

    #[error("challenge bond below minimum ({min} Chronos required)")]
    ChallengeBondTooLow { min: u128 },

    #[error("recovery execution delay not elapsed")]
    RecoveryDelayNotElapsed,

    #[error("recovery challenge window has closed")]
    ChallengeWindowClosed,

    #[error("verifier not registered: {0}")]
    VerifierNotRegistered(String),

    #[error("verifier already voted")]
    VerifierAlreadyVoted,

    #[error("verifier stake below minimum ({min} Chronos required)")]
    VerifierStakeTooLow { min: u128 },

    #[error("recovery not approved by verifiers")]
    RecoveryNotApproved,

    // ── Auth errors ──────────────────────────────────────────────────────────
    #[error("multisig threshold not met: need {need}, got {got}")]
    MultisigThresholdNotMet { need: u32, got: u32 },

    #[error("public key not in multisig set")]
    KeyNotInMultisigSet,

    #[error("duplicate signature in multisig")]
    DuplicateMultisigSignature,

    // ── Serialization / storage ──────────────────────────────────────────────
    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("storage error: {0}")]
    Storage(String),

    // ── Genesis ──────────────────────────────────────────────────────────────
    #[error("genesis supply mismatch: expected {expected}, got {got}")]
    GenesisSupplyMismatch { expected: u128, got: u128 },

    // ── General ──────────────────────────────────────────────────────────────
    #[error("operation not permitted under current auth policy")]
    AuthPolicyViolation,

    #[error("feature not active: {0}")]
    FeatureNotActive(String),

    // ── Claims errors ─────────────────────────────────────────────────────────
    #[error("this lock uses the V2 claims framework; use open_claim instead of timelock_claim")]
    LockRequiresClaimsFramework,

    #[error("claim not found for lock: {0}")]
    ClaimNotFound(String),

    #[error("invalid claim state transition")]
    InvalidClaimStateTransition,

    #[error("reveal hash does not match committed hash")]
    ClaimRevealHashMismatch,

    #[error("reveal window has expired")]
    ClaimRevealWindowExpired,

    #[error("challenge window has expired")]
    ClaimChallengeWindowExpired,

    #[error("challenge window has not yet closed")]
    ClaimChallengeWindowOpen,

    #[error("claim bond below minimum ({min} Chronos required for this lane)")]
    ClaimBondTooLow { min: u128 },

    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    #[error("provider already registered")]
    ProviderAlreadyRegistered,

    #[error("provider is revoked")]
    ProviderRevoked,

    #[error("schema not found: {0}")]
    SchemaNotFound(u64),

    #[error("schema is not active")]
    SchemaNotActive,

    #[error("oracle snapshot not available for pair: {0}")]
    OracleSnapshotUnavailable(String),

    #[error("certificate schema {0} not allowed in this policy/lane")]
    CertificateSchemaNotAllowed(u64),

    #[error("compliance certificate required but not present")]
    ComplianceCertRequired,

    #[error("lock must have claim_policy set to use the claims framework")]
    NoPolicyOnLock,

    #[error("lock is in ambiguous state; an outcome certificate is required")]
    LockAmbiguous,

    #[error("provider registration bond below minimum ({min} Chronos required)")]
    ProviderBondTooLow { min: u128 },

    #[error("schema registration bond below minimum ({min} Chronos required)")]
    SchemaBondTooLow { min: u128 },

    #[error("{0}")]
    Other(String),
}
