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

    #[error("{0}")]
    Other(String),
}
