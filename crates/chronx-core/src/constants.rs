//! ─── ChronX Protocol Constants ──────────────────────────────────────────────
//!
//! "The ledger for long-horizon human promises."
//!
//! Total supply: 8,270,000,000 KX  (≈ human population at genesis design)
//! Base unit:    Chrono  (1 KX = 1,000,000 Chronos)
//! Ticker:       KX

// ── Supply ───────────────────────────────────────────────────────────────────

/// Total fixed supply in Chronos. Never changes after genesis.
pub const TOTAL_SUPPLY_CHRONOS: u128 = 8_270_000_000_000_000;

/// 1 KX expressed in Chronos.
pub const CHRONOS_PER_KX: u128 = 1_000_000;

/// Public sale allocation (KX). 7,268,000,000 after 1,000,000 KX redirected to
/// milestone 2076 lock and protocol reserve lock (see genesis).
pub const PUBLIC_SALE_KX: u128 = 7_268_000_000;

/// Treasury allocation (KX). Released logarithmically over 100 years.
pub const TREASURY_KX: u128 = 1_000_000_000;

/// Humanity stake (KX). Locked until Jan 1 2127 00:00:00 UTC.
pub const HUMANITY_STAKE_KX: u128 = 1_000_000;

// ── Genesis timestamps (Unix seconds UTC) ────────────────────────────────────

/// Genesis timestamp: 2026-01-01 00:00:00 UTC
pub const GENESIS_TIMESTAMP: i64 = 1_735_689_600;

/// Treasury release begins: 2029-01-01 00:00:00 UTC
pub const TREASURY_START_TIMESTAMP: i64 = 1_861_920_000;

/// Humanity stake unlock: 2127-01-01 00:00:00 UTC
/// Treasury Release #99 also falls on this date — intentional alignment.
pub const HUMANITY_UNLOCK_TIMESTAMP: i64 = 4_953_081_600;

/// Final treasury release: 2128-01-01 00:00:00 UTC
pub const TREASURY_FINAL_TIMESTAMP: i64 = 4_984_704_000;

/// Number of treasury releases (one per year, Jan 1).
pub const TREASURY_RELEASE_COUNT: u32 = 100;

// ── Proof-of-Work ─────────────────────────────────────────────────────────────

/// Target PoW difficulty: leading zero bits required in SHA3-256 hash of nonce.
/// Adjusts dynamically; this is the genesis default (~10 second solve time).
pub const POW_INITIAL_DIFFICULTY: u8 = 20;

pub const POW_MIN_DIFFICULTY: u8 = 16;
pub const POW_MAX_DIFFICULTY: u8 = 32;

// ── DAG / Consensus ───────────────────────────────────────────────────────────

/// Minimum parent references per non-genesis vertex.
pub const DAG_MIN_PARENTS: usize = 1;

/// Maximum parent references per vertex.
pub const DAG_MAX_PARENTS: usize = 8;

/// Fraction of validators required for finality (numerator / denominator).
pub const FINALITY_THRESHOLD_NUM: u64 = 2;
pub const FINALITY_THRESHOLD_DEN: u64 = 3;

// ── Recovery protocol ─────────────────────────────────────────────────────────

/// Delay before a recovery can be finalized (seconds). Default: 180 days.
pub const RECOVERY_EXECUTION_DELAY_SECS: i64 = 180 * 24 * 3600;

/// Window during which a recovery can be challenged (seconds). Default: 120 days.
pub const RECOVERY_CHALLENGE_WINDOW_SECS: i64 = 120 * 24 * 3600;

/// Default verifier threshold: 3-of-5.
pub const RECOVERY_VERIFIER_THRESHOLD: u32 = 3;
pub const RECOVERY_VERIFIER_TOTAL: u32 = 5;

/// Minimum bond to initiate recovery (Chronos).
pub const MIN_RECOVERY_BOND_CHRONOS: u128 = 100_000_000; // 100 KX

/// Minimum bond to challenge a recovery (Chronos).
pub const MIN_CHALLENGE_BOND_CHRONOS: u128 = 100_000_000; // 100 KX

/// Minimum stake to register as a verifier (Chronos).
pub const MIN_VERIFIER_STAKE_CHRONOS: u128 = 1_000_000_000; // 1000 KX

/// Post-recovery restriction period (seconds). Default: 30 days.
pub const POST_RECOVERY_RESTRICTION_SECS: i64 = 30 * 24 * 3600;

// ── Governance ────────────────────────────────────────────────────────────────

/// Minimum bond to submit a governance proposal (Chronos).
pub const GOVERNANCE_PROPOSAL_BOND_CHRONOS: u128 = 10_000_000_000_000; // 10M KX

/// Governance voting window (seconds). Default: 14 days.
pub const GOVERNANCE_VOTING_WINDOW_SECS: i64 = 14 * 24 * 3600;

/// Governance quorum: 60% of circulating supply must vote.
pub const GOVERNANCE_QUORUM_PERCENT: u64 = 60;

// ── V2 Claims framework ───────────────────────────────────────────────────────

/// Minimum bond to register as a certificate provider (Chronos).
pub const PROVIDER_BOND_CHRONOS: u128 = 10_000_000_000; // 10,000 KX

/// Minimum bond to register a certificate schema (Chronos).
pub const SCHEMA_BOND_CHRONOS: u128 = 1_000_000_000; // 1,000 KX

/// Age threshold for oracle submissions to be included in a snapshot (seconds).
pub const ORACLE_MAX_AGE_SECS: i64 = 3_600; // 1 hour

/// Minimum oracle submissions needed before a snapshot is valid.
pub const ORACLE_MIN_SUBMISSIONS: usize = 3;

/// Duration after a lock matures before the claim state machine can be opened
/// (the "grace window" where a direct claim is still allowed via TimeLockClaim).
/// After this window, V0 locks can still be claimed directly; V1 locks must use OpenClaim.
pub const UNLOCK_GRACE_SECS: i64 = 7 * 24 * 3600; // 7 days

// ── V3 Lock / Transaction validation ─────────────────────────────────────────

/// Minimum lock amount (1 KX).
pub const MIN_LOCK_AMOUNT_CHRONOS: u128 = 1_000_000;

/// Maximum memo size in bytes (enforced at consensus level).
pub const MAX_MEMO_BYTES: usize = 256;

/// Maximum number of tags per lock.
pub const MAX_TAGS_PER_LOCK: usize = 5;

/// Maximum length of each individual tag (characters).
pub const MAX_TAG_LENGTH: usize = 32;

/// Maximum locks returned in a single RPC query (pagination cap).
pub const MAX_LOCKS_PER_QUERY: usize = 100;

/// Default cancellation window — irrevocable by default.
pub const DEFAULT_CANCELLATION_WINDOW_SECS: u32 = 0;

/// Maximum years a lock may be held (~2226 from genesis).
pub const MAX_LOCK_DURATION_YEARS: u32 = 200;

/// Minimum lock duration — at least 1 hour.
pub const MIN_LOCK_DURATION_SECS: i64 = 3_600;

/// Maximum bytes for `extension_data` fields.
pub const MAX_EXTENSION_DATA_BYTES: usize = 1_024;

/// Maximum recurring payment count (100 years of monthly payments).
pub const MAX_RECURRING_COUNT: u32 = 1_200;

/// Maximum cancellation window — 24 hours.
pub const CANCELLATION_WINDOW_MAX_SECS: u32 = 86_400;

// ── Genesis timestamps for new locks ─────────────────────────────────────────

/// Milestone 2076 lock unlock: 2076-01-01 00:00:00 UTC
pub const MILESTONE_2076_UNLOCK_TIMESTAMP: i64 = 3_345_062_400;

/// Protocol reserve lock unlock: 2036-01-01 00:00:00 UTC
pub const PROTOCOL_RESERVE_UNLOCK_TIMESTAMP: i64 = 2_082_844_800;

/// Milestone 2076 stake (KX).
pub const MILESTONE_2076_KX: u128 = 500_000;

/// Protocol reserve stake (KX).
pub const PROTOCOL_RESERVE_KX: u128 = 500_000;

// ── Harmonic series constant H_100 (used for treasury schedule) ───────────────
/// H_100 = sum(1/k, k=1..100) ≈ 5.187377517639621
/// Scaled by 1_000_000_000_000 for integer arithmetic.
pub const H100_SCALED: u128 = 5_187_377_517_640;
pub const H100_SCALE: u128 = 1_000_000_000_000;
