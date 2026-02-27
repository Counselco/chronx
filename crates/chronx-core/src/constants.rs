/// ─── ChronX Protocol Constants ──────────────────────────────────────────────
///
/// "The ledger for long-horizon human promises."
///
/// Total supply: 8,270,000,000 KX  (≈ human population at genesis design)
/// Base unit:    Chrono  (1 KX = 1,000,000 Chronos)
/// Ticker:       KX

// ── Supply ───────────────────────────────────────────────────────────────────

/// Total fixed supply in Chronos. Never changes after genesis.
pub const TOTAL_SUPPLY_CHRONOS: u128 = 8_270_000_000_000_000;

/// 1 KX expressed in Chronos.
pub const CHRONOS_PER_KX: u128 = 1_000_000;

/// Public sale allocation (KX). Distributed by Dec 31 2026 midnight GMT.
pub const PUBLIC_SALE_KX: u128 = 7_269_000_000;

/// Treasury allocation (KX). Released logarithmically over 100 years.
pub const TREASURY_KX: u128 = 1_000_000_000;

/// Humanity stake (KX). Locked until Jan 1 2127 00:00:00 UTC.
pub const HUMANITY_STAKE_KX: u128 = 1_000_000;

// ── Genesis timestamps (Unix seconds UTC) ────────────────────────────────────

/// Public sale close / genesis reference point: 2026-12-31 23:59:59 UTC
pub const GENESIS_TIMESTAMP: i64 = 1_798_761_599;

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

// ── Harmonic series constant H_100 (used for treasury schedule) ───────────────
/// H_100 = sum(1/k, k=1..100) ≈ 5.187377517639621
/// Scaled by 1_000_000_000_000 for integer arithmetic.
pub const H100_SCALED: u128 = 5_187_377_517_640;
pub const H100_SCALE: u128 = 1_000_000_000_000;
