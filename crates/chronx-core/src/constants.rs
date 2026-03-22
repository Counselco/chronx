//! ─── ChronX Protocol Constants ──────────────────────────────────────────────
//!
//! "The ledger for long-horizon human promises."
//!
//! Total supply: 8,270,000,000 KX (≈ human population at genesis design)
//! Base unit:  Chrono (1 KX = 1,000,000 Chronos)
//! Ticker:    KX

// ── Supply ───────────────────────────────────────────────────────────────────

/// Total fixed supply in Chronos. Never changes after genesis.
pub const TOTAL_SUPPLY_CHRONOS: u128 = 8_270_000_000_000_000;

/// 1 KX expressed in Chronos.
pub const CHRONOS_PER_KX: u128 = 1_000_000;

/// Public sale allocation (KX). : 6,090,000,000 KX.
pub const PUBLIC_SALE_KX: u128 = 6_093_000_000;

/// Founder allocation (KX). Spendable at genesis.
// : Founder funded via post-genesis transfer from Public Sale
pub const FOUNDER_KX: u128 = 0;

/// MISAI Bond allocation (KX). Ecosystem bond, spendable at genesis.
// : MISAI Bond funded via post-genesis transfer from Public Sale
pub const MISAI_BOND_KX: u128 = 0;

/// Verifas Bond allocation (KX). Ecosystem bond, spendable at genesis.
// : Verifas Bond funded via post-genesis transfer from Public Sale
pub const VERIFAS_BOND_KX: u128 = 0;

/// Faucet allocation (KX). Spendable at genesis.
// : Faucet funded via post-genesis transfer from Public Sale
pub const FAUCET_KX: u128 = 0;

/// Treasury allocation (KX). Released logarithmically over 100 years.
pub const TREASURY_KX: u128 = 1_000_000_000;

/// Node Rewards allocation (KX). Same harmonic schedule as Treasury (2029-2128).
/// Distribution to operators designed later; for now just locked on schedule.
pub const NODE_REWARDS_KX: u128 = 1_000_000_000;

/// Humanity stake (KX). Locked until Jan 1 2126 00:00:00 UTC (100 years from genesis).
pub const HUMANITY_STAKE_KX: u128 = 1_000_000;

// ── Genesis timestamps (Unix seconds UTC) ────────────────────────────────────

/// Genesis timestamp: 2026-01-01 00:00:00 UTC
pub const GENESIS_TIMESTAMP: i64 = 1_735_689_600;

/// Treasury release begins: 2029-01-01 00:00:00 UTC
pub const TREASURY_START_TIMESTAMP: i64 = 1_861_920_000;

/// Humanity stake unlock: 2126-01-01 00:00:00 UTC — exactly 100 years from genesis.
pub const HUMANITY_UNLOCK_TIMESTAMP: i64 = 4_922_899_200;

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

/// Minimum lock amount (1 grain).
pub const MIN_LOCK_AMOUNT_CHRONOS: u128 = 1;

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

/// Minimum lock duration — 1 second (wallet enforces user-facing minimums).
pub const MIN_LOCK_DURATION_SECS: i64 = 1;

/// Maximum bytes for `lock_marker` fields.
pub const MAX_EXTENSION_DATA_BYTES: usize = 1_024;

/// Maximum recurring payment count (100 years of monthly payments).
pub const MAX_RECURRING_COUNT: u32 = 1_200;

/// Maximum cancellation window — 7 days.
pub const CANCELLATION_WINDOW_MAX_SECS: u32 = 604_800;

/// Auto-set cancellation window for locks >= 1 year — 24 hours.
pub const AUTO_CANCELLATION_WINDOW_SECS: u32 = 86_400;

/// One year in seconds — threshold for automatic cancellation window.
pub const ONE_YEAR_SECS: i64 = 365 * 24 * 3600; // 31_536_000

// ── Genesis timestamps for new locks ─────────────────────────────────────────

/// Milestone 2076 lock unlock: 2076-01-01 00:00:00 UTC
pub const MILESTONE_2076_UNLOCK_TIMESTAMP: i64 = 3_345_062_400;

/// Protocol reserve lock unlock: 2036-01-01 00:00:00 UTC
pub const PROTOCOL_RESERVE_UNLOCK_TIMESTAMP: i64 = 2_082_844_800;

/// Milestone 2076 stake (KX).
pub const MILESTONE_2076_KX: u128 = 500_000;

/// Protocol reserve stake (KX).
pub const PROTOCOL_RESERVE_KX: u128 = 500_000;

// ── MISAI ────────────────────────────────────────────────────────────────────

/// Minimum days remaining until unlock for a promise to be investable.
pub const MISAI_MIN_INVESTMENT_WINDOW_DAYS: u32 = 90;

// ── Harmonic series constant H_100 (used for treasury schedule) ───────────────
/// H_100 = sum(1/k, k=1..100) ≈ 5.187377517639621
/// Scaled by 1_000_000_000_000 for integer arithmetic.
pub const H100_SCALED: u128 = 5_187_377_517_640;
pub const H100_SCALE: u128 = 1_000_000_000_000;

// ── — TYPE I Invoice ─────────────────────────────────────────────

/// Minimum invoice expiry: 1 hour.
pub const INVOICE_MIN_EXPIRY_SECONDS: u64 = 3600;

/// Maximum invoice expiry: 1 year.
pub const INVOICE_MAX_EXPIRY_SECONDS: u64 = 31_536_000;

/// Invoice fee: zero — always free.
pub const INVOICE_FEE_BASIS_POINTS: u64 = 0;

// ── — TYPE C Credit Authorization ────────────────────────────────

/// Minimum credit ceiling: 1 KX.
pub const CREDIT_MIN_CEILING_CHRONOS: u64 = 1_000_000;  // 1 KX minimum

/// Maximum credit expiry: 3 years.
pub const CREDIT_MAX_EXPIRY_SECONDS: u64 = 94_608_000;

/// Credit fee: zero — always free.
pub const CREDIT_FEE_BASIS_POINTS: u64 = 0;

// ── — TYPE Y Interest Bearing Deposit ───────────────────────────

/// Minimum deposit term: 1 day.
pub const DEPOSIT_MIN_TERM_SECONDS: u64 = 86_400;

/// Maximum deposit term: 10 years.
pub const DEPOSIT_MAX_TERM_SECONDS: u64 = 315_360_000;

/// Maximum deposit rate: 1000% (100_000 basis points). Peer-to-peer; no protocol guarantee.
pub const DEPOSIT_MAX_RATE_BASIS_POINTS: u64 = 100_000;

/// Deposit fee: zero — always free.
pub const DEPOSIT_FEE_BASIS_POINTS: u64 = 0;

/// Default grace period after maturity before Defaulted status: 7 days.
pub const DEPOSIT_DEFAULT_GRACE_SECONDS: u64 = 604_800;

// ── — TYPE V Conditional Validity ────────────────────────────────

/// Minimum number of attestors required.
pub const CONDITIONAL_MIN_ATTESTORS: u32 = 1;

/// Maximum number of attestors allowed.
pub const CONDITIONAL_MAX_ATTESTORS: u32 = 10;

/// Conditional payment fee: zero — always free.
pub const CONDITIONAL_FEE_BASIS_POINTS: u64 = 0;

// ── — TYPE L Ledger Entry ────────────────────────────────────────

/// Ledger entry fee: zero — always free.
pub const LEDGER_ENTRY_FEE_BASIS_POINTS: u64 = 0;

/// Maximum content summary size.
pub const LEDGER_MAX_SUMMARY_BYTES: usize = 500;

// ── — Sign of Life ───────────────────────────────────────────────

/// Default interval between sign-of-life attestations: 1 year.
pub const SIGN_OF_LIFE_DEFAULT_INTERVAL_DAYS: u64 = 365;

/// Default grace period after missed sign-of-life: 90 days.
pub const SIGN_OF_LIFE_DEFAULT_GRACE_DAYS: u64 = 90;

/// Minimum sign-of-life interval: 30 days.
pub const SIGN_OF_LIFE_MIN_INTERVAL_DAYS: u64 = 30;

// ── — Promise Chain ──────────────────────────────────────────────

/// Interval between automatic promise chain anchors: 24 hours.
pub const PROMISE_CHAIN_ANCHOR_INTERVAL_SECONDS: u64 = 86_400;

// ═══ GENESIS 9 — TYPE_G Wallet Group ═══════════════════════════════════════
// Protocol ceiling is unlimited — hardware limits today.
// Node software enforces lower practical limits without
// requiring a re-genesis.
pub const WALLET_GROUP_PROTOCOL_MAX_MEMBERS: u64 = u64::MAX;
pub const WALLET_GROUP_PROTOCOL_MAX_PER_OWNER: u64 = u64::MAX;
pub const WALLET_GROUP_NAME_MAX_BYTES: usize = 128;
pub const WALLET_GROUP_FEE_BASIS_POINTS: u64 = 0;

// Inline authorized payers without a named Group.
// Protocol allows up to 255. Node enforces 10 today.
pub const INVOICE_MAX_INLINE_PAYERS: usize = 255;

// Type M AI Lock — backup executor hard ceiling.
// 1 primary + 3 backups = 4 total AI agents maximum.
pub const AI_LOCK_MAX_BACKUP_EXECUTORS: usize = 3;

// ═══ GENESIS 9 — Humanity Stake ════════════════════════════════════════════
//
// "One million KX — set aside not for the builders
// of this protocol, not for those who governed it,
// and not for those who grew wealthy from it —
// but for the world that inherits it.
//
// Beginning one hundred years from the first day
// of 2026, these funds shall be released in a
// measured cadence — patient as the stars,
// unhurried as the tide — into the hands of those
// who stewarded none of this creation and therefore
// owe it nothing.
//
// Those who governed ChronX shall not direct it.
// Those who prospered most from KX shall not claim it.
// It belongs to the future, which cannot yet
// speak for itself.
//
// This is the Humanity Stake: a promise from the
// present to all tomorrows."

// Release begins 100 years from genesis: 2126-01-01
pub const HUMANITY_STAKE_RELEASE_START_TIMESTAMP: u64
    = 4892198400; // 2126-01-01 00:00:00 UTC

// Same harmonic H_100 schedule as Treasury +
// Node Rewards: 100 annual releases 2126-2225
pub const HUMANITY_STAKE_HARMONIC_N: u64 = 100;

// Immutable governance exclusions — forever:
// 1. Any current or former ChronX Foundation
//  governance board member is excluded from
//  directing distribution.
// 2. Any wallet holding MORE than the median KX
//  balance at time of each distribution is
//  excluded from voting.
//  (Bottom half of holders by balance only —
//   scales automatically regardless of KX value.)
pub const HUMANITY_STAKE_EXCLUDES_GOVERNANCE_BOARD:
    bool = true;
pub const HUMANITY_STAKE_EXCLUDES_ABOVE_MEDIAN_HOLDER:
    bool = true;

// No single recipient may receive more than 10%
// of any one release tranche.
pub const HUMANITY_STAKE_MAX_SINGLE_RECIPIENT_PCT:
    u64 = 10;

// Any proposal for distribution must be publicly
// posted for a minimum of 365 days before funds move.
pub const HUMANITY_STAKE_MIN_PROPOSAL_DAYS: u64 = 365;
