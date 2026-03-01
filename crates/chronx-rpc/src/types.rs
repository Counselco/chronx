use serde::{Deserialize, Serialize};

/// P2P network identity returned by `chronx_getNetworkInfo`.
/// The `peer_multiaddr` field is the full libp2p multiaddress (including
/// `/p2p/<PeerId>`) that other nodes should pass as `--bootstrap` to
/// connect to this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNetworkInfo {
    pub peer_multiaddr: String,
}

/// JSON-serializable account summary returned by `chronx_getAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAccount {
    pub account_id: String,
    /// Total balance including verifier stake (u128 as string).
    pub balance_chronos: String,
    pub balance_kx: String,
    /// Spendable = balance - verifier_stake (u128 as string).
    pub spendable_chronos: String,
    pub spendable_kx: String,
    /// Sum of sender's Pending time-lock amounts (u128 as string).
    pub locked_chronos: String,
    pub locked_kx: String,
    /// Amount staked as verifier collateral (u128 as string).
    pub verifier_stake_chronos: String,
    pub nonce: u64,
    pub is_verifier: bool,
    pub recovery_active: bool,
    /// Approximate DAG tip depth (chain height proxy).
    pub tip_height: u64,
    // ── Cached lock counters (added in V3) ────────────────────────────────
    pub account_version: u16,
    pub created_at: Option<i64>,
    pub incoming_locks_count: u32,
    pub outgoing_locks_count: u32,
    /// Sum of pending incoming chronos (u128 as string).
    pub incoming_locked_chronos: String,
    /// Sum of pending outgoing chronos (u128 as string).
    pub outgoing_locked_chronos: String,
}

/// JSON-serializable time-lock summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTimeLock {
    pub lock_id: String,
    pub sender: String,
    pub recipient_account_id: String,
    pub amount_chronos: String,
    pub amount_kx: String,
    pub unlock_at: i64,
    pub created_at: i64,
    pub status: String,
    pub memo: Option<String>,
    // ── V3 optional metadata ──────────────────────────────────────────────
    pub tags: Option<Vec<String>>,
    pub private: bool,
    pub lock_version: u16,
}

/// Protocol constants returned by `chronx_getGenesisInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcGenesisInfo {
    pub protocol: String,
    pub ticker: String,
    pub base_unit: String,
    pub chronos_per_kx: u64,
    pub total_supply_kx: String,
    pub genesis_timestamp: i64,
    pub treasury_start: i64,
    pub humanity_unlock: i64,
    pub pow_difficulty: u8,
}

impl RpcGenesisInfo {
    pub fn current(pow_difficulty: u8) -> Self {
        use chronx_core::constants::*;
        Self {
            protocol: "ChronX".into(),
            ticker: "KX".into(),
            base_unit: "Chrono".into(),
            chronos_per_kx: CHRONOS_PER_KX as u64,
            total_supply_kx: (TOTAL_SUPPLY_CHRONOS / CHRONOS_PER_KX).to_string(),
            genesis_timestamp: GENESIS_TIMESTAMP,
            treasury_start: TREASURY_START_TIMESTAMP,
            humanity_unlock: HUMANITY_UNLOCK_TIMESTAMP,
            pow_difficulty,
        }
    }
}

// ── V2 Claims RPC types ───────────────────────────────────────────────────────

/// JSON summary of a registered provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcProvider {
    pub provider_id: String,
    pub provider_class: String,
    pub jurisdictions: Vec<String>,
    pub status: String,
    pub registered_at: i64,
}

/// JSON summary of a certificate schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcSchema {
    pub schema_id: u64,
    pub name: String,
    pub version: u32,
    pub active: bool,
    pub registered_at: i64,
}

/// JSON summary of a ClaimState.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcClaimState {
    pub lock_id: String,
    pub lane: u8,
    pub v_claim_usd_cents: u64,
    pub opened_at: i64,
    pub agent_id: Option<String>,
    pub status: String,
}

/// JSON oracle snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcOracleSnapshot {
    pub pair: String,
    pub price_cents: u64,
    pub num_submissions: u32,
    pub updated_at: i64,
}

// ── V3 New RPC types ─────────────────────────────────────────────────────────

/// On-chain statistics summary returned by `chronx_getChainStats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcChainStats {
    pub total_accounts: u64,
    pub total_timelocks: u64,
    pub total_vertices: u64,
    pub dag_tip_count: u64,
    pub dag_depth: u64,
    pub total_supply_chronos: String,
    pub total_supply_kx: String,
}

/// Node / protocol version information returned by `chronx_getVersion`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcVersionInfo {
    pub node_version: String,
    pub protocol_version: String,
    pub api_version: String,
}

/// A lightweight recent-transaction summary returned by `chronx_getRecentTransactions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRecentTx {
    pub tx_id: String,
    pub timestamp: i64,
    pub from: String,
    pub action_count: usize,
    pub depth: u64,
}

/// Query object for `chronx_searchLocks`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcSearchQuery {
    /// Base-58 account that must appear as sender OR recipient.
    pub account_id: String,
    /// Optional status filter: "Pending", "Claimed", "Cancelled", etc.
    pub status: Option<String>,
    /// If provided, all specified tags must be present on the lock.
    pub tags: Option<Vec<String>>,
    /// Minimum `unlock_at` (inclusive).
    pub unlock_from: Option<i64>,
    /// Maximum `unlock_at` (inclusive).
    pub unlock_to: Option<i64>,
    /// Number of results to skip (default 0).
    pub offset: Option<u32>,
    /// Maximum results to return (default 50, max 200).
    pub limit: Option<u32>,
}
