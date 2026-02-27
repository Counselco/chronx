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
    pub balance_chronos: String, // u128 as string to avoid JSON precision loss
    pub balance_kx: String,
    pub nonce: u64,
    pub is_verifier: bool,
    pub recovery_active: bool,
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
