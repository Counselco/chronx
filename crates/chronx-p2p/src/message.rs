use chronx_core::types::TxId;
use serde::{Deserialize, Serialize};

/// Messages exchanged over the ChronX P2P gossip network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pMessage {
    /// A peer is broadcasting a new signed vertex.
    /// `payload` is bincode-serialized `Transaction`.
    NewVertex { payload: Vec<u8> },

    /// Request a specific vertex by its TxId (used during sync).
    RequestVertex { tx_id: TxId },

    /// Respond with the current set of DAG tip TxIds.
    SyncTips { tips: Vec<TxId> },

    /// Request to receive the current tip set from a peer.
    RequestTips,
}

impl P2pMessage {
    /// Serialize to bytes for GossipSub propagation.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("P2pMessage serialization is infallible")
    }

    /// Deserialize from GossipSub bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}
