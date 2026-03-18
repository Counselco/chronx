use chronx_core::transaction::Transaction;
use chronx_core::types::{Timestamp, TxId};
use serde::{Deserialize, Serialize};

/// Finality status of a vertex in the DAG.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VertexStatus {
    /// Received but not yet confirmed by validators.
    Pending,
    /// Confirmed by >= 2/3 of active validators.
    Final,
    /// Rejected by consensus (invalid PoW, bad sig, etc.).
    Rejected { reason: String },
}

/// A vertex in the ChronX DAG.
///
/// Each vertex wraps one `Transaction` and carries DAG-level metadata.
/// The genesis vertex has no parents (`parents` is empty) and is the only
/// such vertex in the entire DAG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vertex {
    /// The transaction payload.
    pub transaction: Transaction,

    /// Depth in the DAG (genesis = 0, each subsequent generation increments).
    pub depth: u64,

    /// When this vertex was first seen by the local node (UTC Unix seconds).
    pub received_at: Timestamp,

    /// Current finality status.
    pub status: VertexStatus,

    /// TxIds of vertices that directly reference this one as a parent.
    /// Populated as child vertices arrive.
    pub children: Vec<TxId>,

    /// Number of validator confirmations received so far.
    pub confirmation_count: u32,
}

impl Vertex {
    pub fn new(transaction: Transaction, depth: u64, received_at: Timestamp) -> Self {
        Self {
            transaction,
            depth,
            received_at,
            status: VertexStatus::Pending,
            children: Vec::new(),
            confirmation_count: 0,
        }
    }

    pub fn tx_id(&self) -> &TxId {
        &self.transaction.tx_id
    }

    pub fn parents(&self) -> &Vec<TxId> {
        &self.transaction.parents
    }

    pub fn is_genesis(&self) -> bool {
        self.transaction.parents.is_empty()
    }

    pub fn is_final(&self) -> bool {
        matches!(self.status, VertexStatus::Final)
    }
}
