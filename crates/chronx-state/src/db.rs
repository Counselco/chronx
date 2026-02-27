use chronx_core::account::{Account, TimeLockContract};
use chronx_core::error::ChronxError;
use chronx_core::types::{AccountId, TxId};
use chronx_dag::vertex::Vertex;
use std::path::Path;

/// Persistent state database backed by sled (pure-Rust, no C dependencies).
///
/// Named trees (analogous to column families):
///   accounts   — AccountId bytes → bincode(Account)
///   vertices   — TxId bytes      → bincode(Vertex)
///   timelocks  — TxId bytes      → bincode(TimeLockContract)
///   dag_tips   — TxId bytes      → [] (membership set)
///   meta       — utf8 key bytes  → raw bytes
pub struct StateDb {
    _db: sled::Db,
    accounts: sled::Tree,
    vertices: sled::Tree,
    timelocks: sled::Tree,
    dag_tips: sled::Tree,
    meta: sled::Tree,
}

impl StateDb {
    /// Open or create the state database at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ChronxError> {
        let db = sled::open(path).map_err(|e| ChronxError::Storage(e.to_string()))?;
        let accounts  = db.open_tree("accounts").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let vertices  = db.open_tree("vertices").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let timelocks = db.open_tree("timelocks").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let dag_tips  = db.open_tree("dag_tips").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let meta      = db.open_tree("meta").map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(Self { _db: db, accounts, vertices, timelocks, dag_tips, meta })
    }

    // ── Accounts ─────────────────────────────────────────────────────────────

    pub fn get_account(&self, id: &AccountId) -> Result<Option<Account>, ChronxError> {
        match self.accounts.get(id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(bytes) => {
                let acc = bincode::deserialize(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(acc))
            }
            None => Ok(None),
        }
    }

    pub fn put_account(&self, account: &Account) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(account)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.accounts
            .insert(account.account_id.as_bytes(), bytes)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn account_exists(&self, id: &AccountId) -> bool {
        self.accounts.contains_key(id.as_bytes()).unwrap_or(false)
    }

    // ── Vertices ─────────────────────────────────────────────────────────────

    pub fn get_vertex(&self, tx_id: &TxId) -> Result<Option<Vertex>, ChronxError> {
        match self.vertices.get(tx_id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(bytes) => {
                let v = bincode::deserialize(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    pub fn put_vertex(&self, vertex: &Vertex) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(vertex)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.vertices
            .insert(vertex.tx_id().as_bytes(), bytes)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn vertex_exists(&self, tx_id: &TxId) -> bool {
        self.vertices.contains_key(tx_id.as_bytes()).unwrap_or(false)
    }

    // ── Time-lock contracts ───────────────────────────────────────────────────

    pub fn get_timelock(&self, id: &TxId) -> Result<Option<TimeLockContract>, ChronxError> {
        match self.timelocks.get(id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(bytes) => {
                let tlc = bincode::deserialize(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(tlc))
            }
            None => Ok(None),
        }
    }

    pub fn put_timelock(&self, contract: &TimeLockContract) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(contract)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.timelocks
            .insert(contract.id.as_bytes(), bytes)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    // ── DAG tips ──────────────────────────────────────────────────────────────

    pub fn add_tip(&self, tx_id: &TxId) -> Result<(), ChronxError> {
        self.dag_tips
            .insert(tx_id.as_bytes(), b"".as_ref())
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn remove_tip(&self, tx_id: &TxId) -> Result<(), ChronxError> {
        self.dag_tips
            .remove(tx_id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_tips(&self) -> Result<Vec<TxId>, ChronxError> {
        let mut tips = Vec::new();
        for item in self.dag_tips.iter() {
            let (key, _) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key);
            tips.push(TxId::from_bytes(arr));
        }
        Ok(tips)
    }

    // ── Meta ──────────────────────────────────────────────────────────────────

    pub fn put_meta(&self, key: &str, value: &[u8]) -> Result<(), ChronxError> {
        self.meta
            .insert(key.as_bytes(), value)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, ChronxError> {
        self.meta
            .get(key.as_bytes())
            .map(|v| v.map(|iv| iv.to_vec()))
            .map_err(|e| ChronxError::Storage(e.to_string()))
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), ChronxError> {
        self._db.flush().map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }
}
