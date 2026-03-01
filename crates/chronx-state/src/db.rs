use chronx_core::account::{Account, TimeLockContract};
use chronx_core::claims::{CertificateSchema, ClaimState, OracleSnapshot, ProviderRecord};
use chronx_core::error::ChronxError;
use chronx_core::types::{AccountId, TxId};
use chronx_dag::vertex::Vertex;
use std::path::Path;

/// Persistent state database backed by sled (pure-Rust, no C dependencies).
///
/// Named trees:
///   accounts         — AccountId bytes  → bincode(Account)
///   vertices         — TxId bytes       → bincode(Vertex)
///   timelocks        — TxId bytes       → bincode(TimeLockContract)
///   dag_tips         — TxId bytes       → [] (membership set)
///   meta             — utf8 key bytes   → raw bytes
///   providers        — AccountId bytes  → bincode(ProviderRecord)   [V2]
///   schemas          — u64 be bytes     → bincode(CertificateSchema) [V2]
///   claims           — TxId bytes       → bincode(ClaimState)       [V2]
///   oracle_snapshots — pair utf8 bytes  → bincode(OracleSnapshot)   [V2]
///   oracle_submissions — (pair + AccountId) → bincode(OracleSubmission) [V2]
pub struct StateDb {
    _db: sled::Db,
    accounts: sled::Tree,
    vertices: sled::Tree,
    timelocks: sled::Tree,
    dag_tips: sled::Tree,
    meta: sled::Tree,
    // V2 Claims trees
    providers: sled::Tree,
    schemas: sled::Tree,
    claims: sled::Tree,
    oracle_snapshots: sled::Tree,
    oracle_submissions: sled::Tree,
}

impl StateDb {
    /// Open or create the state database at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ChronxError> {
        let db = sled::open(path).map_err(|e| ChronxError::Storage(e.to_string()))?;
        let accounts           = db.open_tree("accounts").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let vertices           = db.open_tree("vertices").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let timelocks          = db.open_tree("timelocks").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let dag_tips           = db.open_tree("dag_tips").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let meta               = db.open_tree("meta").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let providers          = db.open_tree("providers").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let schemas            = db.open_tree("schemas").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let claims             = db.open_tree("claims").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let oracle_snapshots   = db.open_tree("oracle_snapshots").map_err(|e| ChronxError::Storage(e.to_string()))?;
        let oracle_submissions = db.open_tree("oracle_submissions").map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(Self { _db: db, accounts, vertices, timelocks, dag_tips, meta,
                  providers, schemas, claims, oracle_snapshots, oracle_submissions })
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

    /// Return all time-lock contracts where `recipient_id` is the registered recipient.
    pub fn iter_timelocks_for_recipient(
        &self,
        recipient_id: &AccountId,
    ) -> Result<Vec<TimeLockContract>, ChronxError> {
        let mut result = Vec::new();
        for item in self.timelocks.iter() {
            let (_, bytes) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let tlc: TimeLockContract = bincode::deserialize(&bytes)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if tlc.recipient_account_id == *recipient_id {
                result.push(tlc);
            }
        }
        Ok(result)
    }

    /// Return all time-lock contracts where `sender_id` is the originating sender.
    pub fn iter_timelocks_for_sender(
        &self,
        sender_id: &AccountId,
    ) -> Result<Vec<TimeLockContract>, ChronxError> {
        let mut result = Vec::new();
        for item in self.timelocks.iter() {
            let (_, bytes) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let tlc: TimeLockContract = bincode::deserialize(&bytes)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if tlc.sender == *sender_id {
                result.push(tlc);
            }
        }
        Ok(result)
    }

    /// Return every time-lock contract in the DB (no filter).
    pub fn iter_all_timelocks(&self) -> Result<Vec<TimeLockContract>, ChronxError> {
        let mut result = Vec::new();
        for item in self.timelocks.iter() {
            let (_, bytes) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let tlc: TimeLockContract = bincode::deserialize(&bytes)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            result.push(tlc);
        }
        Ok(result)
    }

    /// Return every vertex in the DB (no filter).
    pub fn iter_all_vertices(&self) -> Result<Vec<Vertex>, ChronxError> {
        let mut result = Vec::new();
        for item in self.vertices.iter() {
            let (_, bytes) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let v: Vertex = bincode::deserialize(&bytes)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            result.push(v);
        }
        Ok(result)
    }

    /// Count accounts in the DB.
    pub fn count_accounts(&self) -> u64 { self.accounts.len() as u64 }

    /// Count time-lock contracts in the DB.
    pub fn count_timelocks(&self) -> u64 { self.timelocks.len() as u64 }

    /// Count vertices (transactions) in the DB.
    pub fn count_vertices(&self) -> u64 { self.vertices.len() as u64 }

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

    // ── V2 Claims: Provider registry ─────────────────────────────────────────

    pub fn get_provider(&self, id: &AccountId) -> Result<Option<ProviderRecord>, ChronxError> {
        match self.providers.get(id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn put_provider(&self, p: &ProviderRecord) -> Result<(), ChronxError> {
        let b = bincode::serialize(p).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.providers.insert(p.provider_id.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn iter_providers(&self) -> Result<Vec<ProviderRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.providers.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            out.push(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?);
        }
        Ok(out)
    }

    // ── V2 Claims: Schema registry ────────────────────────────────────────────

    pub fn get_schema(&self, id: u64) -> Result<Option<CertificateSchema>, ChronxError> {
        let key = id.to_be_bytes();
        match self.schemas.get(key).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn put_schema(&self, s: &CertificateSchema) -> Result<(), ChronxError> {
        let b = bincode::serialize(s).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.schemas.insert(s.schema_id.to_be_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn iter_schemas(&self) -> Result<Vec<CertificateSchema>, ChronxError> {
        let mut out = Vec::new();
        for item in self.schemas.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            out.push(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?);
        }
        Ok(out)
    }

    /// Allocate the next sequential schema ID (stored in meta tree).
    pub fn next_schema_id(&self) -> Result<u64, ChronxError> {
        let key = "next_schema_id";
        let current = self.get_meta(key)?.map(|b| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&b[..8]);
            u64::from_be_bytes(arr)
        }).unwrap_or(1);
        self.put_meta(key, &(current + 1).to_be_bytes())?;
        Ok(current)
    }

    // ── V2 Claims: ClaimState ─────────────────────────────────────────────────

    pub fn get_claim(&self, lock_id: &TxId) -> Result<Option<ClaimState>, ChronxError> {
        match self.claims.get(lock_id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn put_claim(&self, cs: &ClaimState) -> Result<(), ChronxError> {
        let b = bincode::serialize(cs).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.claims.insert(cs.lock_id.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    // ── V2 Claims: Oracle ─────────────────────────────────────────────────────

    pub fn get_oracle_snapshot(&self, pair: &str) -> Result<Option<OracleSnapshot>, ChronxError> {
        match self.oracle_snapshots.get(pair.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn put_oracle_snapshot(&self, snap: &OracleSnapshot) -> Result<(), ChronxError> {
        let b = bincode::serialize(snap).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.oracle_snapshots.insert(snap.pair.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Store/overwrite a single oracle submission. Key = pair || submitter_bytes.
    pub fn put_oracle_submission(&self, sub: &chronx_core::claims::OracleSubmission) -> Result<(), ChronxError> {
        let mut key = sub.pair.as_bytes().to_vec();
        key.extend_from_slice(sub.submitter.as_bytes());
        let b = bincode::serialize(sub).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.oracle_submissions.insert(key, b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Retrieve all oracle submissions for a given pair (across all submitters).
    pub fn iter_oracle_submissions_for_pair(
        &self,
        pair: &str,
    ) -> Result<Vec<chronx_core::claims::OracleSubmission>, ChronxError> {
        let prefix = pair.as_bytes();
        let mut out = Vec::new();
        for item in self.oracle_submissions.scan_prefix(prefix) {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let sub: chronx_core::claims::OracleSubmission =
                bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            out.push(sub);
        }
        Ok(out)
    }
}
