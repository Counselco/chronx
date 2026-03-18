use chronx_core::account::{Account, TimeLockContract};
use chronx_core::claims::{CertificateSchema, ClaimState, OracleSnapshot, ProviderRecord};
use chronx_core::error::ChronxError;
use chronx_core::types::{AccountId, TxId};
use chronx_dag::vertex::Vertex;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Genesis 7 — Verified Delivery Protocol data structures ───────────────────

/// Contents of a package created at promise time and sent to the Verifas vault
/// on Day 91 trigger. Currently stored as plaintext — see encryption TODO below.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PromisePackage {
    pub claim_secret_hash: String,
    pub promise_value_chronos: u64,
    pub sender_wallet: String,
    pub sent_at: u64,
    pub maturity_at: u64,
    pub beneficiary_type: String,
    pub beneficiary_identifier: String,
    pub freeform_description: String,
}

/// Wrapper around PromisePackage with encryption metadata.
/// Stored in the "promise_packages" sled tree keyed by lock_id bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PromisePackageRecord {
    pub lock_id: String,
    pub encryption_scheme: String,
    pub kyber_ciphertext_hex: String,
    pub chacha20_ciphertext_hex: String,
    pub chacha20_nonce_hex: String,
    pub verifas_kyber_pubkey_hint: String,
    pub created_at: u64,
}

/// Record of a Day 91 trigger event for a promise.
/// Stored in the "promise_triggers" sled tree keyed by lock_id bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PromiseTriggerRecord {
    pub lock_id: String,
    pub trigger_fired_at: u64,
    pub package_routed_to: String,
    pub activation_deposit_chronos: u64,
    pub remaining_chronos: u64,
    pub expiry_at: u64,
}

/// On-chain registry entry for an approved bonded verifier.
/// Stored in the "verifier_registry" sled tree keyed by wallet address bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerifierRecord {
    pub verifier_name: String,
    pub wallet_address: String,
    pub bond_amount_kx: u64,
    pub dilithium2_public_key_hex: String,
    pub jurisdiction: String,
    pub role: String,
    pub approval_date: u64,
    pub status: String,
}

// ── Genesis 8 — AI Agent Architecture data structures ────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentRecord {
    pub agent_name: String,
    pub agent_wallet: String,
    pub agent_code_hash: String,
    pub kyber_public_key_hex: String,
    pub operator_wallet: String,
    pub jurisdiction: String,
    pub status: String,
    pub registered_at: u64,
    pub governance_tx_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentLoanRecord {
    pub lock_id: String,
    pub agent_wallet: String,
    pub agent_name: String,
    pub loan_amount_chronos: u64,
    pub original_promise_value: u64,
    pub investable_fraction: f64,
    pub return_wallet: String,
    pub return_date: u64,
    pub risk_level: u32,
    pub investment_exclusions: String,
    pub grantor_intent: String,
    pub loan_package_encrypted: bool,
    pub kyber_ciphertext_hex: String,
    pub chacha20_ciphertext_hex: String,
    pub chacha20_nonce_hex: String,
    pub disbursed_at: u64,
    pub returned_at: u64,
    pub returned_chronos: u64,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentCustodyRecord {
    pub lock_id: String,
    pub agent_name: String,
    pub agent_wallet: String,
    pub agent_code_hash: String,
    pub operator_wallet: String,
    pub axiom_version_hash: String,
    pub grantor_consent_at: u64,
    pub agent_consent_at: u64,
    pub released_at: u64,
    pub amount_chronos: u64,
    pub statement: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AxiomConsentRecord {
    pub lock_id: String,
    pub party_type: String,
    pub party_wallet: String,
    pub axiom_hash: String,
    pub consented_at: u64,
}


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
///   email_claim_hashes — TxId bytes     → 32-byte BLAKE3 hash       [V3.3]
///   promise_packages — TxId bytes       → bincode(PromisePackageRecord) [G7]
///   promise_triggers — TxId bytes       → bincode(PromiseTriggerRecord) [G7]
///   verifier_registry — wallet bytes    → bincode(VerifierRecord)       [G7]
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
    /// V3.3 Secure email claims: maps TxId (lock_id) → BLAKE3 hash of claim secret.
    /// Separate tree so that TimeLockContract serialisation format is unchanged.
    email_claim_hashes: sled::Tree,
    // Genesis 7 — Verified Delivery Protocol trees
    promise_packages: sled::Tree,
    promise_triggers: sled::Tree,
    verifier_registry: sled::Tree,

    // Genesis 8 — AI Agent Architecture trees
    agent_registry: sled::Tree,
    agent_loans: sled::Tree,
    agent_custody_records: sled::Tree,
    axiom_consents: sled::Tree,

}

impl StateDb {
    /// Open or create the state database at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ChronxError> {
        let db = sled::open(path).map_err(|e| ChronxError::Storage(e.to_string()))?;
        let accounts = db
            .open_tree("accounts")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let vertices = db
            .open_tree("vertices")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let timelocks = db
            .open_tree("timelocks")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let dag_tips = db
            .open_tree("dag_tips")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let meta = db
            .open_tree("meta")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let providers = db
            .open_tree("providers")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let schemas = db
            .open_tree("schemas")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let claims = db
            .open_tree("claims")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let oracle_snapshots = db
            .open_tree("oracle_snapshots")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let oracle_submissions = db
            .open_tree("oracle_submissions")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let email_claim_hashes = db
            .open_tree("email_claim_hashes")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let promise_packages = db
            .open_tree("promise_packages")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let promise_triggers = db
            .open_tree("promise_triggers")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let verifier_registry = db
            .open_tree("verifier_registry")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;

        let agent_registry = db
            .open_tree("agent_registry")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let agent_loans = db
            .open_tree("agent_loans")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let agent_custody_records = db
            .open_tree("agent_custody_records")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let axiom_consents = db
            .open_tree("axiom_consents")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(Self {
            _db: db,
            accounts,
            vertices,
            timelocks,
            dag_tips,
            meta,
            providers,
            schemas,
            claims,
            oracle_snapshots,
            oracle_submissions,
            email_claim_hashes,
            promise_packages,
            promise_triggers,
            verifier_registry,
            agent_registry,
            agent_loans,
            agent_custody_records,
            axiom_consents,
        })
    }

    // ── Accounts ─────────────────────────────────────────────────────────────

    pub fn get_account(&self, id: &AccountId) -> Result<Option<Account>, ChronxError> {
        match self
            .accounts
            .get(id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(bytes) => {
                let acc = bincode::deserialize(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(acc))
            }
            None => Ok(None),
        }
    }

    pub fn put_account(&self, account: &Account) -> Result<(), ChronxError> {
        let bytes =
            bincode::serialize(account).map_err(|e| ChronxError::Serialization(e.to_string()))?;
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
        match self
            .vertices
            .get(tx_id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(bytes) => {
                let v = bincode::deserialize(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    pub fn put_vertex(&self, vertex: &Vertex) -> Result<(), ChronxError> {
        let bytes =
            bincode::serialize(vertex).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.vertices
            .insert(vertex.tx_id().as_bytes(), bytes)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn vertex_exists(&self, tx_id: &TxId) -> bool {
        self.vertices
            .contains_key(tx_id.as_bytes())
            .unwrap_or(false)
    }

    // ── Time-lock contracts ───────────────────────────────────────────────────

    pub fn get_timelock(&self, id: &TxId) -> Result<Option<TimeLockContract>, ChronxError> {
        match self
            .timelocks
            .get(id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(bytes) => {
                let tlc = bincode::deserialize(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(tlc))
            }
            None => Ok(None),
        }
    }

    pub fn put_timelock(&self, contract: &TimeLockContract) -> Result<(), ChronxError> {
        let bytes =
            bincode::serialize(contract).map_err(|e| ChronxError::Serialization(e.to_string()))?;
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
    pub fn count_accounts(&self) -> u64 {
        self.accounts.len() as u64
    }

    /// Count time-lock contracts in the DB.
    pub fn count_timelocks(&self) -> u64 {
        self.timelocks.len() as u64
    }

    /// Count vertices (transactions) in the DB.
    pub fn count_vertices(&self) -> u64 {
        self.vertices.len() as u64
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
        self._db
            .flush()
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    // ── V2 Claims: Provider registry ─────────────────────────────────────────

    pub fn get_provider(&self, id: &AccountId) -> Result<Option<ProviderRecord>, ChronxError> {
        match self
            .providers
            .get(id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(b) => Ok(Some(
                bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn put_provider(&self, p: &ProviderRecord) -> Result<(), ChronxError> {
        let b = bincode::serialize(p).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.providers
            .insert(p.provider_id.as_bytes(), b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn iter_providers(&self) -> Result<Vec<ProviderRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.providers.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            out.push(
                bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?,
            );
        }
        Ok(out)
    }

    // ── V2 Claims: Schema registry ────────────────────────────────────────────

    pub fn get_schema(&self, id: u64) -> Result<Option<CertificateSchema>, ChronxError> {
        let key = id.to_be_bytes();
        match self
            .schemas
            .get(key)
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(b) => Ok(Some(
                bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn put_schema(&self, s: &CertificateSchema) -> Result<(), ChronxError> {
        let b = bincode::serialize(s).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.schemas
            .insert(s.schema_id.to_be_bytes(), b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn iter_schemas(&self) -> Result<Vec<CertificateSchema>, ChronxError> {
        let mut out = Vec::new();
        for item in self.schemas.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            out.push(
                bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?,
            );
        }
        Ok(out)
    }

    /// Allocate the next sequential schema ID (stored in meta tree).
    pub fn next_schema_id(&self) -> Result<u64, ChronxError> {
        let key = "next_schema_id";
        let current = self
            .get_meta(key)?
            .map(|b| {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&b[..8]);
                u64::from_be_bytes(arr)
            })
            .unwrap_or(1);
        self.put_meta(key, &(current + 1).to_be_bytes())?;
        Ok(current)
    }

    // ── V2 Claims: ClaimState ─────────────────────────────────────────────────

    pub fn get_claim(&self, lock_id: &TxId) -> Result<Option<ClaimState>, ChronxError> {
        match self
            .claims
            .get(lock_id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(b) => Ok(Some(
                bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn put_claim(&self, cs: &ClaimState) -> Result<(), ChronxError> {
        let b = bincode::serialize(cs).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.claims
            .insert(cs.lock_id.as_bytes(), b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    // ── V2 Claims: Oracle ─────────────────────────────────────────────────────

    pub fn get_oracle_snapshot(&self, pair: &str) -> Result<Option<OracleSnapshot>, ChronxError> {
        match self
            .oracle_snapshots
            .get(pair.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(b) => Ok(Some(
                bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn put_oracle_snapshot(&self, snap: &OracleSnapshot) -> Result<(), ChronxError> {
        let b = bincode::serialize(snap).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.oracle_snapshots
            .insert(snap.pair.as_bytes(), b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Store/overwrite a single oracle submission. Key = pair || submitter_bytes.
    pub fn put_oracle_submission(
        &self,
        sub: &chronx_core::claims::OracleSubmission,
    ) -> Result<(), ChronxError> {
        let mut key = sub.pair.as_bytes().to_vec();
        key.extend_from_slice(sub.submitter.as_bytes());
        let b = bincode::serialize(sub).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.oracle_submissions
            .insert(key, b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    // ── V3.3 Secure email claim hashes ────────────────────────────────────────

    /// Store the BLAKE3 hash of the claim secret for an email lock.
    /// Key = TxId bytes of the lock, value = raw 32-byte hash.
    pub fn put_email_claim_hash(&self, lock_id: &TxId, hash: [u8; 32]) -> Result<(), ChronxError> {
        self.email_claim_hashes
            .insert(lock_id.as_bytes(), hash.to_vec())
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Retrieve the BLAKE3 claim-secret hash for an email lock.
    /// Returns None if this lock has no claim secret (i.e. it is not an email lock).
    pub fn get_email_claim_hash(&self, lock_id: &TxId) -> Result<Option<[u8; 32]>, ChronxError> {
        match self
            .email_claim_hashes
            .get(lock_id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            Some(_) => Err(ChronxError::Storage("corrupt email_claim_hash entry".into())),
            None => Ok(None),
        }
    }

    /// Find ALL lock_ids that share the given claim-secret hash.
    /// Used by Cascade Send to batch-claim all locks in a series.
    pub fn get_locks_by_claim_hash(&self, hash: &[u8; 32]) -> Result<Vec<TxId>, ChronxError> {
        let mut lock_ids = Vec::new();
        for item in self.email_claim_hashes.iter() {
            let (key, val) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            if val.len() == 32 && val.as_ref() == hash.as_slice() {
                if key.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&key);
                    lock_ids.push(TxId::from_bytes(arr));
                }
            }
        }
        Ok(lock_ids)
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

    // ── Genesis 7 — Promise packages ──────────────────────────────────────────

    /// Store the package created at promise time.
    /// Key = lock_id bytes.
    pub fn put_promise_package(
        &self,
        lock_id: &TxId,
        record: &PromisePackageRecord,
    ) -> Result<(), ChronxError> {
        let b = bincode::serialize(record)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.promise_packages
            .insert(lock_id.as_bytes(), b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Retrieve the promise package for a lock.
    pub fn get_promise_package(
        &self,
        lock_id: &TxId,
    ) -> Result<Option<PromisePackageRecord>, ChronxError> {
        match self
            .promise_packages
            .get(lock_id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(b) => Ok(Some(
                bincode::deserialize(&b)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    // ── Genesis 7 — Promise triggers (Day 91 events) ──────────────────────────

    /// Store a trigger record when Day 91 fires for a promise.
    pub fn put_promise_trigger(
        &self,
        lock_id: &TxId,
        record: &PromiseTriggerRecord,
    ) -> Result<(), ChronxError> {
        let b = bincode::serialize(record)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.promise_triggers
            .insert(lock_id.as_bytes(), b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Retrieve the trigger record for a lock.
    pub fn get_promise_trigger(
        &self,
        lock_id: &TxId,
    ) -> Result<Option<PromiseTriggerRecord>, ChronxError> {
        match self
            .promise_triggers
            .get(lock_id.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(b) => Ok(Some(
                bincode::deserialize(&b)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Check if a trigger has already fired for a lock (avoids double-firing).
    pub fn has_promise_trigger(&self, lock_id: &TxId) -> bool {
        self.promise_triggers
            .contains_key(lock_id.as_bytes())
            .unwrap_or(false)
    }

    /// Iterate all trigger records (used by 100-year expiry sweep).
    pub fn iter_all_promise_triggers(&self) -> Result<Vec<PromiseTriggerRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.promise_triggers.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            out.push(
                bincode::deserialize(&b)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?,
            );
        }
        Ok(out)
    }

    // ── Genesis 7 — Verifier registry ─────────────────────────────────────────

    /// Register or update a verifier entry.
    pub fn put_verifier(
        &self,
        wallet_address: &str,
        record: &VerifierRecord,
    ) -> Result<(), ChronxError> {
        let b = bincode::serialize(record)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.verifier_registry
            .insert(wallet_address.as_bytes(), b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Retrieve a verifier entry by wallet address.
    pub fn get_verifier(
        &self,
        wallet_address: &str,
    ) -> Result<Option<VerifierRecord>, ChronxError> {
        match self
            .verifier_registry
            .get(wallet_address.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(b) => Ok(Some(
                bincode::deserialize(&b)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Return all verifiers with status "Active".
    pub fn get_all_active_verifiers(&self) -> Result<Vec<VerifierRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.verifier_registry.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: VerifierRecord = bincode::deserialize(&b)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.status == "Active" {
                out.push(record);
            }
        }
        Ok(out)
    }

    /// Return the wallet address of the first Active verifier with role "VerifasVault".
    /// Returns None if no such verifier is registered.
    pub fn get_verifas_vault_address(&self) -> Result<Option<String>, ChronxError> {
        for item in self.verifier_registry.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: VerifierRecord = bincode::deserialize(&b)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.status == "Active" && record.role == "VerifasVault" {
                return Ok(Some(record.wallet_address));
            }
        }
        Ok(None)
    }
    // ── Genesis 8 — Agent registry ────────────────────────────────────────

    pub fn put_agent(&self, wallet: &str, record: &AgentRecord) -> Result<(), ChronxError> {
        let b = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.agent_registry.insert(wallet.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_agent(&self, wallet: &str) -> Result<Option<AgentRecord>, ChronxError> {
        match self.agent_registry.get(wallet.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn get_all_active_agents(&self) -> Result<Vec<AgentRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.agent_registry.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: AgentRecord = bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.status == "Active" { out.push(record); }
        }
        Ok(out)
    }

    // ── Genesis 8 — Agent loans ───────────────────────────────────────────

    pub fn put_agent_loan(&self, lock_id: &str, record: &AgentLoanRecord) -> Result<(), ChronxError> {
        let b = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.agent_loans.insert(lock_id.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_agent_loan(&self, lock_id: &str) -> Result<Option<AgentLoanRecord>, ChronxError> {
        match self.agent_loans.get(lock_id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn iter_all_agent_loans(&self) -> Result<Vec<AgentLoanRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.agent_loans.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            out.push(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?);
        }
        Ok(out)
    }

    // ── Genesis 8 — Agent custody records ─────────────────────────────────

    pub fn put_agent_custody(&self, lock_id: &str, record: &AgentCustodyRecord) -> Result<(), ChronxError> {
        let b = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.agent_custody_records.insert(lock_id.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_agent_custody(&self, lock_id: &str) -> Result<Option<AgentCustodyRecord>, ChronxError> {
        match self.agent_custody_records.get(lock_id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn iter_agent_custody_for_wallet(&self, agent_wallet: &str) -> Result<Vec<AgentCustodyRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.agent_custody_records.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: AgentCustodyRecord = bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.agent_wallet == agent_wallet { out.push(record); }
        }
        Ok(out)
    }

    // ── Genesis 8 — Axiom consents ────────────────────────────────────────

    pub fn put_axiom_consent(&self, lock_id: &str, party_type: &str, record: &AxiomConsentRecord) -> Result<(), ChronxError> {
        let key = format!("{}:{}", lock_id, party_type);
        let b = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.axiom_consents.insert(key.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_axiom_consent(&self, lock_id: &str, party_type: &str) -> Result<Option<AxiomConsentRecord>, ChronxError> {
        let key = format!("{}:{}", lock_id, party_type);
        match self.axiom_consents.get(key.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn has_both_consents(&self, lock_id: &str) -> bool {
        let grantor_key = format!("{}:GRANTOR", lock_id);
        let agent_key = format!("{}:AGENT", lock_id);
        let has_grantor = self.axiom_consents.contains_key(grantor_key.as_bytes()).unwrap_or(false);
        let has_agent = self.axiom_consents.contains_key(agent_key.as_bytes()).unwrap_or(false);
        has_grantor && has_agent
    }

    /// Compute the combined axiom hash: BLAKE3(promise_axioms + trading_axioms)
    pub fn get_combined_axiom_hash(&self) -> Result<String, ChronxError> {
        let promise = self.get_meta("promise_axioms")?.unwrap_or_default();
        let trading = self.get_meta("trading_axioms")?.unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&promise);
        hasher.update(&trading);
        Ok(hasher.finalize().to_hex().to_string())
    }

}
