use serde_json;
use hex;
use chronx_core::account::{Account, TimeLockContract};
use chronx_core::claims::{CertificateSchema, ClaimState, OracleSnapshot, ProviderRecord};
use chronx_core::error::ChronxError;
use chronx_core::types::{AccountId, TxId};
use chronx_dag::vertex::Vertex;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Verified Delivery Protocol data structures ───────────────────

/// Contents of a package created at promise time and sent to the Verifas vault
/// MEMO PRIVACY: Memos are private by default.
// memo_encrypted=true means sender encrypts before submission. Node stores ciphertext only.
// memo_public=true requires verified sender identity (TYPE L) and is rejected for promises > 365 days.
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

// ── AI Agent Architecture data structures ────────────────────

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


// ── MISAI ExecutorWithdraw tracking ────────────────────────────────────────

/// Record of an ExecutorWithdraw submission, stored in the `executor_withdrawals` tree.
/// Tracks pending withdrawals for the finalization sweep and enforces rate limits.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecutorWithdrawalRecord {
    pub lock_id: String,
    pub destination: String,
    pub amount_chronos: u64,
    pub submitted_at: i64,
    pub finalize_at: i64,
    pub status: String, // "PendingExecutor" or "Finalized"
}


// ── Invoice/Credit/Deposit/Conditional/Ledger record types ──────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InvoiceStatus {
    Open,
    Fulfilled,
    Lapsed,
    Cancelled,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceRecord {
    pub invoice_id: [u8; 32],
    pub issuer_pubkey: Vec<u8>,
    pub payer_pubkey: Option<Vec<u8>>,
    pub amount_chronos: u64,
    pub expiry: u64,
    pub encrypted_memo: Option<Vec<u8>>,
    pub memo_hash: Option<[u8; 32]>,
    pub status: InvoiceStatus,
    pub created_at: u64,
    pub fulfilled_at: Option<u64>,
    pub fulfilled_by: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CreditStatus {
    Open,
    Closed,
    Lapsed,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreditRecord {
    pub credit_id: [u8; 32],
    pub grantor_pubkey: Vec<u8>,
    pub beneficiary_pubkey: Vec<u8>,
    pub ceiling_chronos: u64,
    pub per_draw_max_chronos: Option<u64>,
    pub expiry: u64,
    pub drawn_chronos: u64,
    pub status: CreditStatus,
    pub encrypted_terms: Option<Vec<u8>>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DepositStatus {
    Active,
    Matured,
    Settled,
    Defaulted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositRecord {
    pub deposit_id: [u8; 32],
    pub depositor_pubkey: Vec<u8>,
    pub obligor_pubkey: Vec<u8>,
    pub principal_chronos: u64,
    pub rate_basis_points: u64,
    pub term_seconds: u64,
    pub compounding: String,
    pub maturity_timestamp: u64,
    pub total_due_chronos: u64,
    pub penalty_basis_points: Option<u64>,
    pub status: DepositStatus,
    pub created_at: u64,
    pub settled_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConditionalStatus {
    Pending,
    Released,
    PartiallyReleased,
    Voided,
    Returned,
    Escrowed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConditionalRecord {
    pub type_v_id: [u8; 32],
    pub sender_pubkey: Vec<u8>,
    pub recipient_pubkey: Vec<u8>,
    pub amount_chronos: u64,
    pub attestor_pubkeys: Vec<Vec<u8>>,
    pub min_attestors: u32,
    pub attestation_memo: Option<String>,
    pub valid_until: u64,
    pub fallback: String,
    pub encrypted_terms: Option<Vec<u8>>,
    pub attestations_received: Vec<(Vec<u8>, u64)>,
    pub status: ConditionalStatus,
    pub created_at: u64,
    // -- Success payment (hedge premium on clean expiry) --
    #[serde(default)]
    pub success_payment_wallet: Option<String>,
    #[serde(default)]
    pub success_payment_chronos: Option<u64>,
    #[serde(default)]
    pub released_so_far_chronos: u64,
    #[serde(default)]
    pub release_count: u32,
    #[serde(default)]
    pub condition_type: Option<String>,
    #[serde(default)]
    pub oracle_pair: Option<String>,
    #[serde(default)]
    pub oracle_trigger_threshold: Option<f64>,
    #[serde(default)]
    pub oracle_trigger_direction: Option<String>,
    #[serde(default)]
    pub oracle_creation_price: Option<f64>,
    #[serde(default)]
    pub escalation_wallet: Option<String>,
    #[serde(default)]
    pub escalation_lock_seconds: Option<u64>,
    #[serde(default)]
    pub attestors_suspended: bool,
    #[serde(default)]
    pub escalation_active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerEntryRecord {
    pub entry_id: [u8; 32],
    pub author_pubkey: Vec<u8>,
    pub mandate_id: Option<[u8; 32]>,
    pub promise_id: Option<[u8; 32]>,
    pub entry_type: String,
    pub content_hash: [u8; 32],
    pub content_summary: Vec<u8>,
    pub promise_chain_hash: Option<[u8; 32]>,
    pub external_ref: Option<String>,
    pub timestamp: u64,
}


// ── Sign of Life and Promise Chain record types ─────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignOfLifeRecord {
    pub lock_id: String,
    pub grantor_pubkey: Vec<u8>,
    pub guardian_pubkey: Option<Vec<u8>>,
    pub alt_guardian_pubkey: Option<Vec<u8>>,
    pub interval_days: u64,
    pub grace_days: u64,
    pub guardian_until: Option<u64>,
    pub last_attestation: u64,
    pub next_due: u64,
    pub grace_expires: Option<u64>,
    pub status: String,           // "Active", "GracePeriod", "Transitioned"
    pub responsible: String,      // "Grantor" or "Guardian"
    pub beneficiary_description_hash: Option<[u8; 32]>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseChainRecord {
    pub promise_id: [u8; 32],
    pub entries: Vec<[u8; 32]>,   // ordered list of entry_ids
    pub last_anchor_hash: Option<[u8; 32]>,
    pub last_anchor_at: Option<u64>,
    pub created_at: u64,
}


// ── Identity Verification record ────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdentityRecord {
    pub wallet_b58: String,
    pub issuer_wallet_b58: String,
    pub display_name: String,
    pub badge_code: String,
    pub badge_color: Option<String>,
    pub verified: bool,
    pub entry_id: [u8; 32],
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub issuer_notes: Option<String>,
}

/// Persistent state database backed by sled (pure-Rust, no C dependencies).
///
/// Named trees:
/// accounts — AccountId bytes  → bincode(Account)
/// vertices — TxId bytes       → bincode(Vertex)
/// timelocks — TxId bytes       → bincode(TimeLockContract)
/// dag_tips — TxId bytes       → [] (membership set)
/// meta — utf8 key bytes   → raw bytes
/// providers — AccountId bytes  → bincode(ProviderRecord)   [V2]
/// schemas — u64 be bytes     → bincode(CertificateSchema) [V2]
/// claims — TxId bytes       → bincode(ClaimState)       [V2]
/// oracle_snapshots — pair utf8 bytes  → bincode(OracleSnapshot)   [V2]
/// oracle_submissions — (pair + AccountId) → bincode(OracleSubmission) [V2]
/// email_claim_hashes — TxId bytes     → 32-byte BLAKE3 hash       [V3.3]
/// promise_packages — TxId bytes       → bincode(PromisePackageRecord) [G7]
/// promise_triggers — TxId bytes       → bincode(PromiseTriggerRecord) [G7]
/// verifier_registry — wallet bytes    → bincode(VerifierRecord)       [G7]
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
    // protocol — Verified Delivery Protocol trees
    promise_packages: sled::Tree,
    promise_triggers: sled::Tree,
    verifier_registry: sled::Tree,

    // protocol — AI Agent Architecture trees
    agent_registry: sled::Tree,
    agent_loans: sled::Tree,
    agent_custody_records: sled::Tree,
    axiom_consents: sled::Tree,

    // protocol — Sign of Life and Promise Chain trees
    sign_of_life: sled::Tree,
    promise_chains: sled::Tree,

    // protocol — Invoice/Credit/Deposit/Conditional/Ledger trees
    invoices: sled::Tree,
    credits: sled::Tree,
    deposits: sled::Tree,
    conditionals: sled::Tree,
    ledger_entries: sled::Tree,
    /// Secondary index: promise_id [u8;32] -> bincode(Vec<[u8;32]>) of entry_ids.
    ledger_promise_index: sled::Tree,
    /// Identity index: wallet_b58 bytes -> bincode(Vec<[u8;32]>) of identity entry_ids.
    identity_index: sled::Tree,
    /// Badge blackouts: wallet_b58 bytes -> JSON {blackout_until, reason, revoked_at}.
    badge_blackouts: sled::Tree,
    /// Suggestion-only convert_to field: lock_id bytes -> UTF-8 string (max 50 chars).
    convert_to_suggestion: sled::Tree,

    /// MISAI ExecutorWithdraw: maps lock_id bytes → bincode(ExecutorWithdrawalRecord).
    /// Tracks pending executor withdrawals for finalization sweep and rate limiting.
    executor_withdrawals: sled::Tree,

    /// protocol: TYPE_G Wallet Groups — maps group_id [u8;32] -> bincode(GroupRecord).
    groups: sled::Tree,

    // Genesis 10a — Loan Protocol trees
    loans: sled::Tree,
    _loan_stages: sled::Tree,
    loan_defaults: sled::Tree,
    _loan_payments: sled::Tree,
    oracle_cache: sled::Tree,
    pub loan_memos: sled::Tree,

    // Re-Genesis 10
    pub escrow_accounts: sled::Tree,
    pub escrow_deposits: sled::Tree,
    pub micro_loans: sled::Tree,
    pub governance_params: sled::Tree,
    pub authority_grants: sled::Tree,
    pub escalations: sled::Tree,
    pub attestor_failures: sled::Tree,
    pub oracle_trigger_history: sled::Tree,
    pub partial_release_history: sled::Tree,
    pub pending_drawrequests: sled::Tree,
    pub escalation_errors: sled::Tree,
    pub bond_slash_cascade: sled::Tree,
    pub hedge_instruments: sled::Tree,
    pub pool_health_scores: sled::Tree,

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
        let sign_of_life = db
            .open_tree("sign_of_life")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let promise_chains = db
            .open_tree("promise_chains")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let invoices = db
            .open_tree("invoices")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let credits = db
            .open_tree("credits")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let deposits = db
            .open_tree("deposits")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let conditionals = db
            .open_tree("conditionals")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let ledger_entries = db
            .open_tree("ledger_entries")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let identity_index = db
            .open_tree("identity_index")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let badge_blackouts = db
            .open_tree("badge_blackouts")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let convert_to_suggestion = db
            .open_tree("convert_to_suggestion")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let ledger_promise_index = db
            .open_tree("ledger_promise_index")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let executor_withdrawals = db
            .open_tree("executor_withdrawals")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let groups = db
            .open_tree("groups")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let loans = db
            .open_tree("loans")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let _loan_stages = db
            .open_tree("loan_stages")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let loan_defaults = db
            .open_tree("loan_defaults")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let _loan_payments = db
            .open_tree("loan_payments")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let oracle_cache = db
            .open_tree("oracle_cache")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let escrow_accounts = db
            .open_tree("escrow_accounts")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let escrow_deposits = db
            .open_tree("escrow_deposits")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let micro_loans = db
            .open_tree("micro_loans")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let loan_memos = db
            .open_tree("loan_memos")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let governance_params = db
            .open_tree("governance_params")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let authority_grants = db
            .open_tree("authority_grants")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;

        let escalations = db
            .open_tree("escalations")
            .expect("Failed to open escalations tree");
        let attestor_failures = db
            .open_tree("attestor_failures")
            .expect("Failed to open attestor_failures tree");
        let oracle_trigger_history = db
            .open_tree("oracle_trigger_history")
            .expect("Failed to open oracle_trigger_history tree");
        let partial_release_history = db
            .open_tree("partial_release_history")
            .expect("Failed to open partial_release_history tree");
        let pending_drawrequests = db
            .open_tree("pending_drawrequests")
            .expect("Failed to open pending_drawrequests tree");
        let escalation_errors = db
            .open_tree("escalation_errors")
            .expect("Failed to open escalation_errors tree");
        let bond_slash_cascade = db
            .open_tree("bond_slash_cascade")
            .expect("Failed to open bond_slash_cascade tree");
        let hedge_instruments = db
            .open_tree("hedge_instruments")
            .expect("Failed to open hedge_instruments tree");
        let pool_health_scores = db
            .open_tree("pool_health_scores")
            .expect("Failed to open pool_health_scores tree");
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
            sign_of_life,
            promise_chains,
            invoices,
            credits,
            deposits,
            conditionals,
            ledger_entries,
            identity_index,
            badge_blackouts,
            convert_to_suggestion,
            ledger_promise_index,
            executor_withdrawals,
            groups,
            loans,
            _loan_stages,
            loan_defaults,
            _loan_payments,
            oracle_cache,
            loan_memos,
            escrow_accounts,
            escrow_deposits,
            micro_loans,
            governance_params,
            authority_grants,
            escalations,
            attestor_failures,
            oracle_trigger_history,
            partial_release_history,
            pending_drawrequests,
            escalation_errors,
            bond_slash_cascade,
            hedge_instruments,
            pool_health_scores,

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
            let (_, bytes) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    eprintln!("[db] Skipping unreadable vertex entry: {}", e);
                    continue;
                }
            };
            match bincode::deserialize::<Vertex>(&bytes) {
                Ok(v) => result.push(v),
                Err(e) => {
                    eprintln!("[db] Skipping vertex with deserialization error: {}", e);
                    continue;
                }
            }
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


    // ── Authority Grants ─────────────────────────────────────────────────────

    /// Save an authority grant keyed by its vertex/tx ID.
    pub fn save_authority_grant(&self, grant_id: &[u8; 32], data: &[u8]) -> Result<(), ChronxError> {
        self.authority_grants.insert(grant_id.as_ref(), data)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Get an authority grant by its vertex/tx ID.
    pub fn get_authority_grant(&self, grant_id: &[u8; 32]) -> Result<Option<Vec<u8>>, ChronxError> {
        match self.authority_grants.get(grant_id.as_ref()) {
            Ok(Some(bytes)) => Ok(Some(bytes.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    /// Iterate all authority grants.
    pub fn iter_authority_grants(&self) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + '_ {
        self.authority_grants.iter().filter_map(|r| {
            r.ok().map(|(k, v)| (k.to_vec(), v.to_vec()))
        })
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

    // ── protocol — Promise packages ──────────────────────────────────────────

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

    // ── protocol — Promise triggers (Day 91 events) ──────────────────────────

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

    // ── protocol — Verifier registry ─────────────────────────────────────────

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
    // ── protocol — Agent registry ────────────────────────────────────────

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

    // ── protocol — Agent loans ───────────────────────────────────────────

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

    // ── protocol — Agent custody records ─────────────────────────────────

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

    // ── protocol — Axiom consents ────────────────────────────────────────

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

    // ── MISAI ExecutorWithdraw ──────────────────────────────────────────

    /// Store an executor withdrawal record keyed by lock_id hex.
    pub fn put_executor_withdrawal(
        &self,
        lock_id_hex: &str,
        record: &ExecutorWithdrawalRecord,
    ) -> Result<(), ChronxError> {
        let b = bincode::serialize(record)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.executor_withdrawals
            .insert(lock_id_hex.as_bytes(), b)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Retrieve an executor withdrawal record by lock_id hex.
    pub fn get_executor_withdrawal(
        &self,
        lock_id_hex: &str,
    ) -> Result<Option<ExecutorWithdrawalRecord>, ChronxError> {
        match self
            .executor_withdrawals
            .get(lock_id_hex.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?
        {
            Some(b) => Ok(Some(
                bincode::deserialize(&b)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Count executor withdrawals submitted in the last `window_secs` seconds.
    pub fn count_recent_executor_withdrawals(&self, now: i64, window_secs: i64) -> Result<u32, ChronxError> {
        let mut count = 0u32;
        let cutoff = now - window_secs;
        for item in self.executor_withdrawals.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: ExecutorWithdrawalRecord = bincode::deserialize(&b)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.submitted_at >= cutoff {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Iterate all executor withdrawal records with status "PendingExecutor".
    pub fn iter_pending_executor_withdrawals(&self) -> Result<Vec<ExecutorWithdrawalRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.executor_withdrawals.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: ExecutorWithdrawalRecord = bincode::deserialize(&b)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.status == "PendingExecutor" {
                out.push(record);
            }
        }
        Ok(out)
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

    // ── protocol — Invoice accessors ─────────────────────────────────────

    pub fn get_invoice(&self, invoice_id: &[u8; 32]) -> Result<Option<InvoiceRecord>, ChronxError> {
        match self.invoices.get(invoice_id) {
            Ok(Some(bytes)) => {
                let record: InvoiceRecord =
                    bincode::deserialize(&bytes).map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn put_invoice(&self, record: &InvoiceRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.invoices.insert(&record.invoice_id, bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn update_invoice_status(&self, invoice_id: &[u8; 32], status: InvoiceStatus, fulfilled_at: Option<u64>, fulfilled_by: Option<Vec<u8>>) -> Result<(), ChronxError> {
        if let Some(mut record) = self.get_invoice(invoice_id)? {
            record.status = status;
            record.fulfilled_at = fulfilled_at;
            record.fulfilled_by = fulfilled_by;
            self.put_invoice(&record)
        } else {
            Err(ChronxError::Other(format!("invoice not found: {}", hex::encode(invoice_id))))
        }
    }

    pub fn iter_invoices_for_wallet(&self, wallet_pubkey: &[u8]) -> Result<Vec<InvoiceRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.invoices.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: InvoiceRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.issuer_pubkey == wallet_pubkey || record.payer_pubkey.as_deref() == Some(wallet_pubkey) {
                results.push(record);
            }
        }
        Ok(results)
    }

    pub fn iter_open_invoices_for_wallet(&self, wallet_pubkey: &[u8]) -> Result<Vec<InvoiceRecord>, ChronxError> {
        Ok(self.iter_invoices_for_wallet(wallet_pubkey)?
            .into_iter()
            .filter(|r| matches!(r.status, InvoiceStatus::Open))
            .collect())
    }

    pub fn iter_all_invoices(&self) -> Result<Vec<InvoiceRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.invoices.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: InvoiceRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            results.push(record);
        }
        Ok(results)
    }

    // ── protocol — Credit accessors ──────────────────────────────────────

    pub fn get_credit(&self, credit_id: &[u8; 32]) -> Result<Option<CreditRecord>, ChronxError> {
        match self.credits.get(credit_id) {
            Ok(Some(bytes)) => {
                let record: CreditRecord =
                    bincode::deserialize(&bytes).map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn put_credit(&self, record: &CreditRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.credits.insert(&record.credit_id, bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn update_credit_drawn(&self, credit_id: &[u8; 32], additional: u64) -> Result<CreditRecord, ChronxError> {
        if let Some(mut record) = self.get_credit(credit_id)? {
            record.drawn_chronos += additional;
            if record.drawn_chronos >= record.ceiling_chronos {
                record.status = CreditStatus::Closed;
            }
            self.put_credit(&record)?;
            Ok(record)
        } else {
            Err(ChronxError::Other(format!("credit not found: {}", hex::encode(credit_id))))
        }
    }

    pub fn update_credit_status(&self, credit_id: &[u8; 32], status: CreditStatus) -> Result<(), ChronxError> {
        if let Some(mut record) = self.get_credit(credit_id)? {
            record.status = status;
            self.put_credit(&record)
        } else {
            Err(ChronxError::Other(format!("credit not found: {}", hex::encode(credit_id))))
        }
    }

    pub fn iter_open_credits_for_wallet(&self, wallet_pubkey: &[u8]) -> Result<Vec<CreditRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.credits.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: CreditRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if matches!(record.status, CreditStatus::Open) &&
               (record.grantor_pubkey == wallet_pubkey || record.beneficiary_pubkey == wallet_pubkey) {
                results.push(record);
            }
        }
        Ok(results)
    }

    pub fn iter_all_credits(&self) -> Result<Vec<CreditRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.credits.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: CreditRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            results.push(record);
        }
        Ok(results)
    }

    // ── protocol — Deposit accessors ─────────────────────────────────────

    pub fn get_deposit(&self, deposit_id: &[u8; 32]) -> Result<Option<DepositRecord>, ChronxError> {
        match self.deposits.get(deposit_id) {
            Ok(Some(bytes)) => {
                let record: DepositRecord =
                    bincode::deserialize(&bytes).map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn put_deposit(&self, record: &DepositRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.deposits.insert(&record.deposit_id, bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn update_deposit_status(&self, deposit_id: &[u8; 32], status: DepositStatus, settled_at: Option<u64>) -> Result<(), ChronxError> {
        if let Some(mut record) = self.get_deposit(deposit_id)? {
            record.status = status;
            record.settled_at = settled_at;
            self.put_deposit(&record)
        } else {
            Err(ChronxError::Other(format!("deposit not found: {}", hex::encode(deposit_id))))
        }
    }

    pub fn iter_active_deposits_for_wallet(&self, wallet_pubkey: &[u8]) -> Result<Vec<DepositRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.deposits.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: DepositRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if matches!(record.status, DepositStatus::Active | DepositStatus::Matured) &&
               (record.depositor_pubkey == wallet_pubkey || record.obligor_pubkey == wallet_pubkey) {
                results.push(record);
            }
        }
        Ok(results)
    }

    pub fn iter_all_deposits(&self) -> Result<Vec<DepositRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.deposits.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: DepositRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            results.push(record);
        }
        Ok(results)
    }

    // ── protocol — Conditional accessors ─────────────────────────────────

    pub fn get_conditional(&self, type_v_id: &[u8; 32]) -> Result<Option<ConditionalRecord>, ChronxError> {
        match self.conditionals.get(type_v_id) {
            Ok(Some(bytes)) => {
                let record: ConditionalRecord =
                    bincode::deserialize(&bytes).map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn put_conditional(&self, record: &ConditionalRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.conditionals.insert(&record.type_v_id, bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn add_attestation(&self, type_v_id: &[u8; 32], attestor_pubkey: Vec<u8>, timestamp: u64) -> Result<ConditionalRecord, ChronxError> {
        if let Some(mut record) = self.get_conditional(type_v_id)? {
            record.attestations_received.push((attestor_pubkey, timestamp));
            self.put_conditional(&record)?;
            Ok(record)
        } else {
            Err(ChronxError::Other(format!("conditional not found: {}", hex::encode(type_v_id))))
        }
    }

    pub fn update_conditional_status(&self, type_v_id: &[u8; 32], status: ConditionalStatus) -> Result<(), ChronxError> {
        if let Some(mut record) = self.get_conditional(type_v_id)? {
            record.status = status;
            self.put_conditional(&record)
        } else {
            Err(ChronxError::Other(format!("conditional not found: {}", hex::encode(type_v_id))))
        }
    }

    pub fn iter_all_conditionals(&self) -> Result<Vec<ConditionalRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.conditionals.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: ConditionalRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            results.push(record);
        }
        Ok(results)
    }

    // ── protocol — Ledger Entry accessors ────────────────────────────────

    pub fn put_ledger_entry(&self, record: &LedgerEntryRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.ledger_entries.insert(&record.entry_id, bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;

        // Update promise_id secondary index
        if let Some(promise_id) = &record.promise_id {
            let mut entry_ids: Vec<[u8; 32]> = match self.ledger_promise_index.get(promise_id) {
                Ok(Some(bytes)) => bincode::deserialize(&bytes).unwrap_or_default(),
                _ => Vec::new(),
            };
            entry_ids.push(record.entry_id);
            let idx_bytes = bincode::serialize(&entry_ids).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            self.ledger_promise_index.insert(promise_id.as_ref(), idx_bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    pub fn get_ledger_entry(&self, entry_id: &[u8; 32]) -> Result<Option<LedgerEntryRecord>, ChronxError> {
        match self.ledger_entries.get(entry_id) {
            Ok(Some(bytes)) => {
                let record: LedgerEntryRecord =
                    bincode::deserialize(&bytes).map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn get_ledger_entries_by_promise(&self, promise_id: &[u8; 32]) -> Result<Vec<LedgerEntryRecord>, ChronxError> {
        let entry_ids: Vec<[u8; 32]> = match self.ledger_promise_index.get(promise_id) {
            Ok(Some(bytes)) => bincode::deserialize(&bytes).unwrap_or_default(),
            _ => return Ok(Vec::new()),
        };
        let mut results = Vec::new();
        for eid in entry_ids {
            if let Some(record) = self.get_ledger_entry(&eid)? {
                results.push(record);
            }
        }
        Ok(results)
    }

    pub fn ledger_entry_exists(&self, entry_id: &[u8; 32]) -> bool {
        self.ledger_entries.contains_key(entry_id).unwrap_or(false)
    }


    // ── Identity verification accessors ───────────────────────────────

    pub fn add_identity_entry(&self, wallet_b58: &str, entry_id: [u8; 32]) -> Result<(), ChronxError> {
        let key = wallet_b58.as_bytes();
        let mut entry_ids: Vec<[u8; 32]> = match self.identity_index.get(key) {
            Ok(Some(bytes)) => bincode::deserialize(&bytes).unwrap_or_default(),
            _ => Vec::new(),
        };
        entry_ids.push(entry_id);
        let bytes = bincode::serialize(&entry_ids).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.identity_index.insert(key, bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_identity_entries(&self, wallet_b58: &str) -> Result<Vec<LedgerEntryRecord>, ChronxError> {
        let key = wallet_b58.as_bytes();
        let entry_ids: Vec<[u8; 32]> = match self.identity_index.get(key) {
            Ok(Some(bytes)) => bincode::deserialize(&bytes).unwrap_or_default(),
            _ => return Ok(Vec::new()),
        };
        let mut results = Vec::new();
        for eid in entry_ids {
            if let Some(record) = self.get_ledger_entry(&eid)? {
                results.push(record);
            }
        }
        results.sort_by_key(|r| r.timestamp);
        Ok(results)
    }

    pub fn badge_blackouts_insert(&self, wallet_b58: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.badge_blackouts.insert(wallet_b58.as_bytes(), data)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_badge_blackout(&self, wallet_b58: &str) -> Result<Option<serde_json::Value>, ChronxError> {
        match self.badge_blackouts.get(wallet_b58.as_bytes()) {
            Ok(Some(bytes)) => {
                let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                Ok(Some(val))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn get_latest_identity(&self, wallet_b58: &str, now_unix: u64) -> Result<Option<IdentityRecord>, ChronxError> {
        let entries = self.get_identity_entries(wallet_b58)?;
        if entries.is_empty() {
            return Ok(None);
        }
        // Most recent entry wins
        let latest = entries.last().unwrap();
        let is_verified = latest.entry_type == "IdentityVerified";
        // Parse content_summary as JSON
        let summary_str = String::from_utf8_lossy(&latest.content_summary).to_string();
        let parsed: serde_json::Value = serde_json::from_str(&summary_str).unwrap_or_default();
        let display_name = parsed.get("display").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let badge_code = parsed.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let badge_color = parsed.get("color").and_then(|v| v.as_str()).map(|s| s.to_string());
        let expires_at_val = parsed.get("expires").and_then(|v| v.as_u64());
        let expires_at = if expires_at_val == Some(0) { None } else { expires_at_val };
        let issuer_notes = parsed.get("notes").and_then(|v| v.as_str()).map(|s| s.to_string());
        // Check expiry
        let verified = if is_verified {
            match expires_at {
                Some(exp) if now_unix > exp => false,
                _ => true,
            }
        } else {
            false
        };
        let issuer_b58 = hex::encode(&latest.author_pubkey);
        Ok(Some(IdentityRecord {
            wallet_b58: wallet_b58.to_string(),
            issuer_wallet_b58: issuer_b58,
            display_name,
            badge_code,
            badge_color,
            verified,
            entry_id: latest.entry_id,
            issued_at: latest.timestamp,
            expires_at,
            issuer_notes,
        }))
    }

    // ── convert_to field accessors ────────────────────────────────────

    pub fn put_convert_to_suggestion(&self, lock_id: &chronx_core::types::TxId, value: &str) -> Result<(), ChronxError> {
        self.convert_to_suggestion.insert(lock_id.as_bytes(), value.as_bytes())
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_convert_to_suggestion(&self, lock_id: &chronx_core::types::TxId) -> Result<Option<String>, ChronxError> {
        match self.convert_to_suggestion.get(lock_id.as_bytes()) {
            Ok(Some(bytes)) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    // ── protocol — Sign of Life accessors ────────────────────────────

    pub fn get_sign_of_life(&self, lock_id: &str) -> Result<Option<SignOfLifeRecord>, ChronxError> {
        match self.sign_of_life.get(lock_id.as_bytes()) {
            Ok(Some(bytes)) => {
                let record: SignOfLifeRecord =
                    bincode::deserialize(&bytes).map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn put_sign_of_life(&self, lock_id: &str, record: &SignOfLifeRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.sign_of_life.insert(lock_id.as_bytes(), bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn iter_active_sign_of_life(&self) -> Result<Vec<SignOfLifeRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.sign_of_life.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: SignOfLifeRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.status == "Active" || record.status == "GracePeriod" {
                results.push(record);
            }
        }
        Ok(results)
    }

    // ── protocol — Promise Chain accessors ───────────────────────────

    pub fn get_promise_chain(&self, promise_id: &[u8; 32]) -> Result<Option<PromiseChainRecord>, ChronxError> {
        match self.promise_chains.get(promise_id) {
            Ok(Some(bytes)) => {
                let record: PromiseChainRecord =
                    bincode::deserialize(&bytes).map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn put_promise_chain(&self, record: &PromiseChainRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.promise_chains.insert(&record.promise_id, bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn iter_all_promise_chains(&self) -> Result<Vec<PromiseChainRecord>, ChronxError> {
        let mut results = Vec::new();
        for kv in self.promise_chains.iter() {
            let (_, v) = kv.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: PromiseChainRecord =
                bincode::deserialize(&v).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            results.push(record);
        }
        Ok(results)
    }


    // ── protocol: Wallet Group accessors ────────────────────────────────────

    pub fn get_group(&self, group_id: &[u8; 32]) -> Result<Option<chronx_core::transaction::GroupRecord>, ChronxError> {
        match self.groups.get(group_id).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(bytes) => {
                let record: chronx_core::transaction::GroupRecord =
                    bincode::deserialize(&bytes).map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    pub fn put_group(&self, record: &chronx_core::transaction::GroupRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.groups.insert(&record.group_id, bytes).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn is_group_member(&self, group_id: &[u8; 32], pubkey: &chronx_core::types::DilithiumPublicKey) -> Result<bool, ChronxError> {
        match self.get_group(group_id)? {
            Some(record) => {
                if record.status == chronx_core::transaction::GroupStatus::Dissolved {
                    return Ok(false);
                }
                Ok(record.members.iter().any(|m| m == pubkey))
            }
            None => Ok(false),
        }
    }

}

// ── Genesis 10a — Loan storage types ───────────────────────────────────────

use chronx_core::transaction::{
    PayAsDenomination, LoanPaymentStage, LateFeeSchedule,
    PrepaymentTerms, HedgeRequirement, OraclePolicy,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum LoanStatus {
    Active,
    Defaulted { defaulted_at: u64 },
    Reinstated { reinstated_at: u64 },
    WrittenOff { written_off_at: u64, outstanding_kx: u64 },
    Completed { completed_at: u64 },
    EarlyPayoff { paid_off_at: u64 },
    AcceptedPendingRescission { rescission_expires_at: u64 },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoanRecord {
    pub loan_id: [u8; 32],
    pub lender: String,
    pub borrower: String,
    pub principal_kx: u64,
    pub pay_as: PayAsDenomination,
    pub stages: Vec<LoanPaymentStage>,
    pub prepayment: PrepaymentTerms,
    pub late_fee_schedule: LateFeeSchedule,
    pub grace_period_days: u8,
    pub hedge_requirement: Option<HedgeRequirement>,
    pub oracle_policy: OraclePolicy,
    pub agreement_hash: Option<[u8; 32]>,
    pub status: LoanStatus,
    pub created_at: u64,
    pub memo: Option<String>,

    /// Child chain anchor for payment history.
    #[serde(default)]
    pub child_chain_id: Option<String>,

    /// Rescission window expiry timestamp.
    #[serde(default)]
    pub rescission_expires_at: Option<i64>,

    /// Borrower age confirmation.
    #[serde(default)]
    pub age_confirmed: bool,

    /// Credit history visibility preference.
    #[serde(default)]
    pub credit_visibility: chronx_core::transaction::CreditVisibility,

    /// Timestamp of last interest payment settlement.
    #[serde(default)]
    pub last_payment_at: Option<i64>,

    #[serde(default)]
    pub prune_after_timestamp: Option<i64>,
    #[serde(default)]
    pub credit_weight_at_creation: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoanDefaultRecord {
    pub loan_id: [u8; 32],
    pub missed_stage_index: u32,
    pub missed_amount_kx: u64,
    pub late_fees_accrued_kx: u64,
    pub days_overdue: u32,
    pub outstanding_balance_kx: u64,
    pub stages_remaining: u32,
    pub defaulted_at: u64,
    pub memo: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OraclePriceRecord {
    pub pair: String,
    pub spot_price_micro: u64,
    pub seven_day_avg_micro: u64,
    pub last_updated: u64,
    pub source: String,
    pub retry_count: u8,
}

impl StateDb {
    /// Store JSON loan data by loan_id
    pub fn save_loan(&self, loan_id: &[u8; 32], data: &[u8]) -> Result<(), ChronxError> {
        self.loans.insert(loan_id.as_ref(), data)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Get JSON loan data by loan_id
    pub fn get_loan(&self, loan_id: &[u8; 32]) -> Result<Option<Vec<u8>>, ChronxError> {
        match self.loans.get(loan_id.as_ref()) {
            Ok(Some(bytes)) => Ok(Some(bytes.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    /// Iterate all raw loan entries (for RPC scan)

    // -- Escalation/failure/hedge scaffold trees --

    pub fn save_escalation(&self, id: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.escalations.insert(id.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn get_escalation(&self, id: &str) -> Result<Option<Vec<u8>>, ChronxError> {
        self.escalations.get(id.as_bytes()).map(|opt| opt.map(|v| v.to_vec())).map_err(|_| ChronxError::DatabaseError)
    }

    pub fn save_attestor_failure(&self, id: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.attestor_failures.insert(id.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn save_partial_release(&self, type_v_id: &[u8; 32], data: &[u8]) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        let existing = self.partial_release_history.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)?.map(|v| v.to_vec()).unwrap_or_default();
        let mut history: Vec<serde_json::Value> = if existing.is_empty() { vec![] } else { serde_json::from_slice(&existing).unwrap_or_default() };
        let entry: serde_json::Value = serde_json::from_slice(data).unwrap_or_default();
        history.push(entry);
        let serialized = serde_json::to_vec(&history).map_err(|_| ChronxError::SerializationError)?;
        self.partial_release_history.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn get_partial_release_history(&self, type_v_id: &[u8; 32]) -> Result<Vec<serde_json::Value>, ChronxError> {
        let key = hex::encode(type_v_id);
        match self.partial_release_history.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)? {
            Some(data) => Ok(serde_json::from_slice(&data).unwrap_or_default()),
            None => Ok(vec![]),
        }
    }

    pub fn save_oracle_trigger_event(&self, type_v_id: &[u8; 32], data: &[u8]) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        let existing = self.oracle_trigger_history.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)?.map(|v| v.to_vec()).unwrap_or_default();
        let mut history: Vec<serde_json::Value> = if existing.is_empty() { vec![] } else { serde_json::from_slice(&existing).unwrap_or_default() };
        let entry: serde_json::Value = serde_json::from_slice(data).unwrap_or_default();
        history.push(entry);
        let serialized = serde_json::to_vec(&history).map_err(|_| ChronxError::SerializationError)?;
        self.oracle_trigger_history.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn save_pending_drawrequest(&self, key: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.pending_drawrequests.insert(key.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn iter_pending_drawrequests(&self) -> Result<Vec<(String, serde_json::Value)>, ChronxError> {
        let mut results = vec![];
        for item in self.pending_drawrequests.iter() {
            let (k, v) = item.map_err(|_| ChronxError::DatabaseError)?;
            results.push((String::from_utf8_lossy(&k).to_string(), serde_json::from_slice(&v).unwrap_or_default()));
        }
        Ok(results)
    }

    pub fn remove_pending_drawrequest(&self, key: &str) -> Result<(), ChronxError> {
        self.pending_drawrequests.remove(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn save_escalation_error(&self, lock_id: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.escalation_errors.insert(lock_id.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn get_conditionals_by_attestor_group(&self, _group_id: &str) -> Result<Vec<ConditionalRecord>, ChronxError> {
        let mut results = vec![];
        for item in self.conditionals.iter() {
            let (_k, v) = item.map_err(|_| ChronxError::DatabaseError)?;
            if let Ok(record) = serde_json::from_slice::<ConditionalRecord>(&v) {
                if matches!(record.status, ConditionalStatus::Pending | ConditionalStatus::PartiallyReleased) {
                    results.push(record);
                }
            }
        }
        Ok(results)
    }

    pub fn set_conditional_attestors_suspended(&self, type_v_id: &[u8; 32], suspended: bool) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        if let Some(data) = self.conditionals.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)? {
            let mut record: ConditionalRecord = serde_json::from_slice(&data).map_err(|_| ChronxError::SerializationError)?;
            record.attestors_suspended = suspended;
            let serialized = serde_json::to_vec(&record).map_err(|_| ChronxError::SerializationError)?;
            self.conditionals.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        }
        Ok(())
    }

    pub fn set_conditional_escalation_active(&self, type_v_id: &[u8; 32], active: bool) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        if let Some(data) = self.conditionals.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)? {
            let mut record: ConditionalRecord = serde_json::from_slice(&data).map_err(|_| ChronxError::SerializationError)?;
            record.escalation_active = active;
            let serialized = serde_json::to_vec(&record).map_err(|_| ChronxError::SerializationError)?;
            self.conditionals.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        }
        Ok(())
    }

    /// Write a ConditionalRecord directly (for engine partial release updates).
    pub fn put_conditional_raw(&self, type_v_id: &[u8; 32], record: &ConditionalRecord) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        let serialized = serde_json::to_vec(record).map_err(|_| ChronxError::SerializationError)?;
        self.conditionals.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }



    pub fn get_attestor_failure(&self, id: &str) -> Result<Option<Vec<u8>>, ChronxError> {
        self.attestor_failures.get(id.as_bytes()).map(|opt| opt.map(|v| v.to_vec())).map_err(|_| ChronxError::DatabaseError)
    }

    pub fn iter_attestor_failures(&self) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + '_ {
        self.attestor_failures.iter().filter_map(|r| r.ok()).map(|(k, v)| (k.to_vec(), v.to_vec()))
    }

    pub fn save_bond_slash(&self, id: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.bond_slash_cascade.insert(id.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn get_bond_slash(&self, id: &str) -> Result<Option<Vec<u8>>, ChronxError> {
        self.bond_slash_cascade.get(id.as_bytes()).map(|opt| opt.map(|v| v.to_vec())).map_err(|_| ChronxError::DatabaseError)
    }

    pub fn save_hedge_instrument(&self, id: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.hedge_instruments.insert(id.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn get_hedge_instrument(&self, id: &str) -> Result<Option<Vec<u8>>, ChronxError> {
        self.hedge_instruments.get(id.as_bytes()).map(|opt| opt.map(|v| v.to_vec())).map_err(|_| ChronxError::DatabaseError)
    }

    pub fn iter_hedge_instruments(&self) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + '_ {
        self.hedge_instruments.iter().filter_map(|r| r.ok()).map(|(k, v)| (k.to_vec(), v.to_vec()))
    }

    pub fn save_pool_health_score(&self, pool_id: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.pool_health_scores.insert(pool_id.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn get_pool_health_score(&self, pool_id: &str) -> Result<Option<Vec<u8>>, ChronxError> {
        self.pool_health_scores.get(pool_id.as_bytes()).map(|opt| opt.map(|v| v.to_vec())).map_err(|_| ChronxError::DatabaseError)
    }

    pub fn iter_loans(&self) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + '_ {
        self.loans.iter()
            .filter_map(|r| r.ok())
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
    }

        pub fn get_oracle_price(&self, pair: &str) -> Result<Option<OraclePriceRecord>, ChronxError> {
        match self.oracle_cache.get(pair.as_bytes()) {
            Ok(Some(bytes)) => {
                let record: OraclePriceRecord = bincode::deserialize(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    pub fn save_oracle_price(&self, record: &OraclePriceRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.oracle_cache.insert(record.pair.as_bytes(), bytes)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_active_loans(&self) -> Result<Vec<LoanRecord>, ChronxError> {
        let mut loans = Vec::new();
        for item in self.loans.iter() {
            let (_, bytes) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: LoanRecord = bincode::deserialize(&bytes)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            match record.status {
                LoanStatus::Active | LoanStatus::Reinstated { .. } => loans.push(record),
                _ => {}
            }
        }
        Ok(loans)
    }

    /// Return all loans where the given wallet is either lender or borrower.
    pub fn get_loans_by_wallet(&self, wallet: &str) -> Result<Vec<LoanRecord>, ChronxError> {
        let mut loans = Vec::new();
        for item in self.loans.iter() {
            let (_, bytes) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: LoanRecord = bincode::deserialize(&bytes)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.lender == wallet || record.borrower == wallet {
                loans.push(record);
            }
        }
        Ok(loans)
    }

    /// Return all loans in the database.
    pub fn get_all_loans(&self) -> Result<Vec<LoanRecord>, ChronxError> {
        let mut loans = Vec::new();
        for item in self.loans.iter() {
            let (_, bytes) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: LoanRecord = bincode::deserialize(&bytes)
                .map_err(|e| ChronxError::Serialization(e.to_string()))?;
            loans.push(record);
        }
        Ok(loans)
    }

    /// Save a default record for a loan into the loan_defaults tree.
    pub fn save_loan_default(&self, loan_id: &[u8; 32], record: &LoanDefaultRecord) -> Result<(), ChronxError> {
        let bytes = bincode::serialize(record)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.loan_defaults.insert(loan_id, bytes)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Get the default record for a loan.
    pub fn get_loan_default(&self, loan_id: &[u8; 32]) -> Result<Option<LoanDefaultRecord>, ChronxError> {
        match self.loan_defaults.get(loan_id) {
            Ok(Some(bytes)) => {
                let record: LoanDefaultRecord = bincode::deserialize(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    // ── Loan escrow deposit methods ──────────────────────────────────────────
    // Key: loan_id bytes (32), Value: JSON { lender_wallet, amount_chronos, expires_at }

    /// Store a loan escrow deposit (lender funds held during rescission window).
    pub fn put_loan_escrow(&self, loan_id: &[u8; 32], lender_wallet: &str, amount_chronos: u128, expires_at: i64) -> Result<(), ChronxError> {
        let record = serde_json::json!({
            "lender_wallet": lender_wallet,
            "amount_chronos": amount_chronos.to_string(),
            "expires_at": expires_at,
        });
        let val = serde_json::to_vec(&record)
            .map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.escrow_deposits.insert(loan_id.as_ref(), val)
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Get a loan escrow deposit by loan_id.
    pub fn get_loan_escrow(&self, loan_id: &[u8; 32]) -> Result<Option<serde_json::Value>, ChronxError> {
        match self.escrow_deposits.get(loan_id.as_ref()) {
            Ok(Some(bytes)) => {
                let val: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| ChronxError::Serialization(e.to_string()))?;
                Ok(Some(val))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChronxError::Storage(e.to_string())),
        }
    }

    /// Remove a loan escrow deposit (after release to borrower or return to lender).
    pub fn remove_loan_escrow(&self, loan_id: &[u8; 32]) -> Result<(), ChronxError> {
        self.escrow_deposits.remove(loan_id.as_ref())
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Iterate all loan escrow deposits. Returns (loan_id_bytes, JSON value).
    pub fn iter_loan_escrows(&self) -> Vec<(Vec<u8>, serde_json::Value)> {
        self.escrow_deposits.iter()
            .filter_map(|r| r.ok())
            .filter_map(|(k, v)| {
                let val: serde_json::Value = serde_json::from_slice(&v).ok()?;
                Some((k.to_vec(), val))
            })
            .collect()
    }

    /// Get all loan escrow deposits for a specific wallet (as lender).
    pub fn get_loan_escrows_by_wallet(&self, wallet: &str) -> Result<Vec<(String, u128, i64)>, ChronxError> {
        let mut results = Vec::new();
        for (key, val) in self.iter_loan_escrows() {
            if val.get("lender_wallet").and_then(|v| v.as_str()) == Some(wallet) {
                let amount: u128 = val.get("amount_chronos")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let expires = val.get("expires_at").and_then(|v| v.as_i64()).unwrap_or(0);
                let loan_id_hex = hex::encode(&key);
                results.push((loan_id_hex, amount, expires));
            }
        }
        Ok(results)
    }
}
