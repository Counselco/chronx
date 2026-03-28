use serde::{Deserialize, Serialize};

/// P2P network identity returned by `chronx_getNetworkInfo`.
/// The `peer_multiaddr` field is the full libp2p multiaddress (including
/// `/p2p/<PeerId>`) that other nodes should pass as `--bootstrap` to
/// connect to this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNetworkInfo {
    pub peer_multiaddr: String,
    pub peer_count: u64,
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
    // ── V4 email-lock & series fields ────────────────────────────────────
    /// Hex of BLAKE3(claim_code) extracted from lock_marker (0xC5 marker).
    /// Locks sharing the same hash belong to the same Promise Series.
    pub claim_secret_hash: Option<String>,
    /// Cancellation window in seconds (72 h for email locks, 24 h for ≥1-year locks).
    pub cancellation_window_secs: Option<u32>,
    /// Hex of BLAKE3(recipient_email) — used for email-lock discovery.
    pub email_recipient_hash: Option<String>,
    /// Seconds from creation the recipient has to claim.
    pub claim_window_secs: Option<u64>,
    /// What happens if claim window expires: "RevertToSender", "Burn", or "ForwardTo(<id>)".
    pub unclaimed_action: Option<String>,
    /// Lock type tag (e.g. "S" = standard, "M" = AI-managed).
    pub lock_type: Option<String>,
    /// JSON metadata associated with this lock.
    pub lock_metadata: Option<String>,
    /// Suggestion-only conversion currency hint.
    pub convert_to: Option<String>,
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
    pub node_rewards_kx: String,
    pub node_rewards_start: i64,
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
            node_rewards_kx: NODE_REWARDS_KX.to_string(),
            node_rewards_start: TREASURY_START_TIMESTAMP,
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
    /// Hex-encoded BLAKE3 balance Merkle root (None if not yet computed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
}

/// State root and vertex count returned by `chronx_getStateRoot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcStateRoot {
    /// Hex-encoded BLAKE3 balance Merkle root.
    pub root: String,
    /// Total number of vertices (transaction count / "block height").
    pub vertex_count: u64,
}

/// Supply invariant verification result returned by `chronx_verifySupplyInvariant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcSupplyInvariant {
    /// Sum of all account balances (Chronos).
    pub total_spendable_chronos: String,
    /// Sum of all active (non-terminal) timelock amounts (Chronos).
    pub total_locked_chronos: String,
    /// total_spendable + total_locked (Chronos).
    pub total_chronos: String,
    /// Expected total: TOTAL_SUPPLY_CHRONOS.
    pub expected_chronos: String,
    /// Whether the invariant holds.
    pub invariant_holds: bool,
}

/// Lightweight global lock statistics returned by `chronx_getLockStats`.
/// Used by the website stats bar to show active promise count and total KX locked
/// without fetching every timelock contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcGlobalLockStats {
    /// Number of timelocks currently in Pending (active) state.
    pub active_lock_count: u64,
    /// Sum of `amount_chronos` across all Pending timelocks (as a decimal string).
    pub total_locked_chronos: String,
    /// Same amount expressed in whole KX (as a decimal string).
    pub total_locked_kx: String,
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

// ── V4 Cascade Send types ───────────────────────────────────────────────────

/// Details of a cascade (multiple locks sharing a claim_secret_hash).
/// Returned by `chronx_getCascadeDetails`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCascadeDetails {
    /// The shared claim_secret_hash (hex).
    pub claim_secret_hash: String,
    /// Number of locks in this cascade.
    pub lock_count: u32,
    /// Total amount across all locks (Chronos as string).
    pub total_chronos: String,
    /// Total amount in KX.
    pub total_kx: String,
    /// Number of locks still Pending.
    pub pending_count: u32,
    /// Number of locks already Claimed.
    pub claimed_count: u32,
    /// All locks in this cascade.
    pub locks: Vec<RpcTimeLock>,
}

/// Input for a single entry in a cascade send.
/// Used by `chronx_submitCascade`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCascadeEntry {
    /// Amount in KX (decimal string, e.g. "100.5").
    pub amount_kx: String,
    /// Unlock timestamp (Unix seconds UTC).
    pub unlock_at: i64,
    /// Optional memo.
    pub memo: Option<String>,
}

/// A single incoming transaction for an account, returned by `chronx_getIncomingTransfers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcIncomingTransfer {
    /// The transaction ID (hex) that carried this transfer.
    pub tx_id: String,
    /// Base-58 account ID of the sender.
    pub from: String,
    /// Amount received in Chronos (u128 as string).
    pub amount_chronos: String,
    /// Amount received in KX (whole units as string).
    pub amount_kx: String,
    /// Unix timestamp of the transaction.
    pub timestamp: i64,
    /// One of: "transfer", "email_claim", "timelock_claim"
    pub tx_type: String,
    /// Optional memo (from timelocks).
    pub memo: Option<String>,
}




/// A single outgoing transaction for an account, returned by .
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcOutgoingTransfer {
    /// The transaction ID (hex) that carried this transfer.
    pub tx_id: String,
    /// Base-58 account ID of the recipient.
    pub to: String,
    /// Amount sent in Chronos (u128 as string).
    pub amount_chronos: String,
    /// Amount sent in KX (whole units as string).
    pub amount_kx: String,
    /// Unix timestamp of the transaction.
    pub timestamp: i64,
    /// One of: "transfer", "email_send", "promise_sent"
    pub tx_type: String,
    /// Optional memo.
    pub memo: Option<String>,
}
// ── Verified Delivery Protocol RPC types ─────────────────────────

/// Verifier registry entry returned by `chronx_getVerifierRegistry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcVerifierRecord {
    pub verifier_name: String,
    pub wallet_address: String,
    pub bond_amount_kx: u64,
    pub jurisdiction: String,
    pub role: String,
    pub approval_date: u64,
    pub status: String,
}

/// Promise trigger status returned by `chronx_getPromiseTriggerStatus`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcPromiseTriggerStatus {
    pub lock_id: String,
    pub trigger_fired_at: u64,
    pub package_routed_to: String,
    pub activation_deposit_chronos: u64,
    pub remaining_chronos: u64,
    pub expiry_at: u64,
}

/// Humanity Stake Pool balance returned by `chronx_getHumanityStakeBalance`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcHumanityStakeBalance {
    pub balance_chronos: String,
    pub balance_kx: String,
}

/// Promise axioms returned by `chronx_getPromiseAxioms`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcPromiseAxioms {
    pub promise_axioms: String,
    pub trading_axioms: String,
    /// BLAKE3 hash of (promise_axioms || trading_axioms) — wallets use this
    /// to compute axiom consent hashes without recalculating.
    pub combined_axiom_hash: String,
}

// ── AI Agent Architecture RPC types ──────────────────────────────

/// Agent registry entry returned by `chronx_getAgentRegistry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAgentRecord {
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

/// Agent loan record returned by `chronx_getAgentLoanRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAgentLoanRecord {
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
    pub disbursed_at: u64,
    pub returned_at: u64,
    pub returned_chronos: u64,
    pub status: String,
}

/// Agent custody record returned by `chronx_getAgentCustodyRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAgentCustodyRecord {
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

/// Axiom consent record returned by `chronx_getAxiomConsent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAxiomConsentRecord {
    pub lock_id: String,
    pub party_type: String,
    pub party_wallet: String,
    pub axiom_hash: String,
    pub consented_at: u64,
}

/// Investable promise summary returned by `chronx_getInvestablePromises`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcInvestablePromise {
    pub lock_id: String,
    pub sender: String,
    pub amount_chronos: String,
    pub amount_kx: String,
    pub unlock_at: i64,
    pub lock_type: Option<String>,
    pub lock_metadata: Option<String>,
}

// ── Admin-facing detailed transaction types ─────────────────────────────────

/// A parsed action summary for the admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcActionSummary {
    pub action_type: String,
    pub to_address: Option<String>,
    pub amount_chronos: Option<String>,
    pub amount_kx: Option<String>,
    pub lock_until: Option<i64>,
    pub memo: Option<String>,
    pub email_hash: Option<String>,
    pub lock_id: Option<String>,
}

/// A detailed recent transaction returned by `chronx_getRecentTransactionsDetailed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDetailedTx {
    pub tx_id: String,
    pub timestamp: i64,
    pub from: String,
    pub action_count: usize,
    pub depth: u64,
    pub actions: Vec<RpcActionSummary>,
    pub memo: Option<String>,
}

// ── Invoice/Credit/Deposit/Conditional/Ledger RPC types ─────────

/// Invoice record returned by `chronx_getInvoice`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcInvoiceRecord {
    pub invoice_id: String,
    pub issuer_pubkey: String,
    pub payer_pubkey: Option<String>,
    pub amount_chronos: String,
    pub amount_kx: String,
    pub expiry: u64,
    pub status: String,
    pub created_at: u64,
    pub fulfilled_at: Option<u64>,
}

/// Credit authorization returned by `chronx_getCreditAuthorization`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCreditRecord {
    pub credit_id: String,
    pub grantor_pubkey: String,
    pub beneficiary_pubkey: String,
    pub ceiling_chronos: String,
    pub ceiling_kx: String,
    pub per_draw_max_chronos: Option<String>,
    pub expiry: u64,
    pub drawn_chronos: String,
    pub drawn_kx: String,
    pub status: String,
    pub created_at: u64,
}

/// Deposit record returned by `chronx_getDeposit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDepositRecord {
    pub deposit_id: String,
    pub depositor_pubkey: String,
    pub obligor_pubkey: String,
    pub principal_chronos: u64,
    pub principal_kx: f64,
    pub rate_basis_points: u64,
    pub term_seconds: u64,
    pub compounding: String,
    pub maturity_timestamp: u64,
    pub total_due_chronos: u64,
    pub total_due_kx: f64,
    pub status: String,
    pub created_at: u64,
    pub settled_at: Option<u64>,
}

/// Conditional payment returned by `chronx_getConditionalPayment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConditionalRecord {
    pub type_v_id: String,
    pub sender_pubkey: String,
    pub recipient_pubkey: String,
    pub amount_chronos: String,
    pub amount_kx: String,
    pub min_attestors: u32,
    pub attestations_received: u32,
    pub valid_until: u64,
    pub fallback: String,
    pub status: String,
    pub created_at: u64,
}

/// Ledger entry returned by `chronx_getLedgerEntries`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcLedgerEntryRecord {
    pub entry_id: String,
    pub author_pubkey: String,
    pub promise_id: Option<String>,
    pub entry_type: String,
    pub content_hash: String,
    pub content_summary: String,
    pub timestamp: u64,
}


// ── Sign of Life and Promise Chain RPC types ────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcSignOfLifeRecord {
    pub lock_id: String,
    pub interval_days: u64,
    pub grace_days: u64,
    pub last_attestation: u64,
    pub next_due: u64,
    pub status: String,
    pub responsible: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcPromiseChainRecord {
    pub promise_id: String,
    pub entry_count: u32,
    pub last_anchor_hash: Option<String>,
    pub last_anchor_at: Option<u64>,
    pub created_at: u64,
}


// ── Identity Verification RPC types ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcIdentityRecord {
    pub wallet: String,
    pub issuer_wallet: String,
    pub display_name: String,
    pub badge_code: String,
    pub badge_color: Option<String>,
    pub verified: bool,
    pub entry_id: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub issuer_notes: Option<String>,
}



// ── Genesis 10a — Loan RPC types ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcLoanRecord {
    pub loan_id: String,
    pub lender: String,
    pub borrower: String,
    pub principal_kx: u64,
    pub pay_as: String,
    pub stages: Vec<RpcLoanPaymentStage>,
    pub prepayment: String,
    pub late_fee_schedule: String,
    pub grace_period_days: u8,
    pub hedge_requirement: Option<String>,
    pub oracle_policy: String,
    pub agreement_hash: Option<String>,
    pub status: String,
    pub created_at: u64,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcLoanPaymentStage {
    pub stage_index: u32,
    pub due_at: u64,
    pub amount_kx: u64,
    pub pay_as: String,
    pub payment_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcLoanDefaultRecord {
    pub loan_id: String,
    pub missed_stage_index: u32,
    pub missed_amount_kx: u64,
    pub late_fees_accrued_kx: u64,
    pub days_overdue: u32,
    pub outstanding_balance_kx: u64,
    pub stages_remaining: u32,
    pub defaulted_at: u64,
    pub memo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcOraclePrice {
    pub pair: String,
    pub spot_price_micro: u64,
    pub seven_day_avg_micro: u64,
    pub last_updated: u64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcLoanCounts {
    pub active: u64,
    pub defaulted: u64,
    pub completed: u64,
    pub written_off: u64,
    pub early_payoff: u64,
    pub reinstated: u64,
}

// ── Child Chain types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcChildChainRecord {
    pub namespace: String,
    pub record_id: String,
    pub payload: String,
    pub payload_hash: String,
    pub dag_vertex_id: String,
    pub stored_at: u64,
    pub previous_record_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcChildChainNamespaceInfo {
    pub namespace: String,
    pub display_name: String,
    pub description: String,
    pub record_count: u64,
    pub status: String,
    pub approved_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcChildChainStats {
    pub namespace: String,
    pub total_records: u64,
    pub records_today: u64,
    pub oldest_record_timestamp: u64,
    pub newest_record_timestamp: u64,
    pub daily_limit: u64,
    pub daily_remaining: u64,
}
