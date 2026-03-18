use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::{
    RpcAccount, RpcCascadeDetails, RpcChainStats, RpcClaimState, RpcGenesisInfo,
    RpcGlobalLockStats, RpcHumanityStakeBalance, RpcIncomingTransfer, RpcNetworkInfo,
    RpcOracleSnapshot, RpcPromiseAxioms, RpcPromiseTriggerStatus, RpcProvider, RpcRecentTx,
    RpcSchema, RpcSearchQuery, RpcTimeLock, RpcVerifierRecord, RpcVersionInfo,
    RpcAgentRecord, RpcAgentLoanRecord, RpcAgentCustodyRecord, RpcAxiomConsentRecord, RpcInvestablePromise,
};

/// ChronX JSON-RPC 2.0 API definition.
///
/// All method names are prefixed with "chronx_" via `namespace = "chronx"`.
#[rpc(server, namespace = "chronx")]
pub trait ChronxApi {
    /// Get full account state by base-58 account ID.
    #[method(name = "getAccount")]
    async fn get_account(&self, account_id: String) -> RpcResult<Option<RpcAccount>>;

    /// Get balance in Chronos by base-58 account ID.
    #[method(name = "getBalance")]
    async fn get_balance(&self, account_id: String) -> RpcResult<String>;

    /// Submit a signed transaction. `tx_hex` is hex-encoded bincode(Transaction).
    /// Returns the TxId hex on success.
    #[method(name = "sendTransaction")]
    async fn send_transaction(&self, tx_hex: String) -> RpcResult<String>;

    /// Get a transaction (DAG vertex) by its TxId hex.
    /// Returns hex-encoded bincode(Transaction) or null if not found.
    #[method(name = "getTransaction")]
    async fn get_transaction(&self, tx_id: String) -> RpcResult<Option<String>>;

    /// List time-lock contracts where `account_id` is the sender or recipient.
    /// Sorted newest-first.
    #[method(name = "getTimeLockContracts")]
    async fn get_timelock_contracts(&self, account_id: String) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return the current DAG tip TxIds (as hex strings).
    #[method(name = "getDagTips")]
    async fn get_dag_tips(&self) -> RpcResult<Vec<String>>;

    /// Return genesis/protocol constants.
    #[method(name = "getGenesisInfo")]
    async fn get_genesis_info(&self) -> RpcResult<RpcGenesisInfo>;

    /// Return the node's P2P identity (peer multiaddress).
    /// Other nodes pass this as `--bootstrap` to connect.
    #[method(name = "getNetworkInfo")]
    async fn get_network_info(&self) -> RpcResult<RpcNetworkInfo>;

    // ── V2 Claims queries ─────────────────────────────────────────────────────

    /// Return all registered certificate providers.
    #[method(name = "getProviders")]
    async fn get_providers(&self) -> RpcResult<Vec<RpcProvider>>;

    /// Return a single provider by base-58 account ID.
    #[method(name = "getProvider")]
    async fn get_provider(&self, provider_id: String) -> RpcResult<Option<RpcProvider>>;

    /// Return all registered certificate schemas.
    #[method(name = "getSchemas")]
    async fn get_schemas(&self) -> RpcResult<Vec<RpcSchema>>;

    /// Return the claim state for a lock (by TxId hex).
    #[method(name = "getClaimState")]
    async fn get_claim_state(&self, lock_id: String) -> RpcResult<Option<RpcClaimState>>;

    /// Return the current oracle snapshot for a trading pair (e.g. "KX/USD").
    #[method(name = "getOracleSnapshot")]
    async fn get_oracle_snapshot(&self, pair: String) -> RpcResult<Option<RpcOracleSnapshot>>;

    // ── V3 New methods ────────────────────────────────────────────────────────

    /// Return a single time-lock contract by its TxId hex.
    #[method(name = "getTimeLockById")]
    async fn get_timelock_by_id(&self, lock_id: String) -> RpcResult<Option<RpcTimeLock>>;

    /// Return all **Pending** time-lock contracts where `account_id` is the recipient.
    /// Results are sorted by `unlock_at` ascending.
    #[method(name = "getPendingIncoming")]
    async fn get_pending_incoming(&self, account_id: String) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return paginated time-lock contracts for an account (sender or recipient).
    /// `offset` is the number of records to skip; `limit` is the page size (max 200).
    #[method(name = "getTimeLockContractsPaged")]
    async fn get_timelock_contracts_paged(
        &self,
        account_id: String,
        offset: u32,
        limit: u32,
    ) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return aggregate on-chain statistics.
    #[method(name = "getChainStats")]
    async fn get_chain_stats(&self) -> RpcResult<RpcChainStats>;

    /// Return the most recent `limit` transactions (max 200) as lightweight summaries.
    #[method(name = "getRecentTransactions")]
    async fn get_recent_transactions(&self, limit: u32) -> RpcResult<Vec<RpcRecentTx>>;

    /// Return all time-lock contracts whose `unlock_at` falls in [`from_unix`, `to_unix`].
    #[method(name = "getLocksByUnlockDate")]
    async fn get_locks_by_unlock_date(
        &self,
        from_unix: i64,
        to_unix: i64,
    ) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return node and protocol version information.
    #[method(name = "getVersion")]
    async fn get_version(&self) -> RpcResult<RpcVersionInfo>;

    /// Submit a signed `CancelTimeLock` transaction. `tx_hex` is hex-encoded bincode(Transaction).
    /// Returns the TxId hex on success. The transaction must contain exactly one
    /// `Action::CancelTimeLock` action.
    #[method(name = "cancelLock")]
    async fn cancel_lock(&self, tx_hex: String) -> RpcResult<String>;

    /// Search time-lock contracts for `account_id` with optional filters.
    #[method(name = "searchLocks")]
    async fn search_locks(&self, query: RpcSearchQuery) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return aggregate statistics across all active (Pending) timelocks.
    /// Lightweight alternative to fetching all contracts — designed for the public stats bar.
    #[method(name = "getGlobalLockStats")]
    async fn get_global_lock_stats(&self) -> RpcResult<RpcGlobalLockStats>;

    /// Return all time-lock contracts whose `recipient_email_hash` matches `email_hash_hex`.
    /// `email_hash_hex` is the 64-character hex encoding of the 32-byte BLAKE3 hash of the
    /// recipient's email address (lowercase, trimmed, no trailing newline).
    /// Returns only Pending locks sorted newest-first.
    #[method(name = "getEmailLocks")]
    async fn get_email_locks(&self, email_hash_hex: String) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return all incoming transactions for an account: direct transfers received,
    /// claimed email locks, and claimed timelocks. Sorted newest-first.
    /// Max 500 results.
    #[method(name = "getIncomingTransfers")]
    async fn get_incoming_transfers(&self, account_id: String) -> RpcResult<Vec<RpcIncomingTransfer>>;

    // ── V4 Cascade Send ────────────────────────────────────────────────────

    /// Create a cascade of email time-locks in a single transaction.
    /// All locks share one claim_secret_hash. The sender's wallet signs it.
    /// `tx_hex` is hex-encoded bincode(Transaction) containing multiple
    /// TimeLockCreate actions with the same extension_data (0xC5 + hash).
    /// Returns the TxId hex on success.
    #[method(name = "sendCascade")]
    async fn send_cascade(&self, tx_hex: String) -> RpcResult<String>;

    /// Return details of a cascade by its claim_secret_hash (hex).
    /// Returns all locks sharing that hash, plus aggregate statistics.
    #[method(name = "getCascadeDetails")]
    async fn get_cascade_details(&self, claim_secret_hash: String) -> RpcResult<RpcCascadeDetails>;


    // ── Genesis 7 — Verified Delivery Protocol ────────────────────────────

    /// Return all Active verifiers in the on-chain registry.
    #[method(name = "getVerifierRegistry")]
    async fn get_verifier_registry(&self) -> RpcResult<Vec<RpcVerifierRecord>>;

    /// Return the Day 91 trigger status for a lock (by TxId hex).
    /// Returns null if the trigger has not yet fired.
    #[method(name = "getPromiseTriggerStatus")]
    async fn get_promise_trigger_status(&self, lock_id: String) -> RpcResult<Option<RpcPromiseTriggerStatus>>;

    /// Return all Genesis 7 protocol constants from genesis metadata.
    #[method(name = "getGenesis7Constants")]
    async fn get_genesis7_constants(&self) -> RpcResult<serde_json::Value>;

    /// Return the current balance of the Humanity Stake Pool wallet.
    #[method(name = "getHumanityStakeBalance")]
    async fn get_humanity_stake_balance(&self) -> RpcResult<RpcHumanityStakeBalance>;

    /// Return Promise Axioms and Trading Axioms from genesis metadata.
    #[method(name = "getPromiseAxioms")]
    async fn get_promise_axioms(&self) -> RpcResult<RpcPromiseAxioms>;


    // ── Genesis 8 — AI Agent Architecture ──────────────────────────────

    /// Return all Active agents in the on-chain registry.
    #[method(name = "getAgentRegistry")]
    async fn get_agent_registry(&self) -> RpcResult<Vec<RpcAgentRecord>>;

    /// Return a single agent loan record by lock_id hex.
    #[method(name = "getAgentLoanRecord")]
    async fn get_agent_loan_record(&self, lock_id: String) -> RpcResult<Option<RpcAgentLoanRecord>>;

    /// Return a single agent custody record by lock_id hex.
    #[method(name = "getAgentCustodyRecord")]
    async fn get_agent_custody_record(&self, lock_id: String) -> RpcResult<Option<RpcAgentCustodyRecord>>;

    /// Return all custody records for an agent wallet.
    #[method(name = "getAgentHistory")]
    async fn get_agent_history(&self, agent_wallet: String) -> RpcResult<Vec<RpcAgentCustodyRecord>>;

    /// Return axiom consent record for a lock_id + party_type ("GRANTOR" or "AGENT").
    #[method(name = "getAxiomConsent")]
    async fn get_axiom_consent(&self, lock_id: String, party_type: String) -> RpcResult<Option<RpcAxiomConsentRecord>>;

    /// Return all investable promises (agent_managed=true, not yet assigned, within investment window).
    #[method(name = "getInvestablePromises")]
    async fn get_investable_promises(&self) -> RpcResult<Vec<RpcInvestablePromise>>;

    /// Return Genesis 8 constants from genesis metadata as JSON.
    #[method(name = "getGenesis8Constants")]
    async fn get_genesis8_constants(&self) -> RpcResult<serde_json::Value>;
}
