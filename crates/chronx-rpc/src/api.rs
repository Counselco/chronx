use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::{
    RpcAccount, RpcChainStats, RpcClaimState, RpcGenesisInfo, RpcNetworkInfo, RpcOracleSnapshot,
    RpcProvider, RpcRecentTx, RpcSchema, RpcSearchQuery, RpcTimeLock, RpcVersionInfo,
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
}
