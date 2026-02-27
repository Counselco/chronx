use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::{RpcAccount, RpcGenesisInfo, RpcNetworkInfo, RpcTimeLock};

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

    /// List time-lock contracts where `account_id` is the recipient.
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
}
