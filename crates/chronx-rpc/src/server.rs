use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::{Server, ServerHandle};
use jsonrpsee::types::ErrorObject;
use tracing::{info, warn};

use chronx_core::constants::CHRONOS_PER_KX;
use chronx_core::transaction::Transaction;
use chronx_core::types::{AccountId, TxId};
use chronx_state::StateDb;

use crate::api::ChronxApiServer;
use crate::types::{RpcAccount, RpcGenesisInfo, RpcNetworkInfo, RpcTimeLock};

fn rpc_err(code: i32, msg: impl Into<String>) -> ErrorObject<'static> {
    ErrorObject::owned(code, msg.into(), None::<()>)
}

/// Shared state passed to the RPC server.
pub struct RpcServerState {
    pub db: Arc<StateDb>,
    pub pow_difficulty: u8,
    /// Optional sender to forward incoming transactions to the node pipeline.
    pub tx_sender: Option<tokio::sync::mpsc::Sender<Transaction>>,
    /// Full libp2p multiaddress of this node (e.g. `/ip4/127.0.0.1/tcp/7777/p2p/<PeerId>`).
    /// Used by peers to bootstrap; returned by `chronx_getNetworkInfo`.
    pub peer_multiaddr: Option<String>,
}

/// The RPC server implementation.
pub struct RpcServer {
    state: Arc<RpcServerState>,
}

impl RpcServer {
    pub fn new(state: Arc<RpcServerState>) -> Self {
        Self { state }
    }

    /// Start the JSON-RPC server on `addr`. Returns a handle to stop it.
    pub async fn start(self, addr: SocketAddr) -> anyhow::Result<ServerHandle> {
        let server = Server::builder().build(addr).await?;
        let module = self.into_rpc();
        let handle = server.start(module);
        info!(%addr, "RPC server started");
        Ok(handle)
    }
}

#[async_trait]
impl ChronxApiServer for RpcServer {
    async fn get_account(&self, account_id: String) -> RpcResult<Option<RpcAccount>> {
        let id = AccountId::from_b58(&account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let acc = self
            .state
            .db
            .get_account(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        Ok(acc.map(|a| RpcAccount {
            account_id: a.account_id.to_b58(),
            balance_chronos: a.balance.to_string(),
            balance_kx: (a.balance / CHRONOS_PER_KX).to_string(),
            nonce: a.nonce,
            is_verifier: a.is_verifier,
            recovery_active: a.recovery_state.active,
        }))
    }

    async fn get_balance(&self, account_id: String) -> RpcResult<String> {
        let id = AccountId::from_b58(&account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let balance = self
            .state
            .db
            .get_account(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?
            .map(|a| a.balance)
            .unwrap_or(0);

        Ok(balance.to_string())
    }

    async fn send_transaction(&self, tx_hex: String) -> RpcResult<String> {
        let tx_bytes =
            hex::decode(&tx_hex).map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;

        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| rpc_err(-32602, format!("invalid transaction encoding: {e}")))?;

        let tx_id = tx.tx_id.to_hex();

        if let Some(sender) = &self.state.tx_sender {
            sender
                .send(tx)
                .await
                .map_err(|_| rpc_err(-32603, "transaction queue full"))?;
        } else {
            warn!("RPC: sendTransaction called but no tx pipeline configured");
            return Err(rpc_err(-32603, "node tx pipeline not connected").into());
        }

        Ok(tx_id)
    }

    async fn get_transaction(&self, tx_id: String) -> RpcResult<Option<String>> {
        let id = TxId::from_hex(&tx_id)
            .map_err(|e| rpc_err(-32602, format!("invalid tx id: {e}")))?;

        let vertex = self
            .state
            .db
            .get_vertex(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        match vertex {
            None => Ok(None),
            Some(v) => {
                let bytes = bincode::serialize(&v)
                    .map_err(|e| rpc_err(-32603, e.to_string()))?;
                Ok(Some(hex::encode(bytes)))
            }
        }
    }

    async fn get_timelock_contracts(&self, _account_id: String) -> RpcResult<Vec<RpcTimeLock>> {
        // Scanning all time-locks is O(n) over the timelocks tree.
        // In production this would be indexed; here we iterate the sled tree.
        // For now, return an empty list — full scan requires a DB iterator API.
        // TODO: add StateDb::iter_timelocks() when needed.
        Ok(Vec::new())
    }

    async fn get_dag_tips(&self) -> RpcResult<Vec<String>> {
        let tips = self
            .state
            .db
            .get_tips()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        Ok(tips.into_iter().map(|t| t.to_hex()).collect())
    }

    async fn get_genesis_info(&self) -> RpcResult<RpcGenesisInfo> {
        Ok(RpcGenesisInfo::current(self.state.pow_difficulty))
    }

    async fn get_network_info(&self) -> RpcResult<RpcNetworkInfo> {
        Ok(RpcNetworkInfo {
            peer_multiaddr: self.state.peer_multiaddr.clone().unwrap_or_default(),
        })
    }
}
