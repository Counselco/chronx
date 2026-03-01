use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::{Server, ServerHandle};
use jsonrpsee::types::ErrorObject;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use chronx_core::account::TimeLockStatus;
use chronx_core::claims::ProviderStatus;
use chronx_core::constants::{CHRONOS_PER_KX, TOTAL_SUPPLY_CHRONOS};
use chronx_core::transaction::{Action, Transaction};
use chronx_core::types::{AccountId, TxId};
use chronx_state::StateDb;

use crate::api::ChronxApiServer;
use crate::types::{
    RpcAccount, RpcChainStats, RpcClaimState, RpcGenesisInfo, RpcNetworkInfo, RpcOracleSnapshot,
    RpcProvider, RpcRecentTx, RpcSchema, RpcSearchQuery, RpcTimeLock, RpcVersionInfo,
};

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

    /// Start the JSON-RPC server on `addr` with permissive CORS headers. Returns a handle to stop it.
    pub async fn start(self, addr: SocketAddr) -> anyhow::Result<ServerHandle> {
        let cors = CorsLayer::new()
            .allow_methods(Any)
            .allow_origin(Any)
            .allow_headers(Any);

        let server = Server::builder()
            .set_http_middleware(tower::ServiceBuilder::new().layer(cors))
            .build(addr)
            .await?;

        let module = self.into_rpc();
        let handle = server.start(module);
        info!(%addr, "RPC server started");
        Ok(handle)
    }
}

// ── Internal helper: convert a TimeLockContract to an RpcTimeLock ────────────

fn tlc_status_str(status: &TimeLockStatus) -> String {
    match status {
        TimeLockStatus::Pending                       => "Pending".to_string(),
        TimeLockStatus::Claimed { .. }               => "Claimed".to_string(),
        TimeLockStatus::ForSale { .. }               => "ForSale".to_string(),
        TimeLockStatus::Ambiguous { .. }             => "Ambiguous".to_string(),
        TimeLockStatus::ClaimOpen { .. }             => "ClaimOpen".to_string(),
        TimeLockStatus::ClaimCommitted { .. }        => "ClaimCommitted".to_string(),
        TimeLockStatus::ClaimRevealed { .. }         => "ClaimRevealed".to_string(),
        TimeLockStatus::ClaimChallenged { .. }       => "ClaimChallenged".to_string(),
        TimeLockStatus::ClaimFinalized { .. }        => "ClaimFinalized".to_string(),
        TimeLockStatus::ClaimSlashed { .. }          => "ClaimSlashed".to_string(),
        TimeLockStatus::Cancelled { .. }             => "Cancelled".to_string(),
    }
}

fn tlc_to_rpc(tlc: chronx_core::account::TimeLockContract) -> RpcTimeLock {
    let status = tlc_status_str(&tlc.status);
    RpcTimeLock {
        lock_id: tlc.id.to_hex(),
        sender: tlc.sender.to_b58(),
        recipient_account_id: tlc.recipient_account_id.to_b58(),
        amount_chronos: tlc.amount.to_string(),
        amount_kx: (tlc.amount / CHRONOS_PER_KX).to_string(),
        unlock_at: tlc.unlock_at,
        created_at: tlc.created_at,
        status,
        memo: tlc.memo,
        tags: tlc.tags,
        private: tlc.private,
        lock_version: tlc.lock_version,
    }
}

// ── RPC implementation ────────────────────────────────────────────────────────

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

        let Some(a) = acc else { return Ok(None); };

        // Sum pending time-lock amounts where this account is the sender.
        let locked: u128 = self
            .state
            .db
            .iter_timelocks_for_sender(&id)
            .unwrap_or_default()
            .into_iter()
            .filter(|tlc| tlc.status == TimeLockStatus::Pending)
            .map(|tlc| tlc.amount)
            .sum();

        // Approximate tip depth as chain height.
        let tip_height = self
            .state
            .db
            .get_tips()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|t| self.state.db.get_vertex(&t).ok().flatten())
            .map(|v| v.depth)
            .max()
            .unwrap_or(0);

        let spendable = a.spendable_balance();

        Ok(Some(RpcAccount {
            account_id: a.account_id.to_b58(),
            balance_chronos: a.balance.to_string(),
            balance_kx: (a.balance / CHRONOS_PER_KX).to_string(),
            spendable_chronos: spendable.to_string(),
            spendable_kx: (spendable / CHRONOS_PER_KX).to_string(),
            locked_chronos: locked.to_string(),
            locked_kx: (locked / CHRONOS_PER_KX).to_string(),
            verifier_stake_chronos: a.verifier_stake.to_string(),
            nonce: a.nonce,
            is_verifier: a.is_verifier,
            recovery_active: a.recovery_state.active,
            tip_height,
            // V3 cached lock counters
            account_version: a.account_version,
            created_at: a.created_at,
            incoming_locks_count: a.incoming_locks_count,
            outgoing_locks_count: a.outgoing_locks_count,
            incoming_locked_chronos: a.total_locked_incoming_chronos.to_string(),
            outgoing_locked_chronos: a.total_locked_outgoing_chronos.to_string(),
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

    async fn get_timelock_contracts(&self, account_id: String) -> RpcResult<Vec<RpcTimeLock>> {
        let id = AccountId::from_b58(&account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let mut seen = std::collections::HashSet::new();
        let mut all: Vec<RpcTimeLock> = Vec::new();

        let as_recipient = self
            .state
            .db
            .iter_timelocks_for_recipient(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let as_sender = self
            .state
            .db
            .iter_timelocks_for_sender(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        for tlc in as_recipient.into_iter().chain(as_sender) {
            if !seen.insert(tlc.id.to_hex()) {
                continue;
            }
            all.push(tlc_to_rpc(tlc));
        }

        all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(all)
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

    // ── V2 Claims queries ─────────────────────────────────────────────────────

    async fn get_providers(&self) -> RpcResult<Vec<RpcProvider>> {
        let records = self.state.db.iter_providers()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        Ok(records.into_iter().map(|p| RpcProvider {
            provider_id: p.provider_id.to_b58(),
            provider_class: p.provider_class,
            jurisdictions: p.jurisdictions,
            status: match &p.status {
                ProviderStatus::Active => "Active".to_string(),
                ProviderStatus::Revoked { revoked_at } => format!("Revoked({})", revoked_at),
            },
            registered_at: p.registered_at,
        }).collect())
    }

    async fn get_provider(&self, provider_id: String) -> RpcResult<Option<RpcProvider>> {
        let id = AccountId::from_b58(&provider_id)
            .map_err(|e| rpc_err(-32602, format!("invalid provider id: {e}")))?;
        let record = self.state.db.get_provider(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|p| RpcProvider {
            provider_id: p.provider_id.to_b58(),
            provider_class: p.provider_class,
            jurisdictions: p.jurisdictions,
            status: match &p.status {
                ProviderStatus::Active => "Active".to_string(),
                ProviderStatus::Revoked { revoked_at } => format!("Revoked({})", revoked_at),
            },
            registered_at: p.registered_at,
        }))
    }

    async fn get_schemas(&self) -> RpcResult<Vec<RpcSchema>> {
        let schemas = self.state.db.iter_schemas()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(schemas.into_iter().map(|s| RpcSchema {
            schema_id: s.schema_id,
            name: s.name,
            version: s.version,
            active: s.active,
            registered_at: s.registered_at,
        }).collect())
    }

    async fn get_claim_state(&self, lock_id: String) -> RpcResult<Option<RpcClaimState>> {
        let id = TxId::from_hex(&lock_id)
            .map_err(|e| rpc_err(-32602, format!("invalid lock id: {e}")))?;
        let tlc = self.state.db.get_timelock(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        let cs = self.state.db.get_claim(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let Some(cs) = cs else { return Ok(None); };

        let status = tlc.map(|t| match &t.status {
            TimeLockStatus::ClaimOpen { .. }       => "ClaimOpen",
            TimeLockStatus::ClaimCommitted { .. }  => "ClaimCommitted",
            TimeLockStatus::ClaimRevealed { .. }   => "ClaimRevealed",
            TimeLockStatus::ClaimChallenged { .. } => "ClaimChallenged",
            TimeLockStatus::ClaimFinalized { .. }  => "ClaimFinalized",
            TimeLockStatus::ClaimSlashed { .. }    => "ClaimSlashed",
            _ => "Unknown",
        }.to_string()).unwrap_or_else(|| "Unknown".to_string());

        Ok(Some(RpcClaimState {
            lock_id,
            lane: cs.lane,
            v_claim_usd_cents: cs.v_claim_snapshot,
            opened_at: cs.opened_at,
            agent_id: cs.agent_id.map(|a| a.to_b58()),
            status,
        }))
    }

    async fn get_oracle_snapshot(&self, pair: String) -> RpcResult<Option<RpcOracleSnapshot>> {
        let snap = self.state.db.get_oracle_snapshot(&pair)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(snap.map(|s| RpcOracleSnapshot {
            pair: s.pair,
            price_cents: s.price_cents,
            num_submissions: s.num_submissions,
            updated_at: s.updated_at,
        }))
    }

    // ── V3 New methods ────────────────────────────────────────────────────────

    async fn get_timelock_by_id(&self, lock_id: String) -> RpcResult<Option<RpcTimeLock>> {
        let id = TxId::from_hex(&lock_id)
            .map_err(|e| rpc_err(-32602, format!("invalid lock id: {e}")))?;
        let tlc = self.state.db.get_timelock(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(tlc.map(tlc_to_rpc))
    }

    async fn get_pending_incoming(&self, account_id: String) -> RpcResult<Vec<RpcTimeLock>> {
        let id = AccountId::from_b58(&account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let mut locks: Vec<RpcTimeLock> = self
            .state
            .db
            .iter_timelocks_for_recipient(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?
            .into_iter()
            .filter(|tlc| tlc.status == TimeLockStatus::Pending)
            .map(tlc_to_rpc)
            .collect();

        locks.sort_by_key(|l| l.unlock_at);
        Ok(locks)
    }

    async fn get_timelock_contracts_paged(
        &self,
        account_id: String,
        offset: u32,
        limit: u32,
    ) -> RpcResult<Vec<RpcTimeLock>> {
        let id = AccountId::from_b58(&account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let limit = limit.min(200) as usize;

        let mut seen = std::collections::HashSet::new();
        let mut all: Vec<RpcTimeLock> = Vec::new();

        let as_recipient = self.state.db.iter_timelocks_for_recipient(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        let as_sender = self.state.db.iter_timelocks_for_sender(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        for tlc in as_recipient.into_iter().chain(as_sender) {
            if !seen.insert(tlc.id.to_hex()) {
                continue;
            }
            all.push(tlc_to_rpc(tlc));
        }

        all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let page: Vec<_> = all.into_iter().skip(offset as usize).take(limit).collect();
        Ok(page)
    }

    async fn get_chain_stats(&self) -> RpcResult<RpcChainStats> {
        let total_accounts = self.state.db.count_accounts();
        let total_timelocks = self.state.db.count_timelocks();
        let total_vertices = self.state.db.count_vertices();

        let tips = self.state.db.get_tips()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        let dag_tip_count = tips.len() as u64;

        let dag_depth = tips
            .iter()
            .filter_map(|t| self.state.db.get_vertex(t).ok().flatten())
            .map(|v| v.depth)
            .max()
            .unwrap_or(0);

        Ok(RpcChainStats {
            total_accounts,
            total_timelocks,
            total_vertices,
            dag_tip_count,
            dag_depth,
            total_supply_chronos: TOTAL_SUPPLY_CHRONOS.to_string(),
            total_supply_kx: (TOTAL_SUPPLY_CHRONOS / CHRONOS_PER_KX).to_string(),
        })
    }

    async fn get_recent_transactions(&self, limit: u32) -> RpcResult<Vec<RpcRecentTx>> {
        let limit = limit.min(200) as usize;

        let mut vertices = self.state.db.iter_all_vertices()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        // Sort by transaction timestamp descending (most recent first).
        vertices.sort_by(|a, b| b.transaction.timestamp.cmp(&a.transaction.timestamp));

        let result: Vec<RpcRecentTx> = vertices
            .into_iter()
            .take(limit)
            .map(|v| RpcRecentTx {
                tx_id: v.transaction.tx_id.to_hex(),
                timestamp: v.transaction.timestamp,
                from: v.transaction.from.to_b58(),
                action_count: v.transaction.actions.len(),
                depth: v.depth,
            })
            .collect();

        Ok(result)
    }

    async fn get_locks_by_unlock_date(
        &self,
        from_unix: i64,
        to_unix: i64,
    ) -> RpcResult<Vec<RpcTimeLock>> {
        let mut locks: Vec<RpcTimeLock> = self
            .state
            .db
            .iter_all_timelocks()
            .map_err(|e| rpc_err(-32603, e.to_string()))?
            .into_iter()
            .filter(|tlc| tlc.unlock_at >= from_unix && tlc.unlock_at <= to_unix)
            .map(tlc_to_rpc)
            .collect();

        locks.sort_by_key(|l| l.unlock_at);
        Ok(locks)
    }

    async fn get_version(&self) -> RpcResult<RpcVersionInfo> {
        Ok(RpcVersionInfo {
            node_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: "3".to_string(),
            api_version: "3".to_string(),
        })
    }

    async fn cancel_lock(&self, tx_hex: String) -> RpcResult<String> {
        let tx_bytes =
            hex::decode(&tx_hex).map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;

        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| rpc_err(-32602, format!("invalid transaction encoding: {e}")))?;

        // Validate: must contain exactly one CancelTimeLock action.
        let has_cancel = tx.actions.len() == 1
            && matches!(&tx.actions[0], Action::CancelTimeLock { .. });
        if !has_cancel {
            return Err(rpc_err(
                -32602,
                "cancelLock requires exactly one CancelTimeLock action",
            )
            .into());
        }

        let tx_id = tx.tx_id.to_hex();

        if let Some(sender) = &self.state.tx_sender {
            sender
                .send(tx)
                .await
                .map_err(|_| rpc_err(-32603, "transaction queue full"))?;
        } else {
            warn!("RPC: cancelLock called but no tx pipeline configured");
            return Err(rpc_err(-32603, "node tx pipeline not connected").into());
        }

        Ok(tx_id)
    }

    async fn search_locks(&self, query: RpcSearchQuery) -> RpcResult<Vec<RpcTimeLock>> {
        let id = AccountId::from_b58(&query.account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let limit = query.limit.unwrap_or(50).min(200) as usize;
        let offset = query.offset.unwrap_or(0) as usize;

        // Collect sender+recipient locks, deduplicated.
        let mut seen = std::collections::HashSet::new();
        let mut all: Vec<RpcTimeLock> = Vec::new();

        let as_recipient = self.state.db.iter_timelocks_for_recipient(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        let as_sender = self.state.db.iter_timelocks_for_sender(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        for tlc in as_recipient.into_iter().chain(as_sender) {
            if !seen.insert(tlc.id.to_hex()) {
                continue;
            }

            // Status filter
            if let Some(ref status_filter) = query.status {
                if tlc_status_str(&tlc.status) != *status_filter {
                    continue;
                }
            }

            // unlock_at range filter
            if let Some(from) = query.unlock_from {
                if tlc.unlock_at < from { continue; }
            }
            if let Some(to) = query.unlock_to {
                if tlc.unlock_at > to { continue; }
            }

            // Tags filter: all requested tags must be present.
            if let Some(ref filter_tags) = query.tags {
                let tlc_tags = tlc.tags.as_deref().unwrap_or(&[]);
                if !filter_tags.iter().all(|ft| tlc_tags.contains(ft)) {
                    continue;
                }
            }

            all.push(tlc_to_rpc(tlc));
        }

        all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let page: Vec<_> = all.into_iter().skip(offset).take(limit).collect();
        Ok(page)
    }
}
