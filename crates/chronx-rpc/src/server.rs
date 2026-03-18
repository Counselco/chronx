//! JSON-RPC 2.0 server implementation for the ChronX node.
//!
//! This module exposes the [`RpcServer`] which binds to a TCP address and
//! serves all `chronx_*` RPC methods defined in [`crate::api::ChronxApiServer`].
//! CORS headers are set to permissive (`*`) so that browser-based clients
//! (including the Tauri GUI wallet) can connect without a proxy.
//!
//! All methods are implemented on [`RpcServer`] via the `ChronxApiServer` trait.
//! Errors return standard JSON-RPC error objects:
//! - `-32602` for invalid or missing parameters
//! - `-32603` for internal errors (DB failure, full queue, etc.)

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::{Server, ServerHandle};
use jsonrpsee::types::ErrorObject;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use chronx_core::account::TimeLockStatus;
use chronx_core::error::ChronxError;
use chronx_core::claims::ProviderStatus;
use chronx_core::constants::{CHRONOS_PER_KX, TOTAL_SUPPLY_CHRONOS};
use chronx_core::transaction::{Action, Transaction};
use chronx_core::types::{AccountId, TxId};
use chronx_state::StateDb;
use chronx_state::db::{InvoiceStatus, CreditStatus, DepositStatus, ConditionalStatus};

use crate::api::ChronxApiServer;
use crate::types::{
    RpcInvoiceRecord, RpcCreditRecord, RpcDepositRecord,
    RpcConditionalRecord, RpcLedgerEntryRecord,
    RpcSignOfLifeRecord, RpcPromiseChainRecord,
    RpcIdentityRecord,
    RpcAccount, RpcCascadeDetails, RpcChainStats, RpcClaimState, RpcGenesisInfo,
    RpcGlobalLockStats, RpcHumanityStakeBalance, RpcIncomingTransfer, RpcOutgoingTransfer, RpcNetworkInfo,
    RpcOracleSnapshot, RpcPromiseAxioms, RpcPromiseTriggerStatus, RpcProvider, RpcRecentTx,
    RpcSchema, RpcSearchQuery, RpcTimeLock, RpcVerifierRecord, RpcVersionInfo,
    RpcAgentRecord, RpcAgentLoanRecord, RpcAgentCustodyRecord, RpcAxiomConsentRecord, RpcInvestablePromise,
    RpcDetailedTx, RpcActionSummary,
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
        TimeLockStatus::Pending => "Pending".to_string(),
        TimeLockStatus::Claimed { .. } => "Claimed".to_string(),
        TimeLockStatus::ForSale { .. } => "ForSale".to_string(),
        TimeLockStatus::Ambiguous { .. } => "Ambiguous".to_string(),
        TimeLockStatus::ClaimOpen { .. } => "ClaimOpen".to_string(),
        TimeLockStatus::ClaimCommitted { .. } => "ClaimCommitted".to_string(),
        TimeLockStatus::ClaimRevealed { .. } => "ClaimRevealed".to_string(),
        TimeLockStatus::ClaimChallenged { .. } => "ClaimChallenged".to_string(),
        TimeLockStatus::ClaimFinalized { .. } => "ClaimFinalized".to_string(),
        TimeLockStatus::ClaimSlashed { .. } => "ClaimSlashed".to_string(),
        TimeLockStatus::Cancelled { .. } => "Cancelled".to_string(),
        TimeLockStatus::Reverted { .. } => "Reverted".to_string(),
        TimeLockStatus::PendingExecutor { .. } => "PendingExecutor".to_string(),
        TimeLockStatus::ExecutorWithdrawn { .. } => "ExecutorWithdrawn".to_string(),
    }
}

fn tlc_to_rpc(tlc: chronx_core::account::TimeLockContract) -> RpcTimeLock {
    let status = tlc_status_str(&tlc.status);

    // If extension_data starts with 0xC5 marker and is 33 bytes,
    // the remaining 32 bytes are BLAKE3(claim_code). Locks sharing the
    // same hash belong to the same Promise Series.
    let claim_secret_hash = tlc.extension_data.as_ref().and_then(|d| {
        if d.len() == 33 && d[0] == 0xC5 {
            Some(hex::encode(&d[1..]))
        } else {
            None
        }
    });

    let recipient_email_hash = tlc.recipient_email_hash.map(|h| hex::encode(h));
    let cancellation_window_secs = tlc.cancellation_window_secs;
    let claim_window_secs_val = tlc.claim_window_secs;
    let unclaimed_action_str = tlc.unclaimed_action.as_ref().map(|ua| {
        match ua {
            chronx_core::account::UnclaimedAction::RevertToSender => "RevertToSender".to_string(),
            chronx_core::account::UnclaimedAction::Burn => "Burn".to_string(),
            chronx_core::account::UnclaimedAction::ForwardTo(id) => format!("ForwardTo({})", id.to_b58()),
        }
    });

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
        claim_secret_hash,
        cancellation_window_secs,
        recipient_email_hash,
        claim_window_secs: claim_window_secs_val,
        unclaimed_action: unclaimed_action_str,
        lock_type: tlc.lock_type,
        lock_metadata: tlc.lock_metadata,
        convert_to: None, // populated by caller from lock_convert_to tree
    }
}

// ── RPC implementation ────────────────────────────────────────────────────────

#[async_trait]
impl ChronxApiServer for RpcServer {
    /// `chronx_getAccount` — return full account state including balance, spendable balance,
    /// locked outgoing amount, verifier stake, nonce, and V3 lock counters.
    async fn get_account(&self, account_id: String) -> RpcResult<Option<RpcAccount>> {
        let id = AccountId::from_b58(&account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let acc = self
            .state
            .db
            .get_account(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let Some(a) = acc else {
            return Ok(None);
        };

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

    /// `chronx_getBalance` — return raw balance in Chronos (1 KX = 1,000,000 Chronos).
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

    /// `chronx_sendTransaction` — submit a hex-encoded, signed, PoW-solved transaction.
    /// Returns the transaction ID on success. The transaction is validated and applied
    /// by the `StateEngine` in the node's main loop, then broadcast to peers via P2P.
    async fn send_transaction(&self, tx_hex: String) -> RpcResult<String> {
        let tx_bytes =
            hex::decode(&tx_hex).map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;

        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| {
                let hex_preview = if tx_hex.len() > 400 { &tx_hex[..400] } else { &tx_hex };
                eprintln!("[DEBUG] DESER FAIL: {} | len={} | first400hex={}", e, tx_bytes.len(), hex_preview);
                rpc_err(-32602, format!("invalid transaction encoding: {e}"))
            })?;

        let tx_id = tx.tx_id.to_hex();

        if let Some(sender) = &self.state.tx_sender {
            sender
                .send(tx)
                .await
                .map_err(|_| rpc_err(-32603, "transaction queue full"))?;
        } else {
            warn!("RPC: sendTransaction called but no tx pipeline configured");
            return Err(rpc_err(-32603, "node tx pipeline not connected"));
        }

        Ok(tx_id)
    }

    /// `chronx_getTransaction` — fetch a serialised DAG vertex by transaction ID (hex).
    /// Returns the bincode-encoded vertex as a hex string, or null if not found.
    async fn get_transaction(&self, tx_id: String) -> RpcResult<Option<String>> {
        let id =
            TxId::from_hex(&tx_id).map_err(|e| rpc_err(-32602, format!("invalid tx id: {e}")))?;

        let vertex = self
            .state
            .db
            .get_vertex(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        match vertex {
            None => Ok(None),
            Some(v) => {
                let bytes = bincode::serialize(&v).map_err(|e| rpc_err(-32603, e.to_string()))?;
                Ok(Some(hex::encode(bytes)))
            }
        }
    }

    /// `chronx_getTimeLockContracts` — all locks where the account is sender or recipient,
    /// deduplicated and sorted newest-first.
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

    /// `chronx_getDagTips` — current DAG tip TxIds (hex). Used to set parent pointers
    /// when constructing a new transaction.
    async fn get_dag_tips(&self) -> RpcResult<Vec<String>> {
        let tips = self
            .state
            .db
            .get_tips()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        Ok(tips.into_iter().map(|t| t.to_hex()).collect())
    }

    /// `chronx_getGenesisInfo` — genesis timestamp, total supply (Chronos and KX),
    /// and initial PoW difficulty.
    async fn get_genesis_info(&self) -> RpcResult<RpcGenesisInfo> {
        Ok(RpcGenesisInfo::current(self.state.pow_difficulty))
    }

    /// `chronx_getNetworkInfo` — the node's full libp2p multiaddress
    /// (e.g. `/ip4/1.2.3.4/tcp/7777/p2p/<PeerId>`). Share with other nodes
    /// as a `--bootstrap` peer.
    async fn get_network_info(&self) -> RpcResult<RpcNetworkInfo> {
        Ok(RpcNetworkInfo {
            peer_multiaddr: self.state.peer_multiaddr.clone().unwrap_or_default(),
        })
    }

    // ── V2 Claims queries ─────────────────────────────────────────────────────

    async fn get_providers(&self) -> RpcResult<Vec<RpcProvider>> {
        let records = self
            .state
            .db
            .iter_providers()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        Ok(records
            .into_iter()
            .map(|p| RpcProvider {
                provider_id: p.provider_id.to_b58(),
                provider_class: p.provider_class,
                jurisdictions: p.jurisdictions,
                status: match &p.status {
                    ProviderStatus::Active => "Active".to_string(),
                    ProviderStatus::Revoked { revoked_at } => format!("Revoked({})", revoked_at),
                },
                registered_at: p.registered_at,
            })
            .collect())
    }

    async fn get_provider(&self, provider_id: String) -> RpcResult<Option<RpcProvider>> {
        let id = AccountId::from_b58(&provider_id)
            .map_err(|e| rpc_err(-32602, format!("invalid provider id: {e}")))?;
        let record = self
            .state
            .db
            .get_provider(&id)
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
        let schemas = self
            .state
            .db
            .iter_schemas()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(schemas
            .into_iter()
            .map(|s| RpcSchema {
                schema_id: s.schema_id,
                name: s.name,
                version: s.version,
                active: s.active,
                registered_at: s.registered_at,
            })
            .collect())
    }

    async fn get_claim_state(&self, lock_id: String) -> RpcResult<Option<RpcClaimState>> {
        let id = TxId::from_hex(&lock_id)
            .map_err(|e| rpc_err(-32602, format!("invalid lock id: {e}")))?;
        let tlc = self
            .state
            .db
            .get_timelock(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        let cs = self
            .state
            .db
            .get_claim(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let Some(cs) = cs else {
            return Ok(None);
        };

        let status = tlc
            .map(|t| {
                match &t.status {
                    TimeLockStatus::ClaimOpen { .. } => "ClaimOpen",
                    TimeLockStatus::ClaimCommitted { .. } => "ClaimCommitted",
                    TimeLockStatus::ClaimRevealed { .. } => "ClaimRevealed",
                    TimeLockStatus::ClaimChallenged { .. } => "ClaimChallenged",
                    TimeLockStatus::ClaimFinalized { .. } => "ClaimFinalized",
                    TimeLockStatus::ClaimSlashed { .. } => "ClaimSlashed",
                    _ => "Unknown",
                }
                .to_string()
            })
            .unwrap_or_else(|| "Unknown".to_string());

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
        let snap = self
            .state
            .db
            .get_oracle_snapshot(&pair)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(snap.map(|s| RpcOracleSnapshot {
            pair: s.pair,
            price_cents: s.price_cents,
            num_submissions: s.num_submissions,
            updated_at: s.updated_at,
        }))
    }

    // ── V3 New methods ────────────────────────────────────────────────────────

    /// `chronx_getTimeLockById` — fetch a single time-lock by its TxId hex.
    async fn get_timelock_by_id(&self, lock_id: String) -> RpcResult<Option<RpcTimeLock>> {
        let id = TxId::from_hex(&lock_id)
            .map_err(|e| rpc_err(-32602, format!("invalid lock id: {e}")))?;
        let tlc = self
            .state
            .db
            .get_timelock(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(tlc.map(tlc_to_rpc))
    }

    /// `chronx_getPendingIncoming` — all `Pending` locks where the account is the recipient,
    /// sorted by `unlock_at` ascending (soonest first).
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

    /// `chronx_getTimeLockContractsPaged` — paginated lock list for an account
    /// (max 200 per page). Deduplicated and sorted newest-first.
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
        let page: Vec<_> = all.into_iter().skip(offset as usize).take(limit).collect();
        Ok(page)
    }

    /// `chronx_getChainStats` — aggregate chain statistics: account count, timelock count,
    /// vertex count, DAG tip count, max DAG depth, and total supply.
    async fn get_chain_stats(&self) -> RpcResult<RpcChainStats> {
        let total_accounts = self.state.db.count_accounts();
        let total_timelocks = self.state.db.count_timelocks();
        let total_vertices = self.state.db.count_vertices();

        let tips = self
            .state
            .db
            .get_tips()
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

    /// `chronx_getRecentTransactions` — the most recent `limit` transactions
    /// (max 200), sorted by timestamp descending.
    async fn get_recent_transactions(&self, limit: u32) -> RpcResult<Vec<RpcRecentTx>> {
        let limit = limit.min(200) as usize;

        let mut vertices = self
            .state
            .db
            .iter_all_vertices()
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

    /// `chronx_getLocksByUnlockDate` — all locks with `unlock_at` in `[from_unix, to_unix]`,
    /// sorted by unlock date ascending. Useful for building unlock calendars.
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

    /// `chronx_getVersion` — node version, protocol version ("3.3"), and API version.
    async fn get_version(&self) -> RpcResult<RpcVersionInfo> {
        Ok(RpcVersionInfo {
            node_version: "1.3.2".to_string(),
            protocol_version: "3.3".to_string(),
            api_version: "3".to_string(),
        })
    }

    /// `chronx_cancelLock` — submit a `CancelTimeLock` transaction (must contain exactly
    /// one `CancelTimeLock` action). Returns the transaction ID. The cancellation is
    /// validated by the engine (sender must match, cancellation window must not have expired).
    async fn cancel_lock(&self, tx_hex: String) -> RpcResult<String> {
        let tx_bytes =
            hex::decode(&tx_hex).map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;

        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| rpc_err(-32602, format!("invalid transaction encoding: {e}")))?;

        // Validate: must contain exactly one CancelTimeLock action.
        let has_cancel =
            tx.actions.len() == 1 && matches!(&tx.actions[0], Action::CancelTimeLock { .. });
        if !has_cancel {
            return Err(rpc_err(
                -32602,
                "cancelLock requires exactly one CancelTimeLock action",
            ));
        }

        let tx_id = tx.tx_id.to_hex();

        if let Some(sender) = &self.state.tx_sender {
            sender
                .send(tx)
                .await
                .map_err(|_| rpc_err(-32603, "transaction queue full"))?;
        } else {
            warn!("RPC: cancelLock called but no tx pipeline configured");
            return Err(rpc_err(-32603, "node tx pipeline not connected"));
        }

        Ok(tx_id)
    }

    /// `chronx_searchLocks` — advanced lock query. Filter by account + optional status +
    /// optional tag list (AND logic) + optional unlock date range + pagination (offset/limit, max 200).
    async fn search_locks(&self, query: RpcSearchQuery) -> RpcResult<Vec<RpcTimeLock>> {
        let id = AccountId::from_b58(&query.account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let limit = query.limit.unwrap_or(50).min(200) as usize;
        let offset = query.offset.unwrap_or(0) as usize;

        // Collect sender+recipient locks, deduplicated.
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

            // Status filter
            if let Some(ref status_filter) = query.status {
                if tlc_status_str(&tlc.status) != *status_filter {
                    continue;
                }
            }

            // unlock_at range filter
            if let Some(from) = query.unlock_from {
                if tlc.unlock_at < from {
                    continue;
                }
            }
            if let Some(to) = query.unlock_to {
                if tlc.unlock_at > to {
                    continue;
                }
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

    /// `chronx_getEmailLocks` — all **Pending** time-lock contracts whose
    /// `recipient_email_hash` matches the provided 64-char hex (BLAKE3 of lowercase email).
    /// Sorted newest-first. Used by wallets to detect incoming email-addressed locks.
    async fn get_email_locks(&self, email_hash_hex: String) -> RpcResult<Vec<RpcTimeLock>> {
        let bytes = hex::decode(&email_hash_hex)
            .map_err(|e| rpc_err(-32602, format!("invalid email hash hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(rpc_err(
                -32602,
                "email hash must be exactly 32 bytes (64 hex chars)",
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);

        let mut locks: Vec<RpcTimeLock> = self
            .state
            .db
            .iter_all_timelocks()
            .map_err(|e| rpc_err(-32603, e.to_string()))?
            .into_iter()
            .filter(|tlc| {
                tlc.recipient_email_hash == Some(hash)
                    && matches!(tlc.status, TimeLockStatus::Pending)
            })
            .map(tlc_to_rpc)
            .collect();

        locks.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(locks)
    }

    /// `chronx_getIncomingTransfers` — all incoming transactions for an account:
    /// direct transfers received, claimed email locks, and claimed timelocks.
    /// Sorted newest-first, max 500 results.
    async fn get_incoming_transfers(&self, account_id: String) -> RpcResult<Vec<RpcIncomingTransfer>> {
        let id = AccountId::from_b58(&account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let mut results: Vec<RpcIncomingTransfer> = Vec::new();

        // 1. Scan all DAG vertices for Transfer actions where to == account_id
        let vertices = self.state.db.iter_all_vertices()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        for v in &vertices {
            let tx = &v.transaction;
            for action in &tx.actions {
                if let Action::Transfer { to, amount } = action {
                    if *to == id && tx.from != id {
                        results.push(RpcIncomingTransfer {
                            tx_id: tx.tx_id.to_hex(),
                            from: tx.from.to_b58(),
                            amount_chronos: amount.to_string(),
                            amount_kx: format!("{}.{:06}", amount / CHRONOS_PER_KX, amount % CHRONOS_PER_KX),
                            timestamp: tx.timestamp,
                            tx_type: "transfer".to_string(),
                            memo: None,
                        });
                    }
                }
            }
        }

        // 2. Find claimed timelocks where this account is the recipient
        let incoming_locks = self.state.db.iter_timelocks_for_recipient(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        for tlc in incoming_locks {
            if tlc.sender == id { continue; }
            match &tlc.status {
                TimeLockStatus::Claimed { .. } => {
                    let tx_type = if tlc.recipient_email_hash.is_some() {
                        "email_claim"
                    } else {
                        "timelock_claim"
                    };
                    results.push(RpcIncomingTransfer {
                        tx_id: tlc.id.to_hex(),
                        from: tlc.sender.to_b58(),
                        amount_chronos: tlc.amount.to_string(),
                        amount_kx: format!("{}.{:06}", tlc.amount / CHRONOS_PER_KX, tlc.amount % CHRONOS_PER_KX),
                        timestamp: tlc.created_at,
                        tx_type: tx_type.to_string(),
                        memo: tlc.memo.clone(),
                    });
                }
                _ => {}
            }
        }

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        results.truncate(500);
        Ok(results)
    }


    /// `chronx_getOutgoingTransfers` -- all outgoing transactions for an account:
    /// direct transfers sent, email timelocks, and promise sends.
    /// Sorted newest-first, max 500 results.
    async fn get_outgoing_transfers(&self, account_id: String) -> RpcResult<Vec<RpcOutgoingTransfer>> {
        let id = AccountId::from_b58(&account_id)
            .map_err(|e| rpc_err(-32602, format!("invalid account id: {e}")))?;

        let mut results: Vec<RpcOutgoingTransfer> = Vec::new();

        // 1. Scan all DAG vertices for Transfer actions where from == account_id
        let vertices = self.state.db.iter_all_vertices()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        for v in &vertices {
            let tx = &v.transaction;
            if tx.from != id { continue; }
            for action in &tx.actions {
                if let Action::Transfer { to, amount } = action {
                    if *to != id {
                        results.push(RpcOutgoingTransfer {
                            tx_id: tx.tx_id.to_hex(),
                            to: to.to_b58(),
                            amount_chronos: amount.to_string(),
                            amount_kx: format!("{}.{:06}", amount / CHRONOS_PER_KX, amount % CHRONOS_PER_KX),
                            timestamp: tx.timestamp,
                            tx_type: "transfer".to_string(),
                            memo: None,
                        });
                    }
                }
            }
        }

        // 2. Find timelocks where this account is the sender
        let outgoing_locks = self.state.db.iter_timelocks_for_sender(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        for tlc in outgoing_locks {
            let tx_type = if tlc.recipient_email_hash.is_some() {
                "email_send"
            } else {
                "promise_sent"
            };
            let recipient = if tlc.recipient_email_hash.is_some() {
                String::new()
            } else {
                tlc.recipient_account_id.to_b58()
            };
            results.push(RpcOutgoingTransfer {
                tx_id: tlc.id.to_hex(),
                to: recipient,
                amount_chronos: tlc.amount.to_string(),
                amount_kx: format!("{}.{:06}", tlc.amount / CHRONOS_PER_KX, tlc.amount % CHRONOS_PER_KX),
                timestamp: tlc.created_at,
                tx_type: tx_type.to_string(),
                memo: tlc.memo.clone(),
            });
        }

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        results.truncate(500);
        Ok(results)
    }
    /// `chronx_getGlobalLockStats` — aggregate stats across all Pending timelocks.
    /// Designed for the public website stats bar: single cheap call, no pagination.
    async fn get_global_lock_stats(&self) -> RpcResult<RpcGlobalLockStats> {
        let all = self
            .state
            .db
            .iter_all_timelocks()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let mut active_lock_count: u64 = 0;
        let mut total_locked_chronos: u128 = 0;

        for tlc in &all {
            if matches!(tlc.status, TimeLockStatus::Pending) {
                active_lock_count += 1;
                total_locked_chronos += tlc.amount;
            }
        }

        const CHRONOS_PER_KX: u128 = 1_000_000;
        let total_locked_kx = total_locked_chronos / CHRONOS_PER_KX;

        Ok(RpcGlobalLockStats {
            active_lock_count,
            total_locked_chronos: total_locked_chronos.to_string(),
            total_locked_kx: total_locked_kx.to_string(),
        })
    }

    // ── V4 Cascade Send ────────────────────────────────────────────────────

    /// `chronx_sendCascade` — submit a cascade transaction.
    /// This is just `sendTransaction` with a semantic name. The transaction
    /// must contain multiple `TimeLockCreate` actions sharing the same
    /// `extension_data` (0xC5 + claim_secret_hash). Returns TxId hex.
    async fn send_cascade(&self, tx_hex: String) -> RpcResult<String> {
        // Delegate to the same pipeline as sendTransaction.
        self.send_transaction(tx_hex).await
    }

    /// `chronx_getCascadeDetails` — return all locks sharing a claim_secret_hash.
    async fn get_cascade_details(
        &self,
        claim_secret_hash: String,
    ) -> RpcResult<RpcCascadeDetails> {
        let hash_bytes = hex::decode(&claim_secret_hash)
            .map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;
        if hash_bytes.len() != 32 {
            return Err(rpc_err(-32602, "claim_secret_hash must be 64 hex chars (32 bytes)"));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let lock_ids = self
            .state
            .db
            .get_locks_by_claim_hash(&hash)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let mut locks = Vec::new();
        let mut total_chronos: u128 = 0;
        let mut pending_count: u32 = 0;
        let mut claimed_count: u32 = 0;

        for lock_id in &lock_ids {
            if let Some(tlc) = self
                .state
                .db
                .get_timelock(lock_id)
                .map_err(|e| rpc_err(-32603, e.to_string()))?
            {
                total_chronos += tlc.amount;
                match &tlc.status {
                    TimeLockStatus::Pending => pending_count += 1,
                    TimeLockStatus::Claimed { .. } => claimed_count += 1,
                    _ => {}
                }
                locks.push(tlc_to_rpc(tlc));
            }
        }

        // Sort by unlock_at ascending.
        locks.sort_by_key(|l| l.unlock_at);

        Ok(RpcCascadeDetails {
            claim_secret_hash,
            lock_count: locks.len() as u32,
            total_chronos: total_chronos.to_string(),
            total_kx: (total_chronos / CHRONOS_PER_KX).to_string(),
            pending_count,
            claimed_count,
            locks,
        })
    }


    // ── Genesis 7 — Verified Delivery Protocol ────────────────────────────

    /// `chronx_getVerifierRegistry` — return all Active verifiers.
    async fn get_verifier_registry(&self) -> RpcResult<Vec<RpcVerifierRecord>> {
        let verifiers = self.state.db.get_all_active_verifiers()
            .map_err(|e: ChronxError| rpc_err(-32603, e.to_string()))?;
        Ok(verifiers.into_iter().map(|v| RpcVerifierRecord {
            verifier_name: v.verifier_name,
            wallet_address: v.wallet_address,
            bond_amount_kx: v.bond_amount_kx,
            jurisdiction: v.jurisdiction,
            role: v.role,
            approval_date: v.approval_date,
            status: v.status,
        }).collect())
    }

    /// `chronx_getPromiseTriggerStatus` — return trigger record for a lock.
    async fn get_promise_trigger_status(&self, lock_id: String) -> RpcResult<Option<RpcPromiseTriggerStatus>> {
        let id_bytes = hex::decode(&lock_id)
            .map_err(|_| rpc_err(-32602, "invalid lock_id hex"))?;
        if id_bytes.len() != 32 {
            return Err(rpc_err(-32602, "lock_id must be 32 bytes (64 hex chars)").into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id_bytes);
        let tx_id = TxId::from_bytes(arr);
        let trigger = self.state.db.get_promise_trigger(&tx_id)
            .map_err(|e: ChronxError| rpc_err(-32603, e.to_string()))?;
        Ok(trigger.map(|t| RpcPromiseTriggerStatus {
            lock_id: t.lock_id,
            trigger_fired_at: t.trigger_fired_at,
            package_routed_to: t.package_routed_to,
            activation_deposit_chronos: t.activation_deposit_chronos,
            remaining_chronos: t.remaining_chronos,
            expiry_at: t.expiry_at,
        }))
    }

    /// `chronx_getGenesis7Constants` — return Genesis 7 constants from metadata.
    async fn get_genesis7_constants(&self) -> RpcResult<serde_json::Value> {
        let meta: Option<Vec<u8>> = self.state.db.get_meta("genesis_7_constants")
            .map_err(|e: ChronxError| rpc_err(-32603, e.to_string()))?;
        match meta {
            Some(bytes) => {
                let s = String::from_utf8_lossy(&bytes);
                serde_json::from_str(&s)
                    .map_err(|e: serde_json::Error| rpc_err(-32603, format!("failed to parse genesis_7_constants: {}", e)))
            }
            None => Ok(serde_json::json!(null)),
        }
    }

    /// `chronx_getHumanityStakeBalance` — return the Humanity Stake Pool balance.
    async fn get_humanity_stake_balance(&self) -> RpcResult<RpcHumanityStakeBalance> {
        let pool_bytes: Option<Vec<u8>> = self.state.db.get_meta("genesis_7_humanity_stake_pool")
            .map_err(|e: ChronxError| rpc_err(-32603, e.to_string()))?;
        let pool_address = match pool_bytes {
            Some(ref b) => String::from_utf8_lossy(b).to_string(),
            None => return Err(rpc_err(-32603, "Humanity Stake Pool address not found in genesis metadata").into()),
        };
        let pool_id = AccountId::from_b58(&pool_address)
            .map_err(|_e| rpc_err(-32603, "invalid Humanity Stake Pool address"))?;
        let balance: u128 = self.state.db.get_account(&pool_id)
            .map_err(|e: ChronxError| rpc_err(-32603, e.to_string()))?
            .map(|a| a.balance)
            .unwrap_or(0);
        Ok(RpcHumanityStakeBalance {
            balance_chronos: balance.to_string(),
            balance_kx: (balance / CHRONOS_PER_KX).to_string(),
        })
    }

    /// `chronx_getPromiseAxioms` — return Promise Axioms and Trading Axioms.
    async fn get_promise_axioms(&self) -> RpcResult<RpcPromiseAxioms> {
        let promise = self.state.db.get_meta("promise_axioms")
            .map_err(|e: ChronxError| rpc_err(-32603, e.to_string()))?
            .map(|b: Vec<u8>| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        let trading = self.state.db.get_meta("trading_axioms")
            .map_err(|e: ChronxError| rpc_err(-32603, e.to_string()))?
            .map(|b: Vec<u8>| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        // Genesis 8: compute combined axiom hash
        let combined_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(promise.as_bytes());
            hasher.update(trading.as_bytes());
            hasher.finalize().to_hex().to_string()
        };
        Ok(RpcPromiseAxioms {
            promise_axioms: promise,
            trading_axioms: trading,
            combined_axiom_hash: combined_hash,
        })
    }


    // ── Genesis 8 — AI Agent Architecture ────────────────────────────

    /// `chronx_getAgentRegistry` — return all Active agents.
    async fn get_agent_registry(&self) -> RpcResult<Vec<RpcAgentRecord>> {
        let agents = self.state.db.get_all_active_agents()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(agents.into_iter().map(|a| RpcAgentRecord {
            agent_name: a.agent_name,
            agent_wallet: a.agent_wallet,
            agent_code_hash: a.agent_code_hash,
            kyber_public_key_hex: a.kyber_public_key_hex,
            operator_wallet: a.operator_wallet,
            jurisdiction: a.jurisdiction,
            status: a.status,
            registered_at: a.registered_at,
            governance_tx_id: a.governance_tx_id,
        }).collect())
    }

    /// `chronx_getAgentLoanRecord` — return a single loan record by lock_id.
    async fn get_agent_loan_record(&self, lock_id: String) -> RpcResult<Option<RpcAgentLoanRecord>> {
        let record = self.state.db.get_agent_loan(&lock_id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcAgentLoanRecord {
            lock_id: r.lock_id,
            agent_wallet: r.agent_wallet,
            agent_name: r.agent_name,
            loan_amount_chronos: r.loan_amount_chronos,
            original_promise_value: r.original_promise_value,
            investable_fraction: r.investable_fraction,
            return_wallet: r.return_wallet,
            return_date: r.return_date,
            risk_level: r.risk_level,
            investment_exclusions: r.investment_exclusions,
            grantor_intent: r.grantor_intent,
            loan_package_encrypted: r.loan_package_encrypted,
            disbursed_at: r.disbursed_at,
            returned_at: r.returned_at,
            returned_chronos: r.returned_chronos,
            status: r.status,
        }))
    }

    /// `chronx_getAgentCustodyRecord` — return a single custody record by lock_id.
    async fn get_agent_custody_record(&self, lock_id: String) -> RpcResult<Option<RpcAgentCustodyRecord>> {
        let record = self.state.db.get_agent_custody(&lock_id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcAgentCustodyRecord {
            lock_id: r.lock_id,
            agent_name: r.agent_name,
            agent_wallet: r.agent_wallet,
            agent_code_hash: r.agent_code_hash,
            operator_wallet: r.operator_wallet,
            axiom_version_hash: r.axiom_version_hash,
            grantor_consent_at: r.grantor_consent_at,
            agent_consent_at: r.agent_consent_at,
            released_at: r.released_at,
            amount_chronos: r.amount_chronos,
            statement: r.statement,
        }))
    }

    /// `chronx_getAgentHistory` — all custody records for an agent wallet.
    async fn get_agent_history(&self, agent_wallet: String) -> RpcResult<Vec<RpcAgentCustodyRecord>> {
        let records = self.state.db.iter_agent_custody_for_wallet(&agent_wallet)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(records.into_iter().map(|r| RpcAgentCustodyRecord {
            lock_id: r.lock_id,
            agent_name: r.agent_name,
            agent_wallet: r.agent_wallet,
            agent_code_hash: r.agent_code_hash,
            operator_wallet: r.operator_wallet,
            axiom_version_hash: r.axiom_version_hash,
            grantor_consent_at: r.grantor_consent_at,
            agent_consent_at: r.agent_consent_at,
            released_at: r.released_at,
            amount_chronos: r.amount_chronos,
            statement: r.statement,
        }).collect())
    }

    /// `chronx_getAxiomConsent` — return axiom consent record.
    async fn get_axiom_consent(&self, lock_id: String, party_type: String) -> RpcResult<Option<RpcAxiomConsentRecord>> {
        let record = self.state.db.get_axiom_consent(&lock_id, &party_type)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcAxiomConsentRecord {
            lock_id: r.lock_id,
            party_type: r.party_type,
            party_wallet: r.party_wallet,
            axiom_hash: r.axiom_hash,
            consented_at: r.consented_at,
        }))
    }

    /// `chronx_getInvestablePromises` — all agent-managed, unassigned promises within investment window.
    async fn get_investable_promises(&self) -> RpcResult<Vec<RpcInvestablePromise>> {
        use chronx_core::constants::MISAI_MIN_INVESTMENT_WINDOW_DAYS;

        let now = chrono::Utc::now().timestamp();
        let min_unlock = now + (MISAI_MIN_INVESTMENT_WINDOW_DAYS as i64 * 86400);

        let all_locks = self.state.db.iter_all_timelocks()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let results: Vec<RpcInvestablePromise> = all_locks.into_iter()
            .filter(|tlc| {
                tlc.status == TimeLockStatus::Pending
                    && tlc.lock_type.as_deref() == Some("M")
                    && tlc.unlock_at > min_unlock
            })
            .map(|tlc| RpcInvestablePromise {
                lock_id: tlc.id.to_hex(),
                sender: tlc.sender.to_b58(),
                amount_chronos: tlc.amount.to_string(),
                amount_kx: (tlc.amount / CHRONOS_PER_KX).to_string(),
                unlock_at: tlc.unlock_at,
                lock_type: tlc.lock_type,
                lock_metadata: tlc.lock_metadata,
            })
            .collect();

        Ok(results)
    }

    /// `chronx_getGenesis8Constants` — return Genesis 8 constants from metadata.
    async fn get_genesis8_constants(&self) -> RpcResult<serde_json::Value> {
        let meta: Option<Vec<u8>> = self.state.db.get_meta("genesis_8_constants")
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        match meta {
            Some(bytes) => {
                let s = String::from_utf8_lossy(&bytes);
                serde_json::from_str(&s)
                    .map_err(|e| rpc_err(-32603, format!("failed to parse genesis_8_constants: {}", e)))
            }
            None => Ok(serde_json::json!(null)),
        }
    }

    /// `chronx_getMisaiPubkey` — return MISAI executor's X25519 public key (hex).
    /// The wallet uses this to encrypt lock_metadata for Type M locks.
    async fn get_misai_pubkey(&self) -> RpcResult<serde_json::Value> {
        let meta = self.state.db.get_meta("misai_x25519_pubkey")
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        match meta {
            Some(bytes) => {
                let hex_str = String::from_utf8_lossy(&bytes).to_string();
                Ok(serde_json::json!({ "pubkey_hex": hex_str }))
            }
            None => Ok(serde_json::json!({ "pubkey_hex": null })),
        }
    }

    /// `chronx_getRecentTransactionsDetailed` - recent transactions with parsed action details.
    async fn get_recent_transactions_detailed(&self, limit: u32) -> RpcResult<Vec<RpcDetailedTx>> {
        let limit = limit.min(500) as usize;

        let mut vertices = self
            .state
            .db
            .iter_all_vertices()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        vertices.sort_by(|a, b| b.transaction.timestamp.cmp(&a.transaction.timestamp));

        let result: Vec<RpcDetailedTx> = vertices
            .into_iter()
            .take(limit)
            .map(|v| {
                let actions: Vec<RpcActionSummary> = v.transaction.actions.iter().map(|action| {
                    match action {
                        Action::Transfer { to, amount } => RpcActionSummary {
                            action_type: "Transfer".to_string(),
                            to_address: Some(to.to_b58()),
                            amount_chronos: Some(amount.to_string()),
                            amount_kx: Some((amount / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::TimeLockCreate {
                            amount, unlock_at, memo, recipient_email_hash, ..
                        } => {
                            let email_hash_hex = recipient_email_hash.map(|h| hex::encode(h));
                            let atype = if email_hash_hex.is_some() { "EmailLock" } else { "TimeLock" };
                            RpcActionSummary {
                                action_type: atype.to_string(),
                                to_address: None,
                                amount_chronos: Some(amount.to_string()),
                                amount_kx: Some((amount / CHRONOS_PER_KX).to_string()),
                                lock_until: Some(*unlock_at),
                                memo: memo.clone(),
                                email_hash: email_hash_hex,
                                lock_id: None,
                            }
                        },
                        Action::TimeLockClaim { lock_id } => RpcActionSummary {
                            action_type: "Claim".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(lock_id.0.to_hex()),
                        },
                        Action::TimeLockClaimWithSecret { lock_id, .. } => RpcActionSummary {
                            action_type: "EmailClaim".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(lock_id.0.to_hex()),
                        },
                        Action::CancelTimeLock { lock_id } => RpcActionSummary {
                            action_type: "Cancel".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(lock_id.0.to_hex()),
                        },
                        Action::ReclaimExpiredLock { lock_id } => RpcActionSummary {
                            action_type: "Reclaim".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(lock_id.0.to_hex()),
                        },
                        _ => RpcActionSummary {
                            action_type: "Other".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: None,
                        },
                    }
                }).collect();

                // Extract memo from the first action that has one
                let memo = actions.iter().find_map(|a| a.memo.clone());

                RpcDetailedTx {
                    tx_id: v.transaction.tx_id.to_hex(),
                    timestamp: v.transaction.timestamp,
                    from: v.transaction.from.to_b58(),
                    action_count: v.transaction.actions.len(),
                    depth: v.depth,
                    actions,
                    memo,
                }
            })
            .collect();

        Ok(result)
    }

    // ── Genesis 8 — Invoice/Credit/Deposit/Conditional/Ledger RPC impls ──

    async fn get_invoice(&self, invoice_id_hex: String) -> RpcResult<Option<RpcInvoiceRecord>> {
        let bytes = hex::decode(&invoice_id_hex).map_err(|e| rpc_err(-32602, e.to_string()))?;
        if bytes.len() != 32 { return Err(rpc_err(-32602, "invoice_id must be 32 bytes hex")); }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        let record = self.state.db.get_invoice(&id).map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| invoice_to_rpc(&r)))
    }

    async fn get_open_invoices(&self, wallet: String) -> RpcResult<Vec<RpcInvoiceRecord>> {
        let account_id = AccountId::from_b58(&wallet).map_err(|e| rpc_err(-32602, e.to_string()))?;
        let account = self.state.db.get_account(&account_id).map_err(|e| rpc_err(-32603, e.to_string()))?;
        let pubkey_bytes = match &account {
            Some(acc) => match &acc.auth_policy {
                chronx_core::account::AuthPolicy::SingleSig { public_key: ref pk } => pk.0.clone(),
                _ => return Ok(Vec::new()),
            },
            None => return Ok(Vec::new()),
        };
        let records = self.state.db.iter_open_invoices_for_wallet(&pubkey_bytes)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(records.iter().map(invoice_to_rpc).collect())
    }

    async fn get_credit_authorization(&self, credit_id_hex: String) -> RpcResult<Option<RpcCreditRecord>> {
        let bytes = hex::decode(&credit_id_hex).map_err(|e| rpc_err(-32602, e.to_string()))?;
        if bytes.len() != 32 { return Err(rpc_err(-32602, "credit_id must be 32 bytes hex")); }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        let record = self.state.db.get_credit(&id).map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| credit_to_rpc(&r)))
    }

    async fn get_open_credits(&self, wallet: String) -> RpcResult<Vec<RpcCreditRecord>> {
        let account_id = AccountId::from_b58(&wallet).map_err(|e| rpc_err(-32602, e.to_string()))?;
        let account = self.state.db.get_account(&account_id).map_err(|e| rpc_err(-32603, e.to_string()))?;
        let pubkey_bytes = match &account {
            Some(acc) => match &acc.auth_policy {
                chronx_core::account::AuthPolicy::SingleSig { public_key: ref pk } => pk.0.clone(),
                _ => return Ok(Vec::new()),
            },
            None => return Ok(Vec::new()),
        };
        let records = self.state.db.iter_open_credits_for_wallet(&pubkey_bytes)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(records.iter().map(credit_to_rpc).collect())
    }

    async fn get_deposit(&self, deposit_id_hex: String) -> RpcResult<Option<RpcDepositRecord>> {
        let bytes = hex::decode(&deposit_id_hex).map_err(|e| rpc_err(-32602, e.to_string()))?;
        if bytes.len() != 32 { return Err(rpc_err(-32602, "deposit_id must be 32 bytes hex")); }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        let record = self.state.db.get_deposit(&id).map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| deposit_to_rpc(&r)))
    }

    async fn get_active_deposits(&self, wallet: String) -> RpcResult<Vec<RpcDepositRecord>> {
        let account_id = AccountId::from_b58(&wallet).map_err(|e| rpc_err(-32602, e.to_string()))?;
        let account = self.state.db.get_account(&account_id).map_err(|e| rpc_err(-32603, e.to_string()))?;
        let pubkey_bytes = match &account {
            Some(acc) => match &acc.auth_policy {
                chronx_core::account::AuthPolicy::SingleSig { public_key: ref pk } => pk.0.clone(),
                _ => return Ok(Vec::new()),
            },
            None => return Ok(Vec::new()),
        };
        let records = self.state.db.iter_active_deposits_for_wallet(&pubkey_bytes)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(records.iter().map(deposit_to_rpc).collect())
    }

    async fn get_conditional_payment(&self, type_v_id_hex: String) -> RpcResult<Option<RpcConditionalRecord>> {
        let bytes = hex::decode(&type_v_id_hex).map_err(|e| rpc_err(-32602, e.to_string()))?;
        if bytes.len() != 32 { return Err(rpc_err(-32602, "type_v_id must be 32 bytes hex")); }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        let record = self.state.db.get_conditional(&id).map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| conditional_to_rpc(&r)))
    }

    async fn get_ledger_entries(&self, promise_id_hex: String) -> RpcResult<Vec<RpcLedgerEntryRecord>> {
        let bytes = hex::decode(&promise_id_hex).map_err(|e| rpc_err(-32602, e.to_string()))?;
        if bytes.len() != 32 { return Err(rpc_err(-32602, "promise_id must be 32 bytes hex")); }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        let records = self.state.db.get_ledger_entries_by_promise(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(records.iter().map(ledger_entry_to_rpc).collect())
    }


    async fn get_sign_of_life_status(&self, lock_id: String) -> RpcResult<Option<RpcSignOfLifeRecord>> {
        let record = self.state.db.get_sign_of_life(&lock_id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcSignOfLifeRecord {
            lock_id: r.lock_id,
            interval_days: r.interval_days,
            grace_days: r.grace_days,
            last_attestation: r.last_attestation,
            next_due: r.next_due,
            status: r.status,
            responsible: r.responsible,
            created_at: r.created_at,
        }))
    }

    async fn get_promise_chain(&self, promise_id_hex: String) -> RpcResult<Option<RpcPromiseChainRecord>> {
        let bytes = hex::decode(&promise_id_hex).map_err(|e| rpc_err(-32602, e.to_string()))?;
        if bytes.len() != 32 { return Err(rpc_err(-32602, "promise_id must be 32 bytes hex")); }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        let record = self.state.db.get_promise_chain(&id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcPromiseChainRecord {
            promise_id: hex::encode(r.promise_id),
            entry_count: r.entries.len() as u32,
            last_anchor_hash: r.last_anchor_hash.map(|h| hex::encode(h)),
            last_anchor_at: r.last_anchor_at,
            created_at: r.created_at,
        }))
    }

    async fn get_promise_chain_anchors(&self, promise_id_hex: String) -> RpcResult<Option<RpcPromiseChainRecord>> {
        // Same as get_promise_chain — anchors are part of the chain record
        self.get_promise_chain(promise_id_hex).await
    }

    async fn get_verified_identity(&self, wallet_b58: String) -> RpcResult<Option<RpcIdentityRecord>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let record = self.state.db.get_latest_identity(&wallet_b58, now)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcIdentityRecord {
            wallet: r.wallet_b58,
            issuer_wallet: r.issuer_wallet_b58,
            display_name: r.display_name,
            badge_code: r.badge_code,
            badge_color: r.badge_color,
            verified: r.verified,
            entry_id: hex::encode(r.entry_id),
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            issuer_notes: r.issuer_notes,
        }))
    }

    async fn get_identity_history(&self, wallet_b58: String) -> RpcResult<Vec<RpcLedgerEntryRecord>> {
        let entries = self.state.db.get_identity_entries(&wallet_b58)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(entries.iter().map(ledger_entry_to_rpc).collect())
    }

    // ── Genesis 9 — TYPE_G Wallet Group implementations ─────────────────

    async fn get_group(&self, group_id_hex: String) -> RpcResult<Option<serde_json::Value>> {
        let bytes = hex::decode(&group_id_hex).map_err(|e| {
            ErrorObject::owned(-32602, format!("Invalid hex: {}", e), None::<()>)
        })?;
        if bytes.len() != 32 {
            return Err(ErrorObject::owned(-32602, "group_id must be 32 bytes (64 hex chars)", None::<()>));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        match self.state.db.get_group(&id) {
            Ok(Some(record)) => {
                let val = serde_json::json!({
                    "group_id": group_id_hex,
                    "owner_pubkey": hex::encode(&record.owner_pubkey.0),
                    "name_hash": hex::encode(record.name_hash),
                    "member_count": record.member_count,
                    "created_at": record.created_at,
                    "status": format!("{:?}", record.status),
                    "members": record.members.iter().map(|m| hex::encode(&m.0)).collect::<Vec<_>>(),
                });
                Ok(Some(val))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ErrorObject::owned(-32603, format!("{}", e), None::<String>)),
        }
    }

    async fn is_group_member(&self, group_id_hex: String, pubkey_hex: String) -> RpcResult<serde_json::Value> {
        let gid_bytes = hex::decode(&group_id_hex).map_err(|e| {
            ErrorObject::owned(-32602, format!("Invalid group_id hex: {}", e), None::<()>)
        })?;
        if gid_bytes.len() != 32 {
            return Err(ErrorObject::owned(-32602, "group_id must be 32 bytes", None::<()>));
        }
        let mut gid = [0u8; 32];
        gid.copy_from_slice(&gid_bytes);

        let pk_bytes = hex::decode(&pubkey_hex).map_err(|e| {
            ErrorObject::owned(-32602, format!("Invalid pubkey hex: {}", e), None::<()>)
        })?;
        let pubkey = chronx_core::types::DilithiumPublicKey(pk_bytes);

        match self.state.db.is_group_member(&gid, &pubkey) {
            Ok(member) => Ok(serde_json::json!({ "member": member })),
            Err(e) => Err(ErrorObject::owned(-32603, format!("{}", e), None::<String>)),
        }
    }
}


// ── Genesis 8 — RPC conversion helpers ──────────────────────────────────────

fn invoice_to_rpc(r: &chronx_state::db::InvoiceRecord) -> RpcInvoiceRecord {
    let status = match r.status {
        InvoiceStatus::Open => "Open",
        InvoiceStatus::Fulfilled => "Fulfilled",
        InvoiceStatus::Lapsed => "Lapsed",
        InvoiceStatus::Cancelled => "Cancelled",
    };
    RpcInvoiceRecord {
        invoice_id: hex::encode(r.invoice_id),
        issuer_pubkey: hex::encode(&r.issuer_pubkey),
        payer_pubkey: r.payer_pubkey.as_ref().map(|p| hex::encode(p)),
        amount_chronos: r.amount_chronos.to_string(),
        amount_kx: format!("{}", r.amount_chronos / CHRONOS_PER_KX as u64),
        expiry: r.expiry,
        status: status.to_string(),
        created_at: r.created_at,
        fulfilled_at: r.fulfilled_at,
    }
}

fn credit_to_rpc(r: &chronx_state::db::CreditRecord) -> RpcCreditRecord {
    let status = match r.status {
        CreditStatus::Open => "Open",
        CreditStatus::Closed => "Closed",
        CreditStatus::Lapsed => "Lapsed",
        CreditStatus::Revoked => "Revoked",
    };
    RpcCreditRecord {
        credit_id: hex::encode(r.credit_id),
        grantor_pubkey: hex::encode(&r.grantor_pubkey),
        beneficiary_pubkey: hex::encode(&r.beneficiary_pubkey),
        ceiling_chronos: r.ceiling_chronos.to_string(),
        ceiling_kx: format!("{}", r.ceiling_chronos / CHRONOS_PER_KX as u64),
        per_draw_max_chronos: r.per_draw_max_chronos.map(|v| v.to_string()),
        expiry: r.expiry,
        drawn_chronos: r.drawn_chronos.to_string(),
        drawn_kx: format!("{}", r.drawn_chronos / CHRONOS_PER_KX as u64),
        status: status.to_string(),
        created_at: r.created_at,
    }
}

fn deposit_to_rpc(r: &chronx_state::db::DepositRecord) -> RpcDepositRecord {
    let status = match r.status {
        DepositStatus::Active => "Active",
        DepositStatus::Matured => "Matured",
        DepositStatus::Settled => "Settled",
        DepositStatus::Defaulted => "Defaulted",
    };
    RpcDepositRecord {
        deposit_id: hex::encode(r.deposit_id),
        depositor_pubkey: hex::encode(&r.depositor_pubkey),
        obligor_pubkey: hex::encode(&r.obligor_pubkey),
        principal_chronos: r.principal_chronos.to_string(),
        principal_kx: format!("{}", r.principal_chronos / CHRONOS_PER_KX as u64),
        rate_basis_points: r.rate_basis_points,
        term_seconds: r.term_seconds,
        compounding: r.compounding.clone(),
        maturity_timestamp: r.maturity_timestamp,
        total_due_chronos: r.total_due_chronos.to_string(),
        total_due_kx: format!("{}", r.total_due_chronos / CHRONOS_PER_KX as u64),
        status: status.to_string(),
        created_at: r.created_at,
        settled_at: r.settled_at,
    }
}

fn conditional_to_rpc(r: &chronx_state::db::ConditionalRecord) -> RpcConditionalRecord {
    let status = match r.status {
        ConditionalStatus::Pending => "Pending",
        ConditionalStatus::Released => "Released",
        ConditionalStatus::Voided => "Voided",
        ConditionalStatus::Returned => "Returned",
        ConditionalStatus::Escrowed => "Escrowed",
    };
    RpcConditionalRecord {
        type_v_id: hex::encode(r.type_v_id),
        sender_pubkey: hex::encode(&r.sender_pubkey),
        recipient_pubkey: hex::encode(&r.recipient_pubkey),
        amount_chronos: r.amount_chronos.to_string(),
        amount_kx: format!("{}", r.amount_chronos / CHRONOS_PER_KX as u64),
        min_attestors: r.min_attestors,
        attestations_received: r.attestations_received.len() as u32,
        valid_until: r.valid_until,
        fallback: r.fallback.clone(),
        status: status.to_string(),
        created_at: r.created_at,
    }
}

fn ledger_entry_to_rpc(r: &chronx_state::db::LedgerEntryRecord) -> RpcLedgerEntryRecord {
    RpcLedgerEntryRecord {
        entry_id: hex::encode(r.entry_id),
        author_pubkey: hex::encode(&r.author_pubkey),
        promise_id: r.promise_id.map(|id| hex::encode(id)),
        entry_type: r.entry_type.clone(),
        content_hash: hex::encode(r.content_hash),
        content_summary: String::from_utf8_lossy(&r.content_summary).to_string(),
        timestamp: r.timestamp,
    }
}
