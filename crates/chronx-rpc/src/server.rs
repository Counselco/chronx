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
use std::sync::atomic::{AtomicU64, Ordering};

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
use chronx_state::db::{InvoiceStatus, CreditStatus, DepositStatus, ConditionalStatus, LoanStatus};

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
    RpcLoanPaymentStage, RpcLoanDefaultRecord, RpcOraclePrice, RpcLoanCounts,
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
    /// Shared counter of currently connected P2P peers.
    pub peer_count: Arc<AtomicU64>,
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
        TimeLockStatus::PartiallyReleased { .. } => "PartiallyReleased".to_string(),
        TimeLockStatus::OracleTriggered { .. } => "OracleTriggered".to_string(),
        TimeLockStatus::OracleExpiredClean { .. } => "OracleExpiredClean".to_string(),
        TimeLockStatus::AttestorFailed { .. } => "AttestorFailed".to_string(),
    }
}

fn tlc_to_rpc(tlc: chronx_core::account::TimeLockContract) -> RpcTimeLock {
    let status = tlc_status_str(&tlc.status);

    // If lock_marker starts with 0xC5 marker and is 33 bytes,
    // the remaining 32 bytes are BLAKE3(claim_code). Locks sharing the
    // same hash belong to the same Promise Series.
    let claim_secret_hash = tlc.lock_marker.as_ref().and_then(|d| {
        if d.len() == 33 && d[0] == 0xC5 {
            Some(hex::encode(&d[1..]))
        } else {
            None
        }
    });

    let email_recipient_hash = tlc.email_recipient_hash.map(hex::encode);
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
        email_recipient_hash,
        claim_window_secs: claim_window_secs_val,
        unclaimed_action: unclaimed_action_str,
        lock_type: tlc.lock_type,
        lock_metadata: tlc.lock_metadata,
        convert_to: None, // populated by caller from convert_to_suggestion tree
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
    async fn get_transaction(&self, tx_id: String) -> RpcResult<Option<RpcDetailedTx>> {
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
                let actions: Vec<RpcActionSummary> = v.transaction.actions.iter().map(|action| {
                    match action {
                        Action::Transfer { to, amount, .. } => RpcActionSummary {
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
                            amount, unlock_at, memo, email_recipient_hash, ..
                        } => {
                            let email_hash_hex = email_recipient_hash.map(hex::encode);
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
                        Action::LoanOffer(ref lo) => RpcActionSummary {
                            action_type: "LoanOffer".to_string(),
                            to_address: Some(lo.borrower_wallet.to_string()),
                            amount_chronos: Some(lo.principal_chronos.to_string()),
                            amount_kx: Some((lo.principal_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: lo.memo.clone(),
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::LoanAcceptance(ref la) => RpcActionSummary {
                            action_type: "LoanAcceptance".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(hex::encode(la.loan_id)),
                        },
                        Action::LoanDecline(ref ld) => RpcActionSummary {
                            action_type: "LoanDecline".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(hex::encode(ld.loan_id)),
                        },
                        Action::LoanExit { .. } => RpcActionSummary {
                            action_type: "LoanExit".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::LoanRescissionCancel { ref loan_id, .. } => RpcActionSummary {
                            action_type: "LoanRescissionCancel".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::DrawRequest { ref loan_id, amount_chronos, .. } => RpcActionSummary {
                            action_type: "DrawRequest".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::DrawApproval { ref loan_id, amount_chronos, .. } => RpcActionSummary {
                            action_type: "DrawApproval".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::DrawDecline { ref loan_id, .. } => RpcActionSummary {
                            action_type: "DrawDecline".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::PartialExit { ref loan_id, amount_chronos, .. } => RpcActionSummary {
                            action_type: "PartialExit".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::CreateLedgerEntry(ref le) => {
                            let atype = match le.entry_type {
                                chronx_core::transaction::LedgerEntryType::IdentityVerified => "IdentityVerified",
                                chronx_core::transaction::LedgerEntryType::IdentityRevoked => "IdentityRevoked",
                                _ => "LedgerEntry",
                            };
                            RpcActionSummary {
                                action_type: atype.to_string(),
                                to_address: None,
                                amount_chronos: None,
                                amount_kx: None,
                                lock_until: None,
                                memo: None,
                                email_hash: None,
                                lock_id: None,
                            }
                        },
                        Action::CreateDeposit(ref d) => RpcActionSummary {
                            action_type: "DepositCreate".to_string(),
                            to_address: Some("Savings".to_string()),
                            amount_chronos: Some(d.principal_chronos.to_string()),
                            amount_kx: Some((d.principal_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: Some(d.term_seconds as i64),
                            memo: None,
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::SettleDeposit(ref s) => RpcActionSummary {
                            action_type: "DepositSettle".to_string(),
                            to_address: Some("Available Balance".to_string()),
                            amount_chronos: Some(s.amount_chronos.to_string()),
                            amount_kx: Some((s.amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(hex::encode(s.deposit_id)),
                        },
                        Action::DepositDefault { ref deposit_id } => RpcActionSummary {
                            action_type: "DepositDefault".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(hex::encode(deposit_id)),
                        },
                        Action::CreateSavingsDeposit { amount_chronos } => RpcActionSummary {
                            action_type: "SavingsDeposit".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::WithdrawSavings { amount_chronos } => RpcActionSummary {
                            action_type: "SavingsWithdraw".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: None,
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

                let memo = actions.iter().find_map(|a| a.memo.clone());

                Ok(Some(RpcDetailedTx {
                    tx_id: v.transaction.tx_id.to_hex(),
                    timestamp: v.transaction.timestamp,
                    from: v.transaction.from.to_b58(),
                    action_count: v.transaction.actions.len(),
                    depth: v.depth,
                    actions,
                    memo,
                }))
            }
        }
    }

    /// `chronx_getLocks` — all locks where the account is sender or recipient,
    /// deduplicated and sorted newest-first.
    async fn get_locks(&self, account_id: String) -> RpcResult<Vec<RpcTimeLock>> {
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
            peer_count: self.state.peer_count.load(Ordering::Relaxed),
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

    /// `chronx_getLockById` — fetch a single time-lock by its TxId hex.
    async fn get_lock_by_id(&self, lock_id: String) -> RpcResult<Option<RpcTimeLock>> {
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

    /// `chronx_getLocksPaged` — paginated lock list for an account
    /// (max 200 per page). Deduplicated and sorted newest-first.
    async fn get_locks_paged(
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
            node_version: "1.0.0".to_string(),
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
    /// `email_recipient_hash` matches the provided 64-char hex (BLAKE3 of lowercase email).
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
                tlc.email_recipient_hash == Some(hash)
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
                if let Action::Transfer { to, amount, .. } = action {
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
            if let TimeLockStatus::Claimed { .. } = &tlc.status {
                let tx_type = if tlc.email_recipient_hash.is_some() {
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
                if let Action::Transfer { to, amount, .. } = action {
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
            let tx_type = if tlc.email_recipient_hash.is_some() {
                "email_send"
            } else {
                "promise_sent"
            };
            let recipient = if tlc.email_recipient_hash.is_some() {
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
    /// `chronx_getLockStats` — aggregate stats across all Pending timelocks.
    /// Designed for the public website stats bar: single cheap call, no pagination.
    async fn get_lock_stats(&self) -> RpcResult<RpcGlobalLockStats> {
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

    /// `chronx_submitCascade` — submit a cascade transaction.
    /// This is just `sendTransaction` with a semantic name. The transaction
    /// must contain multiple `TimeLockCreate` actions sharing the same
    /// `lock_marker` (0xC5 + claim_secret_hash). Returns TxId hex.
    async fn submit_cascade(&self, tx_hex: String) -> RpcResult<String> {
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


    // ── Verified Delivery Protocol ────────────────────────────

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
            return Err(rpc_err(-32602, "lock_id must be 32 bytes (64 hex chars)"));
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

    /// `chronx_getGenesis7Constants` — return protocol constants from metadata.
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
            None => return Err(rpc_err(-32603, "Humanity Stake Pool address not found in genesis metadata")),
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
        // protocol: compute combined axiom hash
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


    // ── AI Agent Architecture ────────────────────────────

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

    /// `chronx_getGenesis8Constants` — return protocol constants from metadata.
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
                        Action::Transfer { to, amount, .. } => RpcActionSummary {
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
                            amount, unlock_at, memo, email_recipient_hash, ..
                        } => {
                            let email_hash_hex = email_recipient_hash.map(hex::encode);
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
                        Action::LoanOffer(ref lo) => RpcActionSummary {
                            action_type: "LoanOffer".to_string(),
                            to_address: Some(lo.borrower_wallet.to_string()),
                            amount_chronos: Some(lo.principal_chronos.to_string()),
                            amount_kx: Some((lo.principal_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: lo.memo.clone(),
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::LoanAcceptance(ref la) => RpcActionSummary {
                            action_type: "LoanAcceptance".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(hex::encode(la.loan_id)),
                        },
                        Action::LoanDecline(ref ld) => RpcActionSummary {
                            action_type: "LoanDecline".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(hex::encode(ld.loan_id)),
                        },
                        Action::LoanExit { .. } => RpcActionSummary {
                            action_type: "LoanExit".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::LoanRescissionCancel { ref loan_id, .. } => RpcActionSummary {
                            action_type: "LoanRescissionCancel".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::DrawRequest { ref loan_id, amount_chronos, .. } => RpcActionSummary {
                            action_type: "DrawRequest".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::DrawApproval { ref loan_id, amount_chronos, .. } => RpcActionSummary {
                            action_type: "DrawApproval".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::DrawDecline { ref loan_id, .. } => RpcActionSummary {
                            action_type: "DrawDecline".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::PartialExit { ref loan_id, amount_chronos, .. } => RpcActionSummary {
                            action_type: "PartialExit".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(loan_id.clone()),
                        },
                        Action::CreateLedgerEntry(ref le) => {
                            let atype = match le.entry_type {
                                chronx_core::transaction::LedgerEntryType::IdentityVerified => "IdentityVerified",
                                chronx_core::transaction::LedgerEntryType::IdentityRevoked => "IdentityRevoked",
                                _ => "LedgerEntry",
                            };
                            RpcActionSummary {
                                action_type: atype.to_string(),
                                to_address: None,
                                amount_chronos: None,
                                amount_kx: None,
                                lock_until: None,
                                memo: None,
                                email_hash: None,
                                lock_id: None,
                            }
                        },
                        Action::CreateDeposit(ref d) => RpcActionSummary {
                            action_type: "DepositCreate".to_string(),
                            to_address: Some("Savings".to_string()),
                            amount_chronos: Some(d.principal_chronos.to_string()),
                            amount_kx: Some((d.principal_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: Some(d.term_seconds as i64),
                            memo: None,
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::SettleDeposit(ref s) => RpcActionSummary {
                            action_type: "DepositSettle".to_string(),
                            to_address: Some("Available Balance".to_string()),
                            amount_chronos: Some(s.amount_chronos.to_string()),
                            amount_kx: Some((s.amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(hex::encode(s.deposit_id)),
                        },
                        Action::DepositDefault { ref deposit_id } => RpcActionSummary {
                            action_type: "DepositDefault".to_string(),
                            to_address: None,
                            amount_chronos: None,
                            amount_kx: None,
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: Some(hex::encode(deposit_id)),
                        },
                        Action::CreateSavingsDeposit { amount_chronos } => RpcActionSummary {
                            action_type: "SavingsDeposit".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: None,
                        },
                        Action::WithdrawSavings { amount_chronos } => RpcActionSummary {
                            action_type: "SavingsWithdraw".to_string(),
                            to_address: None,
                            amount_chronos: Some(amount_chronos.to_string()),
                            amount_kx: Some((*amount_chronos as u128 / CHRONOS_PER_KX).to_string()),
                            lock_until: None,
                            memo: None,
                            email_hash: None,
                            lock_id: None,
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

    // ── Invoice/Credit/Deposit/Conditional/Ledger RPC impls ──

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

    /// `chronx_getDepositsByWallet` — all deposits for a wallet (all statuses).
    async fn get_deposits_by_wallet(&self, wallet: String) -> RpcResult<Vec<RpcDepositRecord>> {
        let all = self.state.db.iter_all_deposits()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        // Get the wallet's pubkey bytes for matching against deposit records
        let wallet_id = chronx_core::types::AccountId::from_b58(&wallet)
            .map_err(|e| rpc_err(-32602, format!("Invalid wallet: {}", e)))?;
        let wallet_pubkey = self.state.db.get_account(&wallet_id)
            .ok().flatten()
            .map(|acc| match acc.auth_policy {
                chronx_core::account::AuthPolicy::SingleSig { ref public_key } => public_key.0.clone(),
                _ => vec![],
            })
            .unwrap_or_default();
        let filtered: Vec<_> = all.into_iter()
            .filter(|d| d.depositor_pubkey == wallet_pubkey || d.obligor_pubkey == wallet_pubkey)
            .map(|d| deposit_to_rpc(&d))
            .collect();
        Ok(filtered)
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
            last_anchor_hash: r.last_anchor_hash.map(hex::encode),
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

    // ── Wallet Group implementations ─────────────────

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

    /// `chronx_rejectInvoice` — submit a `RejectInvoice` transaction (must contain exactly
    /// one `Action::RejectInvoice` action). Returns the transaction ID.
    async fn reject_invoice(&self, tx_hex: String) -> RpcResult<String> {
        let tx_bytes =
            hex::decode(&tx_hex).map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;

        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| rpc_err(-32602, format!("invalid transaction encoding: {e}")))?;

        // Validate: must contain exactly one RejectInvoice action.
        let has_reject =
            tx.actions.len() == 1 && matches!(&tx.actions[0], Action::RejectInvoice { .. });
        if !has_reject {
            return Err(rpc_err(
                -32602,
                "rejectInvoice requires exactly one RejectInvoice action",
            ));
        }

        let tx_id = tx.tx_id.to_hex();

        if let Some(sender) = &self.state.tx_sender {
            sender
                .send(tx)
                .await
                .map_err(|_| rpc_err(-32603, "transaction queue full"))?;
        } else {
            warn!("RPC: rejectInvoice called but no tx pipeline configured");
            return Err(rpc_err(-32603, "node tx pipeline not connected"));
        }

        Ok(tx_id)
    }

    // ── Genesis 10a — Loan queries ──────────────────────────────────────

    /// `chronx_getLoan` — fetch a single loan by its loan_id hex.
    async fn get_loan(&self, loan_id_hex: String) -> RpcResult<Option<serde_json::Value>> {
        let bytes = hex::decode(&loan_id_hex)
            .map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(rpc_err(-32602, "loan_id must be 32 bytes (64 hex chars)"));
        }
        let mut loan_id = [0u8; 32];
        loan_id.copy_from_slice(&bytes);
        // All loans stored as JSON
        if let Ok(Some(raw)) = self.state.db.get_loan(&loan_id) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&raw) {
                return Ok(Some(val));
            }
        }
        Ok(None)
    }

    /// `chronx_getLoansByWallet` — all loans for a given wallet (as lender or borrower).
    async fn get_loans_by_wallet(&self, wallet_address: String) -> RpcResult<Vec<serde_json::Value>> {
        let mut loans: Vec<serde_json::Value> = Vec::new();
        for (key, val) in self.state.db.iter_loans() {
            if String::from_utf8_lossy(&key).contains(':') { continue; }
            if let Ok(loan) = serde_json::from_slice::<serde_json::Value>(&val) {
                let is_lender = loan.get("lender_wallet")
                    .and_then(|w| w.as_str()) == Some(&wallet_address);
                let is_borrower = loan.get("borrower_wallet")
                    .and_then(|w| w.as_str()) == Some(&wallet_address);
                if is_lender || is_borrower {
                    loans.push(loan);
                }
            }
        }
        Ok(loans)
    }

    /// `chronx_getLoanPaymentHistory` — return the payment stages for a loan.
    async fn get_loan_payment_history(&self, loan_id_hex: String) -> RpcResult<Vec<RpcLoanPaymentStage>> {
        let bytes = hex::decode(&loan_id_hex)
            .map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(rpc_err(-32602, "loan_id must be 32 bytes (64 hex chars)"));
        }
        let mut loan_id = [0u8; 32];
        loan_id.copy_from_slice(&bytes);
        let raw = self.state.db.get_loan(&loan_id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        match raw {
            Some(bytes) => {
                if let Ok(loan) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    // Extract stages from JSON loan
                    let stages = loan.get("stages").and_then(|s| s.as_array()).cloned().unwrap_or_default();
                    let rpc_stages: Vec<RpcLoanPaymentStage> = stages.iter().filter_map(|s| {
                        Some(RpcLoanPaymentStage {
                            stage_index: s.get("stage_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                            due_at: s.get("due_at").and_then(|v| v.as_u64()).unwrap_or(0),
                            amount_kx: s.get("amount_kx").and_then(|v| v.as_u64()).unwrap_or(0),
                            pay_as: s.get("pay_as").and_then(|v| v.as_str()).unwrap_or("KX").to_string(),
                            payment_type: s.get("payment_type").and_then(|v| v.as_str()).unwrap_or("principal_and_interest").to_string(),
                        })
                    }).collect();
                    Ok(rpc_stages)
                } else {
                    Err(rpc_err(-32603, "failed to parse loan data"))
                }
            }
            None => Err(rpc_err(-32602, format!("loan not found: {loan_id_hex}"))),
        }
    }

    /// `chronx_getLoanDefaultRecord` — return default record details for a loan.
    async fn get_loan_default_record(&self, loan_id_hex: String) -> RpcResult<Option<RpcLoanDefaultRecord>> {
        let bytes = hex::decode(&loan_id_hex)
            .map_err(|e| rpc_err(-32602, format!("invalid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(rpc_err(-32602, "loan_id must be 32 bytes (64 hex chars)"));
        }
        let mut loan_id = [0u8; 32];
        loan_id.copy_from_slice(&bytes);
        let record = self.state.db.get_loan_default(&loan_id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcLoanDefaultRecord {
            loan_id: hex::encode(r.loan_id),
            missed_stage_index: r.missed_stage_index,
            missed_amount_kx: r.missed_amount_kx,
            late_fees_accrued_kx: r.late_fees_accrued_kx,
            days_overdue: r.days_overdue,
            outstanding_balance_kx: r.outstanding_balance_kx,
            stages_remaining: r.stages_remaining,
            defaulted_at: r.defaulted_at,
            memo: r.memo,
        }))
    }

    /// `chronx_getOraclePrice` — return oracle price for a trading pair.
    async fn get_oracle_price_record(&self, pair: String) -> RpcResult<Option<RpcOraclePrice>> {
        let record = self.state.db.get_oracle_price(&pair)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcOraclePrice {
            pair: r.pair,
            spot_price_micro: r.spot_price_micro,
            seven_day_avg_micro: r.seven_day_avg_micro,
            last_updated: r.last_updated,
            source: r.source,
        }))
    }

    /// `chronx_getActiveLoanCount` — aggregate loan counts by status.
    async fn get_active_loan_count(&self) -> RpcResult<RpcLoanCounts> {
        let all_loans = self.state.db.get_all_loans()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let mut active: u64 = 0;
        let mut defaulted: u64 = 0;
        let mut completed: u64 = 0;
        let mut written_off: u64 = 0;
        let mut early_payoff: u64 = 0;
        let mut reinstated: u64 = 0;

        for loan in &all_loans {
            match loan.status {
                LoanStatus::Active => active += 1,
                LoanStatus::Defaulted { .. } => defaulted += 1,
                LoanStatus::Completed { .. } => completed += 1,
                LoanStatus::WrittenOff { .. } => written_off += 1,
                LoanStatus::EarlyPayoff { .. } => early_payoff += 1,
                LoanStatus::Reinstated { .. } => reinstated += 1,
                LoanStatus::AcceptedPendingRescission { .. } => active += 1,
            }
        }

        Ok(RpcLoanCounts {
            active,
            defaulted,
            completed,
            written_off,
            early_payoff,
            reinstated,
        })
    }


    // ── LenderMemo + Governance queries ─────────────────────

    /// `chronx_getLenderMemos` — all lender memos for a given loan_id (hex).
    async fn get_lender_memos(&self, loan_id_hex: String) -> RpcResult<Vec<serde_json::Value>> {
        let prefix = format!("{}:", loan_id_hex);
        let memos: Vec<serde_json::Value> = self.state.db.loan_memos.scan_prefix(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        Ok(memos)
    }

    /// `chronx_getGovernanceParams` — current governance parameters.
    async fn get_governance_params(&self) -> RpcResult<serde_json::Value> {
        let params_val = self.state.db.governance_params.get(b"current")
            .ok().flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_else(|| serde_json::json!({
                "min_loan_size_chronos": null,
                "approved_currencies": ["USD","EUR","BTC","ETH"],
                "deprecated_currencies": []
            }));
        Ok(params_val)
    }

    /// chronx_getEscrow -- fetch escrow account by ID.
    async fn get_escrow(&self, escrow_id_hex: String) -> RpcResult<Option<serde_json::Value>> {
        let key = hex::decode(&escrow_id_hex).unwrap_or_default();
        match self.state.db.escrow_accounts.get(&key) {
            Ok(Some(val)) => {
                let v: serde_json::Value = serde_json::from_slice(&val).unwrap_or(serde_json::Value::Null);
                Ok(Some(v))
            }
            _ => Ok(None),
        }
    }

    /// chronx_getEscrowHistory -- deposit history for an escrow.
    async fn get_escrow_history(&self, escrow_id_hex: String) -> RpcResult<Vec<serde_json::Value>> {
        let prefix = format!("{}:", escrow_id_hex);
        let history: Vec<serde_json::Value> = self.state.db.escrow_deposits
            .scan_prefix(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        Ok(history)
    }


    /// chronx_getLoanOffers -- pending offers for borrower.
    async fn get_loan_offers(&self, wallet_b58: String) -> RpcResult<Vec<serde_json::Value>> {
        let offers: Vec<serde_json::Value> = self.state.db.iter_loans()
            .filter(|(k, _)| !String::from_utf8_lossy(k).contains(':'))
            .filter_map(|(_, v)| serde_json::from_slice::<serde_json::Value>(&v).ok())
            .filter(|loan: &serde_json::Value| {
                loan.get("borrower_wallet").and_then(|w| w.as_str()) == Some(&wallet_b58)
                && loan.get("status").and_then(|s| s.as_str()) == Some("pending")
            })
            .collect();
        Ok(offers)
    }

    /// chronx_getLoansByStatus -- loans by status for wallet.
    async fn get_loans_by_status(&self, wallet_b58: String, status: String) -> RpcResult<Vec<serde_json::Value>> {
        let loans: Vec<serde_json::Value> = self.state.db.iter_loans()
            .filter(|(k, _)| !String::from_utf8_lossy(k).contains(':'))
            .filter_map(|(_, v)| serde_json::from_slice::<serde_json::Value>(&v).ok())
            .filter(|loan: &serde_json::Value| {
                let is_party = loan.get("lender_wallet").and_then(|w| w.as_str()) == Some(&wallet_b58)
                    || loan.get("borrower_wallet").and_then(|w| w.as_str()) == Some(&wallet_b58);
                let loan_status = loan.get("status").and_then(|s| s.as_str()).unwrap_or("pending");
                is_party && loan_status == status
            })
            .collect();
        Ok(loans)
    }

    
    /// `chronx_getLoanEscrowBalance` -- escrow balance for a wallet during rescission.
    async fn get_loan_escrow_balance(&self, wallet_b58: String) -> RpcResult<serde_json::Value> {
        let escrows = self.state.db.get_loan_escrows_by_wallet(&wallet_b58)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let mut total_locked: u128 = 0;
        let mut loans = Vec::new();
        for (loan_id_hex, amount, expires_at) in &escrows {
            total_locked += amount;
            loans.push(serde_json::json!({
                "loan_id": loan_id_hex,
                "amount_chronos": amount.to_string(),
                "amount_kx": amount / 1_000_000,
                "expires_at": expires_at,
            }));
        }

        Ok(serde_json::json!({
            "wallet": wallet_b58,
            "total_locked_chronos": total_locked.to_string(),
            "total_locked_kx": total_locked / 1_000_000,
            "loan_count": escrows.len(),
            "loans": loans,
        }))
    }

    /// chronx_getMicroLoan -- fetch micro-loan by loan_id hex.
    /// `chronx_getSavingsBalance` -- savings account balance and yield info.
    async fn get_savings_balance(&self, wallet_b58: String) -> RpcResult<serde_json::Value> {
        use chronx_core::types::AccountId;
        let account_id = AccountId::from_b58(&wallet_b58)
            .map_err(|e| rpc_err(-32602, format!("Invalid wallet: {}", e)))?;
        let account = self.state.db.get_account(&account_id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        match account {
            Some(acc) => {
                let savings_kx = acc.savings_balance / 1_000_000;
                let annual_rate = if acc.savings_invested { 2.1 } else { 0.0 };
                let daily_yield = (acc.savings_balance as f64) * (annual_rate / 100.0 / 365.0);

                Ok(serde_json::json!({
                    "wallet": wallet_b58,
                    "savings_chronos": acc.savings_balance.to_string(),
                    "savings_kx": savings_kx,
                    "invested": acc.savings_invested,
                    "withdrawal_pending": acc.savings_withdrawal_pending,
                    "annual_rate_pct": annual_rate,
                    "daily_yield_chronos": (daily_yield as u64).to_string(),
                    "daily_yield_kx": daily_yield / 1_000_000.0,
                }))
            }
            None => Ok(serde_json::json!({
                "wallet": wallet_b58,
                "savings_chronos": "0",
                "savings_kx": 0,
                "invested": false,
                "withdrawal_pending": false,
                "annual_rate_pct": 0.0,
                "daily_yield_chronos": "0",
                "daily_yield_kx": 0.0,
            }))
        }
    }


    async fn get_micro_loan(&self, loan_id_hex: String) -> RpcResult<Option<serde_json::Value>> {
        let key = hex::decode(&loan_id_hex).unwrap_or_default();
        match self.state.db.micro_loans.get(&key) {
            Ok(Some(val)) => {
                let v: serde_json::Value = serde_json::from_slice(&val).unwrap_or(serde_json::Value::Null);
                Ok(Some(v))
            }
            _ => Ok(None),
        }
    }

    /// chronx_getChannelInfo -- stub for payment channel info.
    async fn get_channel_info(&self, channel_id_hex: String) -> RpcResult<serde_json::Value> {
        // Channels are scaffolding only — no persistent storage yet.
        // Return a placeholder response.
        Ok(serde_json::json!({
            "channel_id": channel_id_hex,
            "status": "not_found",
            "message": "Payment channels are Phase 2 — scaffolding only in this build."
        }))
    }



    // ── TYPE A — Authority Grant queries ────────────────────────────────────

    async fn get_authority_grants(&self, wallet_b58: String) -> RpcResult<serde_json::Value> {
        let db = &self.state.db;
        let mut grants = Vec::new();
        for item in db.iter_authority_grants() {
            if let Ok(grant) = serde_json::from_slice::<serde_json::Value>(&item.1) {
                let grantor = grant.get("grantor_wallet").and_then(|v| v.as_str()).unwrap_or("");
                let grantee = grant.get("grantee_wallet").and_then(|v| v.as_str()).unwrap_or("");
                if grantor == wallet_b58 || grantee == wallet_b58 {
                    grants.push(grant);
                }
            }
        }
        Ok(serde_json::json!({
            "wallet": wallet_b58,
            "grants": grants,
            "count": grants.len()
        }))
    }

    async fn get_kxgc_capacity(&self) -> RpcResult<serde_json::Value> {
        let db = &self.state.db;
        let kxgc_b58 = db.get_meta("kxgc_bond_wallet")
            .ok().flatten()
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        let kxgc_balance_kx: u64 = if !kxgc_b58.is_empty() {
            if let Ok(id) = chronx_core::types::AccountId::from_b58(&kxgc_b58) {
                if let Ok(Some(acc)) = db.get_account(&id) {
                    (acc.balance / 1_000_000) as u64
                } else { 0 }
            } else { 0 }
        } else { 0 };
        let mut total_obligations_kx: u64 = 0;
        let mut active_grants: Vec<serde_json::Value> = Vec::new();
        for item in db.iter_authority_grants() {
            if let Ok(grant) = serde_json::from_slice::<serde_json::Value>(&item.1) {
                let status = grant.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if status == "Active" || status == "PendingRevocation" {
                    let max_kx = grant.get("max_obligations_kx").and_then(|v| v.as_u64()).unwrap_or(0);
                    total_obligations_kx = total_obligations_kx.saturating_add(max_kx);
                    active_grants.push(grant);
                }
            }
        }
        let available_kx = kxgc_balance_kx.saturating_sub(total_obligations_kx);
        let reserve_ratio: f64 = if total_obligations_kx > 0 {
            kxgc_balance_kx as f64 / total_obligations_kx as f64
        } else if kxgc_balance_kx > 0 { -1.0 } else { 0.0 };
        let warning_level = if total_obligations_kx == 0 || !(0.0..1.0).contains(&reserve_ratio) {
            "GREEN"
        } else if reserve_ratio >= 0.5 { "YELLOW" } else { "RED" };
        Ok(serde_json::json!({
            "kxgc_wallet": kxgc_b58,
            "kxgc_balance_kx": kxgc_balance_kx,
            "total_granted_obligations_kx": total_obligations_kx,
            "available_capacity_kx": available_kx,
            "reserve_ratio": reserve_ratio,
            "warning_level": warning_level,
            "active_grant_count": active_grants.len(),
            "active_grants": active_grants,
        }))
    }
    // -- Genesis Zero -- Obligation Transfer RPC implementations --------------

    async fn get_obligation_owner(&self, obligation_id: String) -> RpcResult<serde_json::Value> {
        let id_bytes = hex_to_32(&obligation_id)?;
        let db = &self.state.db;
        if let Ok(Some(existing)) = db.get_loan(&id_bytes) {
            if let Ok(loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                let current_owner = loan_val.get("current_owner")
                    .or_else(|| loan_val.get("lender_wallet"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(serde_json::json!({
                    "obligation_id": obligation_id,
                    "current_owner": current_owner
                }))
            } else {
                Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Deserialization error", None::<String>))
            }
        } else {
            Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Obligation not found", None::<String>))
        }
    }

    async fn get_transfer_history(&self, obligation_id: String) -> RpcResult<serde_json::Value> {
        let id_bytes = hex_to_32(&obligation_id)?;
        let db = &self.state.db;
        if let Ok(Some(existing)) = db.get_loan(&id_bytes) {
            if let Ok(loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                let history = loan_val.get("transfer_history")
                    .cloned()
                    .unwrap_or(serde_json::json!([]));
                Ok(serde_json::json!({
                    "obligation_id": obligation_id,
                    "transfer_history": history
                }))
            } else {
                Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Deserialization error", None::<String>))
            }
        } else {
            Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Obligation not found", None::<String>))
        }
    }

    async fn get_obligations_by_owner(&self, wallet: String) -> RpcResult<serde_json::Value> {
        let db = &self.state.db;
        let mut obligation_ids: Vec<String> = Vec::new();
        for item in db.iter_loans() {
            if let Ok(loan_val) = serde_json::from_slice::<serde_json::Value>(&item.1) {
                let current_owner = loan_val.get("current_owner")
                    .or_else(|| loan_val.get("lender_wallet"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if current_owner == wallet {
                    obligation_ids.push(hex::encode(&item.0));
                }
            }
        }
        Ok(serde_json::json!({
            "wallet": wallet,
            "obligation_ids": obligation_ids,
            "count": obligation_ids.len()
        }))
    }

    async fn get_tranches(&self, parent_obligation_id: String) -> RpcResult<serde_json::Value> {
        let id_bytes = hex_to_32(&parent_obligation_id)?;
        let db = &self.state.db;
        if let Ok(Some(existing)) = db.get_loan(&id_bytes) {
            if let Ok(loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                let tranche_count = loan_val.get("tranche_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let tranched = loan_val.get("tranched")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                Ok(serde_json::json!({
                    "parent_obligation_id": parent_obligation_id,
                    "tranched": tranched,
                    "tranche_count": tranche_count
                }))
            } else {
                Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Deserialization error", None::<String>))
            }
        } else {
            Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Obligation not found", None::<String>))
        }
    }

    async fn get_yield_inputs(&self, obligation_id: String) -> RpcResult<serde_json::Value> {
        let id_bytes = hex_to_32(&obligation_id)?;
        let db = &self.state.db;
        if let Ok(Some(existing)) = db.get_loan(&id_bytes) {
            if let Ok(loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                let visibility = loan_val.get("terms_visibility")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Private");
                let current_owner = loan_val.get("current_owner")
                    .or_else(|| loan_val.get("lender_wallet"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let retirement_status = loan_val.get("retirement_status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Active")
                    .to_string();
                let retired_fraction = loan_val.get("retired_fraction")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let history_count = loan_val.get("transfer_history")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len() as u32)
                    .unwrap_or(0);

                if visibility == "Public" {
                    // Full details
                    let interest_rate = loan_val.get("interest_rate").cloned();
                    let term_seconds = loan_val.get("term_seconds")
                        .and_then(|v| v.as_u64());
                    let payment_schedule = loan_val.get("payment_schedule")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    Ok(serde_json::json!({
                        "obligation_id": obligation_id,
                        "terms_visibility": visibility,
                        "interest_rate": interest_rate,
                        "term_seconds": term_seconds,
                        "payment_schedule": payment_schedule,
                        "current_owner": current_owner,
                        "retirement_status": retirement_status,
                        "retired_fraction": retired_fraction,
                        "transfer_history_count": history_count
                    }))
                } else {
                    // Private: only non-sensitive fields
                    Ok(serde_json::json!({
                        "obligation_id": obligation_id,
                        "terms_visibility": "Private",
                        "interest_rate": null,
                        "term_seconds": null,
                        "payment_schedule": null,
                        "current_owner": current_owner,
                        "retirement_status": retirement_status,
                        "retired_fraction": retired_fraction,
                        "transfer_history_count": history_count
                    }))
                }
            } else {
                Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Deserialization error", None::<String>))
            }
        } else {
            Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Obligation not found", None::<String>))
        }
    }

    async fn get_obligation_status(&self, obligation_id: String) -> RpcResult<serde_json::Value> {
        let id_bytes = hex_to_32(&obligation_id)?;
        let db = &self.state.db;
        if let Ok(Some(existing)) = db.get_loan(&id_bytes) {
            if let Ok(loan_val) = serde_json::from_slice::<serde_json::Value>(&existing) {
                let retirement_status = loan_val.get("retirement_status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Active")
                    .to_string();
                let retired_fraction = loan_val.get("retired_fraction")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let tranche_count = loan_val.get("tranche_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let transferable = loan_val.get("transferable")
                    .cloned()
                    .unwrap_or(serde_json::json!("Free"));
                let current_owner = loan_val.get("current_owner")
                    .or_else(|| loan_val.get("lender_wallet"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(serde_json::json!({
                    "obligation_id": obligation_id,
                    "status": retirement_status,
                    "retired_fraction": retired_fraction,
                    "tranche_count": tranche_count,
                    "active_tranches": tranche_count,
                    "transferable": transferable,
                    "current_owner": current_owner
                }))
            } else {
                Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Deserialization error", None::<String>))
            }
        } else {
            Err(jsonrpsee::types::ErrorObjectOwned::owned(-32603, "Obligation not found", None::<String>))
        }
    }


    // -- Escalation/failure/hedge scaffold RPC implementations ----------------

    async fn get_escalation_status(&self, conditional_id: String) -> RpcResult<serde_json::Value> {
        let db = &self.state.db;
        match db.get_escalation(&conditional_id) {
            Ok(Some(data)) => {
                let val: serde_json::Value = serde_json::from_slice(&data)
                    .unwrap_or(serde_json::json!(null));
                Ok(serde_json::json!({
                    "conditional_id": conditional_id,
                    "escalation": val
                }))
            }
            _ => Ok(serde_json::json!({
                "conditional_id": conditional_id,
                "escalation": null
            }))
        }
    }

    async fn get_attestor_failures(&self) -> RpcResult<serde_json::Value> {
        let db = &self.state.db;
        let mut failures = Vec::new();
        for (key, val) in db.iter_attestor_failures() {
            let id = String::from_utf8_lossy(&key).to_string();
            let record: serde_json::Value = serde_json::from_slice(&val)
                .unwrap_or(serde_json::json!(null));
            failures.push(serde_json::json!({
                "group_id": id,
                "record": record
            }));
        }
        Ok(serde_json::json!({
            "failures": failures,
            "count": failures.len()
        }))
    }

    async fn get_affected_policies(&self, group_id: String) -> RpcResult<serde_json::Value> {
        let db = &self.state.db;
        let mut affected: Vec<serde_json::Value> = Vec::new();

        // Check escalations tree for entries referencing this group
        if let Ok(Some(data)) = db.get_attestor_failure(&group_id) {
            if let Ok(failure) = serde_json::from_slice::<serde_json::Value>(&data) {
                affected.push(serde_json::json!({
                    "type": "attestor_failure",
                    "record": failure
                }));
            }
        }

        // Check escalations tree for conditionals escalated due to this group
        if let Ok(Some(data)) = db.get_escalation(&group_id) {
            if let Ok(esc) = serde_json::from_slice::<serde_json::Value>(&data) {
                affected.push(serde_json::json!({
                    "type": "escalation",
                    "record": esc
                }));
            }
        }

        Ok(serde_json::json!({
            "group_id": group_id,
            "affected_records": affected,
            "count": affected.len()
        }))
    }

    async fn get_hedge_instruments(&self, pool_id: String) -> RpcResult<serde_json::Value> {
        // Scaffold: return hedge instruments linked to pool
        let db = &self.state.db;
        let mut instruments = Vec::new();
        for (_key, val) in db.iter_hedge_instruments() {
            let record: serde_json::Value = serde_json::from_slice(&val)
                .unwrap_or(serde_json::json!(null));
            if let Some(pid) = record.get("pool_id").and_then(|v| v.as_str()) {
                if pid == pool_id {
                    instruments.push(record);
                }
            }
        }
        Ok(serde_json::json!({
            "pool_id": pool_id,
            "instruments": instruments,
            "count": instruments.len()
        }))
    }

    async fn get_linked_spring_status(&self, instrument_id: String) -> RpcResult<serde_json::Value> {
        // Scaffold: return status of linked instrument
        Ok(serde_json::json!({
            "instrument_id": instrument_id,
            "fired": false,
            "status": "scaffold",
            "note": "Full LinkedSpring engine logic pending"
        }))
    }

    async fn get_pool_health_score(&self, pool_id: String) -> RpcResult<serde_json::Value> {
        let db = &self.state.db;
        match db.get_pool_health_score(&pool_id) {
            Ok(Some(data)) => {
                let val: serde_json::Value = serde_json::from_slice(&data)
                    .unwrap_or(serde_json::json!(null));
                Ok(serde_json::json!({
                    "pool_id": pool_id,
                    "health_score": val
                }))
            }
            _ => Ok(serde_json::json!({
                "pool_id": pool_id,
                "health_score": null,
                "note": "Not yet populated by MISAI"
            }))
        }
    }

    async fn get_oracle_trigger_status(&self, lock_id: String) -> RpcResult<serde_json::Value> {
        let id_bytes = hex_to_32(&lock_id)?;
        let db = &self.state.db;
        match db.get_conditional(&id_bytes) {
            Ok(Some(cond)) => {
                let cond_type = cond.condition_type.as_deref().unwrap_or("SingleAttestation");
                if cond_type != "OracleTrigger" {
                    return Ok(serde_json::json!({
                        "lock_id": lock_id,
                        "error": "Not an OracleTrigger conditional"
                    }));
                }
                let status_str = match cond.status {
                    chronx_state::db::ConditionalStatus::Pending => "Pending",
                    chronx_state::db::ConditionalStatus::Released => "Triggered",
                    chronx_state::db::ConditionalStatus::PartiallyReleased => "PartiallyTriggered",
                    chronx_state::db::ConditionalStatus::Voided => "Expired",
                    chronx_state::db::ConditionalStatus::Returned => "Returned",
                    chronx_state::db::ConditionalStatus::Escrowed => "Escrowed",
                };
                let creation_price = cond.oracle_creation_price.unwrap_or(0.0);
                let threshold = cond.oracle_trigger_threshold.unwrap_or(0.0);
                let trigger_price = creation_price * threshold;
                let direction = cond.oracle_trigger_direction.as_deref().unwrap_or("Below");
                let triggered = status_str == "Triggered";

                Ok(serde_json::json!({
                    "lock_id": lock_id,
                    "status": status_str,
                    "condition_type": "OracleTrigger",
                    "oracle_pair": cond.oracle_pair,
                    "creation_price": creation_price,
                    "trigger_threshold": threshold,
                    "trigger_price": trigger_price,
                    "trigger_direction": direction,
                    "triggered": triggered,
                    "valid_until": cond.valid_until,
                    "success_payment_wallet": cond.success_payment_wallet,
                    "success_payment_chronos": cond.success_payment_chronos
                }))
            }
            _ => Ok(serde_json::json!({
                "lock_id": lock_id,
                "error": "Conditional not found"
            }))
        }
    }

    async fn get_pending_draw_requests(&self) -> RpcResult<serde_json::Value> {
        let db = &self.state.db;
        match db.iter_pending_drawrequests() {
            Ok(items) => {
                let requests: Vec<serde_json::Value> = items.into_iter().map(|(key, val)| {
                    serde_json::json!({
                        "id": key,
                        "bond_wallet": val.get("bond_wallet").and_then(|v| v.as_str()).unwrap_or(""),
                        "destination_wallet": val.get("destination_wallet").and_then(|v| v.as_str()).unwrap_or(""),
                        "amount_chronos": val.get("amount_chronos").and_then(|v| v.as_u64()).unwrap_or(0),
                        "reason": val.get("reason").and_then(|v| v.as_str()).unwrap_or(""),
                        "lock_until": val.get("lock_until").and_then(|v| v.as_u64()).unwrap_or(0),
                        "auto_generated": val.get("auto_generated").and_then(|v| v.as_bool()).unwrap_or(false),
                        "queued_at": val.get("queued_at").and_then(|v| v.as_u64()).unwrap_or(0)
                    })
                }).collect();
                Ok(serde_json::json!({
                    "requests": requests,
                    "count": requests.len()
                }))
            }
            Err(_) => Ok(serde_json::json!({
                "requests": [],
                "count": 0
            }))
        }
    }

    async fn get_partial_release_history(&self, lock_id: String) -> RpcResult<serde_json::Value> {
        let id_bytes = hex_to_32(&lock_id)?;
        let db = &self.state.db;
        match db.get_partial_release_history(&id_bytes) {
            Ok(releases) => {
                Ok(serde_json::json!({
                    "lock_id": lock_id,
                    "releases": releases,
                    "count": releases.len()
                }))
            }
            Err(_) => Ok(serde_json::json!({
                "lock_id": lock_id,
                "releases": [],
                "count": 0
            }))
        }
    }

    async fn get_friendly_loan(&self, loan_id: String) -> RpcResult<Option<serde_json::Value>> {
        let id = hex_to_32(&loan_id)?;
        match self.state.db.get_friendly_loan(&id) {
            Ok(Some(r)) => Ok(Some(serde_json::to_value(&r).unwrap_or_default())),
            Ok(None) => Ok(None),
            Err(e) => Err(jsonrpsee::types::ErrorObjectOwned::owned(-32000, e.to_string(), None::<String>)),
        }
    }

    async fn get_friendly_loans_by_wallet(&self, wallet: String) -> RpcResult<Vec<serde_json::Value>> {
        match self.state.db.iter_friendly_loans_by_wallet(&wallet) {
            Ok(records) => Ok(records.iter().map(|r| serde_json::to_value(r).unwrap_or_default()).collect()),
            Err(e) => Err(jsonrpsee::types::ErrorObjectOwned::owned(-32000, e.to_string(), None::<String>)),
        }
    }

    async fn get_active_friendly_loans(&self, wallet: String) -> RpcResult<Vec<serde_json::Value>> {
        match self.state.db.iter_friendly_loans_by_wallet(&wallet) {
            Ok(records) => Ok(records.iter()
                .filter(|r| r.status == "Active")
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect()),
            Err(e) => Err(jsonrpsee::types::ErrorObjectOwned::owned(-32000, e.to_string(), None::<String>)),
        }
    }

}


// ── RPC conversion helpers ──────────────────────────────────────

fn invoice_to_rpc(r: &chronx_state::db::InvoiceRecord) -> RpcInvoiceRecord {
    let status = match r.status {
        InvoiceStatus::Open => "Open",
        InvoiceStatus::Fulfilled => "Fulfilled",
        InvoiceStatus::Lapsed => "Lapsed",
        InvoiceStatus::Cancelled => "Cancelled",
        InvoiceStatus::Rejected => "Rejected",
    };
    RpcInvoiceRecord {
        invoice_id: hex::encode(r.invoice_id),
        issuer_pubkey: hex::encode(&r.issuer_pubkey),
        payer_pubkey: r.payer_pubkey.as_ref().map(hex::encode),
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
        principal_chronos: r.principal_chronos,
        principal_kx: r.principal_chronos as f64 / CHRONOS_PER_KX as f64,
        rate_basis_points: r.rate_basis_points,
        term_seconds: r.term_seconds,
        compounding: r.compounding.clone(),
        maturity_timestamp: r.maturity_timestamp,
        total_due_chronos: r.total_due_chronos,
        total_due_kx: r.total_due_chronos as f64 / CHRONOS_PER_KX as f64,
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
        ConditionalStatus::PartiallyReleased => "PartiallyReleased",
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
        promise_id: r.promise_id.map(hex::encode),
        entry_type: r.entry_type.clone(),
        content_hash: hex::encode(r.content_hash),
        content_summary: String::from_utf8_lossy(&r.content_summary).to_string(),
        timestamp: r.timestamp,
    }
}


// ── Genesis 10a — Loan RPC conversion helpers ───────────────────────────────





fn hex_to_32(hex_str: &str) -> RpcResult<[u8; 32]> {
    let decoded = hex::decode(hex_str)
        .map_err(|_| jsonrpsee::types::ErrorObjectOwned::owned(-32602, "Invalid hex", None::<String>))?;
    if decoded.len() != 32 {
        return Err(jsonrpsee::types::ErrorObjectOwned::owned(-32602, "Expected 32 bytes", None::<String>));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}
