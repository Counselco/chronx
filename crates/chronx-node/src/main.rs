//! chronx-node — the ChronX full-node binary.
//!
//! Startup sequence:
//!   1. Open (or initialise) the state database
//!   2. Apply genesis if the DB is fresh
//!   3. Start the P2P network (libp2p GossipSub + Kademlia)
//!   4. Start the JSON-RPC 2.0 server
//!   5. Run the main loop: validate inbound txs → apply → broadcast

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tracing::{info, warn};

/// Current node software version. Compared against https://chronx.io/version.json at startup.
const NODE_VERSION: &str = "9.2.0";

use chronx_consensus::DifficultyConfig;
use chronx_core::constants::POW_INITIAL_DIFFICULTY;
use chronx_crypto::KeyPair;
use chronx_genesis::{apply_genesis, GenesisParams};
use chronx_p2p::{P2pConfig, P2pMessage, P2pNetwork};
use chronx_rpc::server::RpcServerState;
use chronx_rpc::RpcServer;
use chronx_state::{StateDb, StateEngine};

#[derive(Parser, Debug)]
#[command(
    name = "chronx-node",
    version,
    about = "ChronX full node — the ledger for long-horizon human promises"
)]
struct Args {
    /// Directory for the persistent state database.
    #[arg(long, default_value = "~/.chronx/data")]
    data_dir: PathBuf,

    /// P2P listen address.
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/7777")]
    p2p_listen: String,

    /// JSON-RPC listen address.
    #[arg(long, default_value = "127.0.0.1:8545")]
    rpc_addr: SocketAddr,

    /// Bootstrap peer multiaddresses (comma-separated).
    #[arg(long, value_delimiter = ',')]
    bootstrap: Vec<String>,

    /// Path to genesis params JSON (only required on first run).
    #[arg(long)]
    genesis_params: Option<PathBuf>,

    /// PoW difficulty override.
    #[arg(long, default_value_t = POW_INITIAL_DIFFICULTY)]
    pow_difficulty: u8,

    /// Path to a persistent P2P identity key file (protobuf-encoded Ed25519).
    /// If the file does not exist, a new identity is generated and saved.
    /// If omitted, a random identity is used each run.
    #[arg(long)]
    identity_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,chronx=debug".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    info!(version = NODE_VERSION, "ChronX node starting");

    // ── Version check against chronx.io/version.json ─────────────────────────
    check_node_version().await;

    // ── State database ────────────────────────────────────────────────────────
    let data_dir = expand_tilde(&args.data_dir);
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    let db = Arc::new(StateDb::open(&data_dir).context("opening state database")?);

    // ── Genesis if fresh ──────────────────────────────────────────────────────
    if db.get_tips().map(|t| t.is_empty()).unwrap_or(true) {
        info!("fresh database — applying genesis");
        let params = load_or_generate_genesis_params(args.genesis_params.as_deref())?;
        apply_genesis(&db, &params).context("applying genesis")?;
    } else {
        info!("existing database found — skipping genesis");
    }

    // ── Store MISAI X25519 public key if provided and not yet stored ─────────
    if let Ok(pubkey_hex) = std::env::var("MISAI_X25519_PUBKEY") {
        if !pubkey_hex.is_empty() {
            match db.get_meta("misai_x25519_pubkey") {
                Ok(None) => {
                    db.put_meta("misai_x25519_pubkey", pubkey_hex.as_bytes())
                        .expect("failed to store misai_x25519_pubkey");
                    info!(pubkey = %pubkey_hex, "stored MISAI X25519 public key in metadata");
                }
                Ok(Some(existing)) => {
                    let existing_hex = String::from_utf8_lossy(&existing);
                    if existing_hex != pubkey_hex {
                        db.put_meta("misai_x25519_pubkey", pubkey_hex.as_bytes())
                            .expect("failed to update misai_x25519_pubkey");
                        info!(pubkey = %pubkey_hex, "updated MISAI X25519 public key in metadata");
                    }
                }
                Err(e) => warn!(error = %e, "failed to check misai_x25519_pubkey"),
            }
        }
    }

    // ── Store MISAI executor wallet address if provided ─────────────────────
    if let Ok(executor_wallet) = std::env::var("MISAI_EXECUTOR_WALLET") {
        if !executor_wallet.is_empty() {
            match db.get_meta("misai_executor_wallet") {
                Ok(None) => {
                    db.put_meta("misai_executor_wallet", executor_wallet.as_bytes())
                        .expect("failed to store misai_executor_wallet");
                    info!(wallet = %executor_wallet, "stored MISAI executor wallet in metadata");
                }
                Ok(Some(existing)) => {
                    let existing_str = String::from_utf8_lossy(&existing);
                    if existing_str != executor_wallet {
                        db.put_meta("misai_executor_wallet", executor_wallet.as_bytes())
                            .expect("failed to update misai_executor_wallet");
                        info!(wallet = %executor_wallet, "updated MISAI executor wallet in metadata");
                    }
                }
                Err(e) => warn!(error = %e, "failed to check misai_executor_wallet"),
            }
        }
    }

    // ── Store MISAI executor pubkey if provided ───────────────────────────────
    if let Ok(executor_pubkey) = std::env::var("MISAI_EXECUTOR_PUBKEY") {
        if !executor_pubkey.is_empty() {
            match db.get_meta("misai_executor_pubkey") {
                Ok(None) => {
                    db.put_meta("misai_executor_pubkey", executor_pubkey.as_bytes())
                        .expect("failed to store misai_executor_pubkey");
                    info!(pubkey_len = executor_pubkey.len(), "stored MISAI executor pubkey in metadata");
                }
                Ok(Some(existing)) => {
                    let existing_str = String::from_utf8_lossy(&existing);
                    if existing_str != executor_pubkey {
                        db.put_meta("misai_executor_pubkey", executor_pubkey.as_bytes())
                            .expect("failed to update misai_executor_pubkey");
                        info!(pubkey_len = executor_pubkey.len(), "updated MISAI executor pubkey in metadata");
                    }
                }
                Err(e) => warn!(error = %e, "failed to check misai_executor_pubkey"),
            }
        }
    }

    // ── State engine ──────────────────────────────────────────────────────────
    // Share the same DB handle — sled uses an Arc internally so this is safe.
    let engine = Arc::new(StateEngine::new(Arc::clone(&db), args.pow_difficulty));

    // ── Migrate account savings fields (bincode re-serialize) ────────────
    match engine.migrate_account_savings_fields() {
        Ok(0) => {},
        Ok(n) => tracing::info!("[STARTUP] Migrated {n} accounts with savings fields"),
        Err(e) => tracing::warn!("[STARTUP] Account savings migration error: {e}"),
    }

    // ── One-time escrow migration for pre-fix rescission loans ────────────
    match engine.migrate_rescission_escrows() {
        Ok(0) => {},
        Ok(n) => tracing::info!("[STARTUP] Migrated {n} rescission loans to escrow"),
        Err(e) => tracing::warn!("[STARTUP] Escrow migration error: {e}"),
    }

    // ── One-time fix: credit borrowers for waived loans that never transferred KX
    match engine.fix_waived_loan_transfers() {
        Ok(0) => {},
        Ok(n) => tracing::info!("[STARTUP] Fixed {n} waived loans — borrowers credited"),
        Err(e) => tracing::warn!("[STARTUP] Waive fix error: {e}"),
    }

    // ── Inbound transaction queue ─────────────────────────────────────────────
    let (tx_sender, mut tx_receiver) =
        tokio::sync::mpsc::channel::<chronx_core::transaction::Transaction>(512);

    // ── P2P network ───────────────────────────────────────────────────────────
    let p2p_config = P2pConfig {
        listen_addr: args.p2p_listen.clone(),
        bootstrap_peers: args.bootstrap.clone(),
        protocol_version: "/chronx/1.0.0".into(),
        vertex_topic: "chronx-vertices".into(),
        identity_file: args.identity_file.clone(),
    };
    let (p2p_network, mut p2p_handle) =
        P2pNetwork::new(&p2p_config).map_err(|e| anyhow::anyhow!("building P2P network: {e}"))?;
    info!(peer_id = %p2p_handle.local_peer_id, "P2P identity");

    // Full multiaddr for peer discovery (used by chronx_getNetworkInfo).
    let peer_multiaddr = format!(
        "{}/p2p/{}",
        p2p_config.listen_addr, p2p_handle.local_peer_id
    );

    let outbound_tx = p2p_handle.outbound_tx.clone();

    // Pipe gossip-received messages into the tx queue.
    let tx_sender_for_p2p = tx_sender.clone();
    tokio::spawn(async move {
        while let Some(msg) = p2p_handle.inbound_rx.recv().await {
            if let P2pMessage::NewVertex { payload } = msg {
                match bincode::deserialize(&payload) {
                    Ok(tx) => {
                        let _ = tx_sender_for_p2p.send(tx).await;
                    }
                    Err(e) => warn!(error = %e, "failed to decode inbound vertex"),
                }
            }
        }
    });

    tokio::spawn(async move { p2p_network.run().await as () });

    // ── RPC server ────────────────────────────────────────────────────────────
    let rpc_state = Arc::new(RpcServerState {
        db: Arc::clone(&db),
        pow_difficulty: args.pow_difficulty,
        tx_sender: Some(tx_sender),
        peer_multiaddr: Some(peer_multiaddr),
        peer_count: p2p_handle.peer_count.clone(),
    });
    let _rpc_handle = RpcServer::new(rpc_state)
        .start(args.rpc_addr)
        .await
        .context("starting RPC server")?;


    // ── Read sweep intervals from genesis-params.json ─────────────────────────
    let sweep_intervals = {
        let gp_content = args.genesis_params.as_ref().map(|p| std::fs::read_to_string(p).unwrap_or_default())
            .unwrap_or_default();
        let gp: serde_json::Value = serde_json::from_str(&gp_content)
            .unwrap_or(serde_json::Value::Null);
        (
            gp.get("sweep_email_lock_interval_seconds").and_then(|v| v.as_u64()).unwrap_or(300),
            gp.get("sweep_matured_timelock_interval_seconds").and_then(|v| v.as_u64()).unwrap_or(60),
            gp.get("sweep_executor_interval_seconds").and_then(|v| v.as_u64()).unwrap_or(60),
            gp.get("sweep_humanity_stake_interval_seconds").and_then(|v| v.as_u64()).unwrap_or(86400),
            gp.get("sweep_guardian_transition_interval_seconds").and_then(|v| v.as_u64()).unwrap_or(3600),
            gp.get("sweep_promise_chain_interval_seconds").and_then(|v| v.as_u64()).unwrap_or(86400),
            gp.get("sweep_loan_interval_seconds").and_then(|v| v.as_u64()).unwrap_or(3600),
            gp.get("loan_min_settlement_chronos").and_then(|v| v.as_u64()).unwrap_or(1000),
        )
    };
    let (sweep_email_secs, sweep_timelock_secs, sweep_executor_secs,
         sweep_humanity_secs, sweep_guardian_secs, sweep_promise_secs,
         sweep_loan_secs, loan_min_settlement) = sweep_intervals;
    info!(email=sweep_email_secs, timelock=sweep_timelock_secs, executor=sweep_executor_secs,
          humanity=sweep_humanity_secs, guardian=sweep_guardian_secs, promise=sweep_promise_secs,
          loan=sweep_loan_secs, "sweep intervals loaded from genesis-params");

    // ── Background sweep: revert expired email locks every 5 minutes ──────────
    {
        let sweep_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_email_secs));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                match sweep_engine.sweep_expired_email_locks(chrono::Utc::now().timestamp()) {
                    Ok(0) => {} // nothing to revert — silent
                    Ok(n) => info!(count = n, "sweep: reverted expired email locks"),
                    Err(e) => warn!(error = %e, "sweep: failed to process expired locks"),
                }

                // ── Day 91 activation trigger sweep ──────────────────────────
                match sweep_engine.sweep_genesis7_triggers(chrono::Utc::now().timestamp()) {
                    Ok(0) => {}
                    Ok(n) => info!(count = n, "sweep: activation triggers fired"),
                    Err(e) => warn!(error = %e, "sweep: activation trigger sweep failed"),
                }

                // ── 100-year humanity stake expiry sweep ─────────────────────────
                // Read the Humanity Stake Pool address from genesis metadata.
                if let Ok(Some(pool_bytes)) = sweep_engine.db.get_meta("genesis_7_humanity_stake_pool") {
                    let pool_address = String::from_utf8_lossy(&pool_bytes).to_string();
                    match sweep_engine.sweep_genesis7_expiry(chrono::Utc::now().timestamp(), &pool_address) {
                        Ok(0) => {}
                        Ok(n) => info!(count = n, "sweep: humanity stake expiry transfers"),
                        Err(e) => warn!(error = %e, "sweep: humanity stake expiry sweep failed"),
                    }
                }
            }
        });
        info!("background sweep task started (every 5 minutes)");
    }

    // ── Background sweep: finalize executor withdrawals every 60 seconds ─────
    {
        let executor_sweep_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_executor_secs));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                match executor_sweep_engine.sweep_executor_withdrawals(chrono::Utc::now().timestamp()) {
                    Ok(0) => {} // nothing to finalize — silent
                    Ok(n) => info!(count = n, "sweep: finalized executor withdrawals"),
                    Err(e) => warn!(error = %e, "sweep: failed to process executor withdrawals"),
                }
            }
        });
        info!("executor withdrawal sweep task started (every 60 seconds)");
    }

    // ── Background sweep: auto-deliver matured wallet-to-wallet locks every 60s ──
    {
        let wallet_sweep_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_timelock_secs));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                match wallet_sweep_engine.sweep_matured_wallet_locks(chrono::Utc::now().timestamp()) {
                    Ok(0) => {} // nothing to deliver — silent
                    Ok(n) => info!(count = n, "sweep: auto-delivered matured wallet locks"),
                    Err(e) => warn!(error = %e, "sweep: failed to auto-deliver wallet locks"),
                }
            }
        });
        info!("wallet-to-wallet auto-delivery sweep started (every 60 seconds)");
    }

    

    // ── Background sweep: humanity stake 100-year expiry (daily) ──────────────
    {
        let expiry_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_humanity_secs));
            interval.tick().await;
            loop {
                interval.tick().await;
                match expiry_engine.sweep_genesis8_expiry(chrono::Utc::now().timestamp()) {
                    Ok(0) => {}
                    Ok(n) => info!(count = n, "sweep: humanity stake expiry transfers"),
                    Err(e) => warn!(error = %e, "sweep: humanity stake expiry failed"),
                }
            }
        });
        info!("humanity stake expiry sweep started (daily)");
    }

    // ── Background sweep: guardian transitions / sign of life (hourly) ────────
    {
        let sol_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_guardian_secs));
            interval.tick().await;
            loop {
                interval.tick().await;
                match sol_engine.sweep_sign_of_life(chrono::Utc::now().timestamp()) {
                    Ok(0) => {}
                    Ok(n) => info!(count = n, "sweep: guardian transitions processed"),
                    Err(e) => warn!(error = %e, "sweep: guardian transition check failed"),
                }
            }
        });
        info!("guardian transition sweep started (hourly)");
    }

    // ── Background sweep: promise chain anchors (daily) ───────────────────────
    {
        let anchor_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_promise_secs));
            interval.tick().await;
            loop {
                interval.tick().await;
                match anchor_engine.sweep_promise_chain_anchors(chrono::Utc::now().timestamp()) {
                    Ok(0) => {}
                    Ok(n) => info!(count = n, "sweep: promise chain anchors written"),
                    Err(e) => warn!(error = %e, "sweep: promise chain anchor failed"),
                }
            }
        });
        info!("promise chain anchor sweep started (daily)");
    }

    // ── Background sweep: settle loan payments every hour ─────────────────────
    {
        let loan_sweep_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_loan_secs));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                match loan_sweep_engine.sweep_loan_payments(chrono::Utc::now().timestamp(), loan_min_settlement) {
                    Ok(0) => {} // nothing to settle — silent
                    Ok(n) => info!(count = n, "sweep: settled loan interest payments"),
                    Err(e) => warn!(error = %e, "sweep: failed to settle loan payments"),
                }
            }
        });
        info!("loan payment sweep task started (every 3600 seconds)");
    }

    // ── Background sweep: activate loans past rescission window (every 5 min) ─
    {
        let rescission_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                match rescission_engine.sweep_loan_rescissions(chrono::Utc::now().timestamp()) {
                    Ok(0) => {} // nothing to activate — silent
                    Ok(n) => info!(count = n, "sweep: activated loans past rescission window"),
                    Err(e) => warn!(error = %e, "sweep: failed to sweep loan rescissions"),
                }
            }
        });
        info!("loan rescission sweep task started (every 300 seconds)");
    }
    // Oracle trigger sweep (every 60 seconds)
    {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = chrono::Utc::now().timestamp();
                match engine.sweep_oracle_triggers(now) {
                    Ok(n) if n > 0 => tracing::info!(triggered = n, "Oracle trigger sweep completed"),
                    Err(e) => tracing::warn!(error = %e, "Oracle trigger sweep error"),
                    _ => {}
                }
            }
        });
        tracing::info!("oracle trigger sweep started (every 60 seconds)");
    }
    // Oracle price poller: fetches KX/USD from HedgeKX API every 60s
    // and stores in oracle_price_kx_usd meta key for sweep_oracle_triggers
    {
        let db = Arc::clone(&engine).db.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                match client.get("http://127.0.0.1:4044/hedgekx/reserves")
                    .timeout(std::time::Duration::from_secs(5))
                    .send().await
                {
                    Ok(resp) => {
                        if let Ok(text) = resp.text().await {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                if let Some(price) = json.get("kx_price_now").and_then(|v| v.as_f64()) {
                                    if price > 0.0 {
                                        let _ = db.put_meta("oracle_price_kx_usd", price.to_string().as_bytes());
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {} // HedgeKX unavailable, skip
                }
            }
        });
        tracing::info!("oracle price poller started (every 60 seconds from HedgeKX)");
    }

    // Pending draw requests sweep (every 60 seconds)
    {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = chrono::Utc::now().timestamp();
                match engine.sweep_pending_drawrequests(now) {
                    Ok(n) if n > 0 => tracing::info!(executed = n, "Draw request sweep completed"),
                    Err(e) => tracing::warn!(error = %e, "Draw request sweep error"),
                    _ => {}
                }
            }
        });
        tracing::info!("pending draw request sweep started (every 60 seconds)");
    }

    // ── Background sweep: auto-renew matured deposits (every 60 seconds) ────
    {
        let deposit_sweep_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                match deposit_sweep_engine.sweep_matured_deposits(chrono::Utc::now().timestamp()) {
                    Ok(0) => {} // nothing to process — silent
                    Ok(n) => tracing::info!(count = n, "sweep: processed matured deposits"),
                    Err(e) => tracing::warn!(error = %e, "sweep: failed to sweep matured deposits"),
                }
            }
        });
        tracing::info!("deposit maturity sweep started (every 60 seconds)");
    }

    // ── Background sweep: friendly loan write-offs (every 60 seconds) ────
    {
        let fl_sweep_engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                match fl_sweep_engine.sweep_friendly_loan_writeoffs(chrono::Utc::now().timestamp()) {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(count = n, "sweep: wrote off expired friendly loans"),
                    Err(e) => tracing::warn!(error = %e, "sweep: friendly loan write-off failed"),
                }
            }
        });
        tracing::info!("friendly loan write-off sweep started (every 60 seconds)");
    }

    // ── Periodic node version check (every 24 hours) ─────────────────────────
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
            check_node_version().await;
        }
    });
    tracing::info!("node version check scheduled (every 24 hours)");

    // ── Main loop: validate & apply ───────────────────────────────────────────
    let mut difficulty = DifficultyConfig::new(args.pow_difficulty, 10_000, 100);


            // Store KXGC bond wallet in meta for TYPE A authority grant validation
            if let Ok(val) = std::env::var("KXGC_BOND_WALLET") {
                let _ = db.put_meta("kxgc_bond_wallet", val.as_bytes());
                info!(wallet = %val, "KXGC bond wallet stored in meta");
            } else {
                // Try loading from genesis-params.json
                if let Ok(gp_str) = std::fs::read_to_string("genesis-params.json") {
                    if let Ok(gp) = serde_json::from_str::<serde_json::Value>(&gp_str) {
                        if let Some(wallet) = gp.get("kxgc_bond_wallet_b58").and_then(|v| v.as_str()) {
                            let _ = db.put_meta("kxgc_bond_wallet", wallet.as_bytes());
                            info!(wallet = %wallet, "KXGC bond wallet loaded from genesis-params");
                        }
                    }
                }
            }

    info!("node ready");
    while let Some(tx) = tx_receiver.recv().await {
        let now = chrono::Utc::now().timestamp();
        match engine.apply(&tx, now) {
            Ok(()) => {
                // Check if any action is an ExecutorWithdraw and fire alert email.
                for action in &tx.actions {
                    if let chronx_core::transaction::Action::ExecutorWithdraw {
                        lock_id,
                        destination,
                        ..
                    } = action
                    {
                        // Look up the withdrawal record for the amount.
                        let lock_id_hex = lock_id.to_string();
                        let amount_kx = match db.get_executor_withdrawal(&lock_id_hex) {
                            Ok(Some(r)) => r.amount_chronos / 1_000_000,
                            _ => 0,
                        };
                        let delay_secs: i64 = std::env::var("EXECUTOR_WITHDRAW_DELAY_SECONDS")
                            .ok()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(86400);
                        let finalize_at = now + delay_secs;
                        // Fire alert email asynchronously.
                        let lock_str = lock_id_hex.clone();
                        let dest_str = destination.to_string();
                        tokio::spawn(async move {
                            send_executor_withdraw_alert(
                                &lock_str,
                                amount_kx,
                                &dest_str,
                                now,
                                finalize_at,
                            )
                            .await;
                        });
                    }
                }
                let payload = bincode::serialize(&tx).unwrap_or_default();
                let _ = outbound_tx.send(P2pMessage::NewVertex { payload }).await;
                let ts_ms = (tx.timestamp * 1000) as u64;
                if let Some(new_diff) = difficulty.record_solve(ts_ms) {
                    info!(difficulty = new_diff, "PoW difficulty adjusted");
                }
            }
            Err(e) => warn!(error = %e, "transaction rejected"),
        }
    }

    Ok(())
}

/// Load genesis parameters from a JSON file, or generate ephemeral keypairs if no path is given.
///
/// # Warning
/// Ephemeral keys are **not reproducible**. A node started without `--genesis-params`
/// will produce a genesis that cannot be shared with other nodes. Only use this for
/// local development and testing.
fn load_or_generate_genesis_params(
    path: Option<&std::path::Path>,
) -> anyhow::Result<GenesisParams> {
    if let Some(p) = path {
        let json = std::fs::read_to_string(p)
            .with_context(|| format!("reading genesis params from {}", p.display()))?;
        return serde_json::from_str(&json).context("parsing genesis params JSON");
    }
    let ps = KeyPair::generate();
    let tr = KeyPair::generate();
    let hu = KeyPair::generate();
    let nr = KeyPair::generate();
    let ms = KeyPair::generate();
    let re = KeyPair::generate();
    Ok(GenesisParams {
        public_sale_key: ps.public_key.clone(),
        treasury_key: tr.public_key.clone(),
        humanity_key: hu.public_key.clone(),
        node_rewards_key: nr.public_key.clone(),
        founder_key: chronx_core::types::DilithiumPublicKey(vec![0u8; 1312]),
        misai_key: chronx_core::types::DilithiumPublicKey(vec![0u8; 1312]),
        verifas_key: chronx_core::types::DilithiumPublicKey(vec![0u8; 1312]),
        milestone_key: ms.public_key.clone(),
        reserve_key: re.public_key.clone(),
        faucet_key: chronx_core::types::DilithiumPublicKey(vec![0u8; 1312]),
        axioms: None,
        rate_limit_tx_per_wallet_per_minute: 10,
        rate_limit_loan_actions_per_wallet_per_day: 100,
        channel_threshold_daily_tx: 1000,
        channel_open_min_lock_kx: 1,
        sweep_loan_interval_seconds: 3600,
        sweep_email_lock_interval_seconds: 300,
        sweep_matured_timelock_interval_seconds: 60,
        loan_min_settlement_chronos: 1000,
        sweep_humanity_stake_interval_seconds: 86400,
        sweep_guardian_transition_interval_seconds: 3600,
        sweep_promise_chain_interval_seconds: 86400,
        sweep_executor_interval_seconds: 60,
        pay_as_max_usd: 100.0,
        pay_as_enabled: true,
    })
}

/// Check the node version against https://chronx.io/version.json on startup.
/// Never blocks or fails startup — silently skips on any network error.
async fn check_node_version() {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let resp = match client.get("https://chronx.io/version.json").send().await {
        Ok(r) => r,
        Err(_) => return,
    };

    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(_) => return,
    };

    let latest_str = json["node_version"].as_str().unwrap_or("");
    let min_str = json["node_min_version"].as_str().unwrap_or("");

    if latest_str.is_empty() || min_str.is_empty() {
        return; // version.json doesn't have node fields yet — skip silently
    }

    let current = match semver::Version::parse(NODE_VERSION) {
        Ok(v) => v,
        Err(_) => return,
    };
    let latest = match semver::Version::parse(latest_str) {
        Ok(v) => v,
        Err(_) => return,
    };
    let minimum = match semver::Version::parse(min_str) {
        Ok(v) => v,
        Err(_) => return,
    };

    if current < minimum {
        // Red error box — exit(1)
        eprintln!();
        eprintln!("\x1b[31m\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
        eprintln!("\u{2551}  \u{2717}  ChronX Node Version No Longer Supported         \u{2551}");
        eprintln!("\u{2551}  Your version:   v{:<39}\u{2551}", NODE_VERSION);
        eprintln!("\u{2551}  Minimum:        v{:<39}\u{2551}", min_str);
        eprintln!("\u{2551}  Please update:  https://chronx.io/node.html        \u{2551}");
        eprintln!("\u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}\x1b[0m");
        eprintln!();
        std::process::exit(1);
    } else if current < latest {
        // Yellow warning box — continue starting
        eprintln!();
        eprintln!("\x1b[33m\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
        eprintln!("\u{2551}  \u{26a0}  ChronX Node Update Available                    \u{2551}");
        eprintln!("\u{2551}  Your version:   v{:<39}\u{2551}", NODE_VERSION);
        eprintln!("\u{2551}  Latest version: v{:<39}\u{2551}", latest_str);
        eprintln!("\u{2551}  Download at:    https://chronx.io/node.html        \u{2551}");
        eprintln!("\u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}\x1b[0m");
        eprintln!();
    }
    // If current >= latest: start silently, no output
}

/// Send an alert email via the notify API when an ExecutorWithdraw is submitted.
/// This gives a 24-hour window to cancel if the executor key is compromised.
async fn send_executor_withdraw_alert(
    lock_id: &str,
    amount_kx: u64,
    destination: &str,
    submitted_at: i64,
    finalize_at: i64,
) {
    let client = reqwest::Client::new();
    let notify_url = std::env::var("NOTIFY_API_URL")
        .unwrap_or_else(|_| "https://api.chronx.io/notify".to_string());

    let subject = format!(
        "\u{26a0}\u{fe0f} MISAI ExecutorWithdraw Submitted \u{2014} Lock {}",
        &lock_id[..16]
    );

    let body_text = format!(
        "MISAI ExecutorWithdraw Alert\n\n\
         Lock ID: {}\n\
         Amount: {} KX\n\
         Destination: {}\n\
         Submitted: {} (Unix)\n\
         Finalization: {} (Unix)\n\n\
         If this is unexpected, cancel immediately.\n\
         The lock is in PendingExecutor status and can be cancelled before finalization.",
        lock_id, amount_kx, destination, submitted_at, finalize_at
    );

    let payload = serde_json::json!({
        "email": "alerts@misai.io",
        "subject": subject,
        "body": body_text,
        "alert_type": "executor_withdraw"
    });

    match client.post(&notify_url).json(&payload).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                info!(lock_id = %lock_id, "ExecutorWithdraw alert email sent to alerts@misai.io");
            } else {
                warn!(
                    lock_id = %lock_id,
                    status = %resp.status(),
                    "ExecutorWithdraw alert email failed"
                );
            }
        }
        Err(e) => {
            warn!(
                lock_id = %lock_id,
                error = %e,
                "failed to send ExecutorWithdraw alert email"
            );
        }
    }
}

/// Expand a leading `~` to the user's home directory (`HOME` or `USERPROFILE`).
fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            return PathBuf::from(home).join(stripped);
        }
    }
    path.to_path_buf()
}
