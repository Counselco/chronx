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
    info!("ChronX node starting");

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

    // ── State engine ──────────────────────────────────────────────────────────
    // Share the same DB handle — sled uses an Arc internally so this is safe.
    let engine = Arc::new(StateEngine::new(Arc::clone(&db), args.pow_difficulty));

    // ── Inbound transaction queue ─────────────────────────────────────────────
    let (tx_sender, mut tx_receiver) =
        tokio::sync::mpsc::channel::<chronx_core::transaction::Transaction>(512);

    // ── P2P network ───────────────────────────────────────────────────────────
    let p2p_config = P2pConfig {
        listen_addr: args.p2p_listen.clone(),
        bootstrap_peers: args.bootstrap.clone(),
        protocol_version: "/chronx/1.0.0".into(),
        vertex_topic: "chronx-vertices".into(),
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
    });
    let _rpc_handle = RpcServer::new(rpc_state)
        .start(args.rpc_addr)
        .await
        .context("starting RPC server")?;

    // ── Main loop: validate & apply ───────────────────────────────────────────
    let mut difficulty = DifficultyConfig::new(args.pow_difficulty, 10_000, 100);

    info!("node ready");
    while let Some(tx) = tx_receiver.recv().await {
        let now = chrono::Utc::now().timestamp();
        match engine.apply(&tx, now) {
            Ok(()) => {
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
    warn!("No --genesis-params provided. Generating ephemeral keys — DO NOT USE IN PRODUCTION.");
    let ps = KeyPair::generate();
    let tr = KeyPair::generate();
    let hu = KeyPair::generate();
    Ok(GenesisParams {
        public_sale_key: ps.public_key.clone(),
        treasury_key: tr.public_key.clone(),
        humanity_key: hu.public_key.clone(),
    })
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
