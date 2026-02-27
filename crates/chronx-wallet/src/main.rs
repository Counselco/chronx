//! chronx-wallet
//!
//! CLI wallet for ChronX. Manages Dilithium2 keypairs, builds and signs
//! transactions, and submits them to a running node via JSON-RPC.
//!
//! Usage:
//!   chronx-wallet keygen    [--keyfile <path>]
//!   chronx-wallet transfer  --to <account> --amount <kx> [--rpc <url>] [--keyfile <path>]
//!   chronx-wallet timelock  --to-pubkey <hex> --amount <kx> --unlock <unix_ts> [--rpc <url>] [--keyfile <path>]
//!   chronx-wallet claim     --lock-id <hex> [--rpc <url>] [--keyfile <path>]
//!   chronx-wallet balance   --account <b58> [--rpc <url>]
//!   chronx-wallet info      [--rpc <url>]

use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use tracing::info;

use chronx_core::{
    constants::{CHRONOS_PER_KX, POW_INITIAL_DIFFICULTY},
    transaction::{Action, AuthScheme, Transaction},
    types::{AccountId, DilithiumPublicKey, TimeLockId, TxId},
};
use chronx_crypto::{hash::tx_id_from_body, mine_pow, KeyPair};
use chronx_genesis::GenesisParams;

mod rpc_client;
use rpc_client::WalletRpcClient;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "chronx-wallet",
    version,
    about = "ChronX wallet — sign and submit transactions"
)]
struct Args {
    /// Path to the keyfile (JSON).
    #[arg(long, global = true, default_value = "~/.chronx/wallet.json")]
    keyfile: PathBuf,

    /// Node RPC endpoint.
    #[arg(long, global = true, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new Dilithium2 keypair and save to the keyfile.
    Keygen,

    /// Print the account ID and balance.
    Balance {
        /// Account to query (base-58). Defaults to the local keypair's account.
        #[arg(long)]
        account: Option<String>,
    },

    /// Transfer KX to another account.
    Transfer {
        /// Recipient account ID (base-58).
        #[arg(long)]
        to: String,
        /// Amount in KX (will be converted to Chronos internally).
        #[arg(long)]
        amount: f64,
    },

    /// Create a time-lock sending KX to a recipient key.
    Timelock {
        /// Recipient Dilithium2 public key (hex-encoded).
        #[arg(long)]
        to_pubkey: String,
        /// Amount in KX.
        #[arg(long)]
        amount: f64,
        /// Unlock Unix timestamp (UTC seconds).
        #[arg(long)]
        unlock: i64,
        /// Optional memo (max 256 chars).
        #[arg(long)]
        memo: Option<String>,
    },

    /// Claim a matured time-lock.
    Claim {
        /// Lock ID (TxId hex of the creating transaction).
        #[arg(long)]
        lock_id: String,
    },

    /// Initiate account recovery for a target account.
    Recover {
        /// Target account (base-58).
        #[arg(long)]
        target: String,
        /// Proposed new owner public key (hex).
        #[arg(long)]
        new_key: String,
        /// Blake3 hash of off-chain evidence (hex, 32 bytes).
        #[arg(long)]
        evidence: String,
        /// Bond amount in KX.
        #[arg(long)]
        bond: f64,
    },

    /// Challenge an in-progress recovery for a target account.
    ChallengeRecovery {
        /// Target account whose recovery you are challenging (base-58).
        #[arg(long)]
        target: String,
        /// Blake3 hash of off-chain counter-evidence (hex, 32 bytes).
        #[arg(long)]
        counter_evidence: String,
        /// Challenge bond amount in KX.
        #[arg(long)]
        bond: f64,
    },

    /// Cast a verifier vote on an active recovery.
    VoteRecovery {
        /// Target account under recovery (base-58).
        #[arg(long)]
        target: String,
        /// Approve the recovery (pass --approve) or reject (omit flag).
        #[arg(long, default_value_t = false)]
        approve: bool,
        /// Fee bid in KX (paid from recovery bond if approved).
        #[arg(long, default_value_t = 0.0)]
        fee_bid: f64,
    },

    /// Finalize an approved recovery after the delay has elapsed.
    FinalizeRecovery {
        /// Target account to finalize recovery for (base-58).
        #[arg(long)]
        target: String,
    },

    /// Print genesis/protocol info from the node.
    Info,

    /// Generate three genesis keypairs (public_sale, treasury, humanity) and
    /// write genesis-params.json to the output directory.
    /// Run this ONCE before launching a new chain, then store the private keys
    /// in cold storage.
    GenesisParams {
        /// Directory to write keypairs and genesis-params.json into.
        #[arg(long, default_value = "~/.chronx/genesis")]
        out_dir: PathBuf,
    },
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn,chronx_wallet=info")
        .init();

    let args = Args::parse();
    let keyfile = expand_tilde(&args.keyfile);
    let client = WalletRpcClient::new(&args.rpc);

    match args.command {
        Command::Keygen => cmd_keygen(&keyfile),

        Command::Balance { account } => {
            let addr = match account {
                Some(a) => a,
                None => {
                    let kp = load_keypair(&keyfile)?;
                    kp.account_id.to_b58()
                }
            };
            let bal = client.get_balance(&addr).await?;
            let bal_kx = bal / CHRONOS_PER_KX;
            println!("Account:  {}", addr);
            println!("Balance:  {} KX  ({} Chronos)", bal_kx, bal);
            Ok(())
        }

        Command::Transfer { to, amount } => {
            let kp = load_keypair(&keyfile)?;
            let to_id = AccountId::from_b58(&to)
                .map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            let chronos = kx_to_chronos(amount);
            let tx = build_and_sign(
                &kp,
                vec![Action::Transfer { to: to_id, amount: chronos }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Submitted: {}", tx_id);
            Ok(())
        }

        Command::Timelock { to_pubkey, amount, unlock, memo } => {
            let kp = load_keypair(&keyfile)?;
            let pk_bytes =
                hex::decode(&to_pubkey).context("decoding recipient public key hex")?;
            let chronos = kx_to_chronos(amount);
            let tx = build_and_sign(
                &kp,
                vec![Action::TimeLockCreate {
                    recipient: DilithiumPublicKey(pk_bytes),
                    amount: chronos,
                    unlock_at: unlock,
                    memo,
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("TimeLock created: {}", tx_id);
            Ok(())
        }

        Command::Claim { lock_id } => {
            let kp = load_keypair(&keyfile)?;
            let lock_txid =
                TxId::from_hex(&lock_id).map_err(|e| anyhow::anyhow!("invalid lock id: {e}"))?;
            let tx = build_and_sign(
                &kp,
                vec![Action::TimeLockClaim {
                    lock_id: TimeLockId(lock_txid),
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Claim submitted: {}", tx_id);
            Ok(())
        }

        Command::Recover { target, new_key, evidence, bond } => {
            let kp = load_keypair(&keyfile)?;
            let target_id = AccountId::from_b58(&target)
                .map_err(|e| anyhow::anyhow!("invalid target account: {e}"))?;
            let new_pk_bytes =
                hex::decode(&new_key).context("decoding proposed owner key hex")?;
            let ev_bytes = hex::decode(&evidence).context("decoding evidence hash hex")?;
            if ev_bytes.len() != 32 {
                bail!("evidence hash must be 32 bytes (64 hex chars)");
            }
            let mut ev_arr = [0u8; 32];
            ev_arr.copy_from_slice(&ev_bytes);
            let bond_chronos = kx_to_chronos(bond);

            let tx = build_and_sign(
                &kp,
                vec![Action::StartRecovery {
                    target_account: target_id,
                    proposed_owner_key: DilithiumPublicKey(new_pk_bytes),
                    evidence_hash: chronx_core::types::EvidenceHash(ev_arr),
                    bond_amount: bond_chronos,
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Recovery started: {}", tx_id);
            Ok(())
        }

        Command::ChallengeRecovery { target, counter_evidence, bond } => {
            let kp = load_keypair(&keyfile)?;
            let target_id = AccountId::from_b58(&target)
                .map_err(|e| anyhow::anyhow!("invalid target account: {e}"))?;
            let ev_bytes = hex::decode(&counter_evidence)
                .context("decoding counter-evidence hash hex")?;
            if ev_bytes.len() != 32 {
                bail!("counter-evidence hash must be 32 bytes (64 hex chars)");
            }
            let mut ev_arr = [0u8; 32];
            ev_arr.copy_from_slice(&ev_bytes);
            let bond_chronos = kx_to_chronos(bond);

            let tx = build_and_sign(
                &kp,
                vec![Action::ChallengeRecovery {
                    target_account: target_id,
                    counter_evidence_hash: chronx_core::types::EvidenceHash(ev_arr),
                    bond_amount: bond_chronos,
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Challenge submitted: {}", tx_id);
            Ok(())
        }

        Command::VoteRecovery { target, approve, fee_bid } => {
            let kp = load_keypair(&keyfile)?;
            let target_id = AccountId::from_b58(&target)
                .map_err(|e| anyhow::anyhow!("invalid target account: {e}"))?;
            let fee_chronos = kx_to_chronos(fee_bid);

            let tx = build_and_sign(
                &kp,
                vec![Action::VoteRecovery {
                    target_account: target_id,
                    approve,
                    fee_bid: fee_chronos,
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Vote submitted (approve={}): {}", approve, tx_id);
            Ok(())
        }

        Command::FinalizeRecovery { target } => {
            let kp = load_keypair(&keyfile)?;
            let target_id = AccountId::from_b58(&target)
                .map_err(|e| anyhow::anyhow!("invalid target account: {e}"))?;

            let tx = build_and_sign(
                &kp,
                vec![Action::FinalizeRecovery {
                    target_account: target_id,
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Recovery finalized: {}", tx_id);
            Ok(())
        }

        Command::Info => {
            let info = client.get_genesis_info().await?;
            println!("Protocol:     {}", info.protocol);
            println!("Ticker:       {}", info.ticker);
            println!("Base unit:    {}", info.base_unit);
            println!("Total supply: {} {}", info.total_supply_kx, info.ticker);
            println!("PoW difficulty: {} bits", info.pow_difficulty);
            Ok(())
        }

        Command::GenesisParams { out_dir } => {
            let dir = expand_tilde(&out_dir);
            cmd_genesis_params(&dir)
        }
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

fn cmd_keygen(keyfile: &PathBuf) -> anyhow::Result<()> {
    if keyfile.exists() {
        bail!(
            "Keyfile {} already exists. Delete it first to generate a new key.",
            keyfile.display()
        );
    }
    if let Some(parent) = keyfile.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let kp = KeyPair::generate();
    let json = serde_json::to_string_pretty(&kp)?;
    std::fs::write(keyfile, &json)
        .with_context(|| format!("writing keyfile to {}", keyfile.display()))?;

    println!("Generated new keypair.");
    println!("Account ID: {}", kp.account_id.to_b58());
    println!("Public key: {}", hex::encode(&kp.public_key.0));
    println!("Keyfile:    {}", keyfile.display());
    println!("\nBACK UP YOUR KEYFILE. Loss = permanent loss of funds.");
    Ok(())
}

fn cmd_genesis_params(out_dir: &PathBuf) -> anyhow::Result<()> {
    if out_dir.exists() {
        bail!(
            "Output directory {} already exists. Delete it first to avoid overwriting a previous genesis ceremony.",
            out_dir.display()
        );
    }
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating output directory {}", out_dir.display()))?;

    // Generate all three keypairs.
    let public_sale_kp = KeyPair::generate();
    let treasury_kp    = KeyPair::generate();
    let humanity_kp    = KeyPair::generate();

    // Write each private keyfile.
    let ps_path = out_dir.join("public_sale.json");
    let tr_path = out_dir.join("treasury.json");
    let hu_path = out_dir.join("humanity.json");

    std::fs::write(&ps_path, serde_json::to_string_pretty(&public_sale_kp)?)
        .with_context(|| format!("writing {}", ps_path.display()))?;
    std::fs::write(&tr_path, serde_json::to_string_pretty(&treasury_kp)?)
        .with_context(|| format!("writing {}", tr_path.display()))?;
    std::fs::write(&hu_path, serde_json::to_string_pretty(&humanity_kp)?)
        .with_context(|| format!("writing {}", hu_path.display()))?;

    // Build GenesisParams (public keys only) and write genesis-params.json.
    let params = GenesisParams {
        public_sale_key: public_sale_kp.public_key.clone(),
        treasury_key:    treasury_kp.public_key.clone(),
        humanity_key:    humanity_kp.public_key.clone(),
    };
    let params_path = out_dir.join("genesis-params.json");
    std::fs::write(&params_path, serde_json::to_string_pretty(&params)?)
        .with_context(|| format!("writing {}", params_path.display()))?;

    println!("Genesis keypair ceremony complete.");
    println!();
    println!("Public sale");
    println!("  Account:  {}", public_sale_kp.account_id.to_b58());
    println!("  PubKey:   {}", hex::encode(&public_sale_kp.public_key.0));
    println!("  Keyfile:  {}", ps_path.display());
    println!();
    println!("Treasury");
    println!("  Account:  {}", treasury_kp.account_id.to_b58());
    println!("  PubKey:   {}", hex::encode(&treasury_kp.public_key.0));
    println!("  Keyfile:  {}", tr_path.display());
    println!();
    println!("Humanity stake");
    println!("  Account:  {}", humanity_kp.account_id.to_b58());
    println!("  PubKey:   {}", hex::encode(&humanity_kp.public_key.0));
    println!("  Keyfile:  {}", hu_path.display());
    println!();
    println!("genesis-params.json written to: {}", params_path.display());
    println!();
    println!("CRITICAL: Move private keyfiles off this machine and into cold storage NOW.");
    println!("Only genesis-params.json is needed by the node (--genesis-params flag).");

    Ok(())
}

// ── Transaction builder ───────────────────────────────────────────────────────

async fn build_and_sign(
    kp: &KeyPair,
    actions: Vec<Action>,
    client: &WalletRpcClient,
) -> anyhow::Result<Transaction> {
    // Fetch current nonce and DAG tips from the node.
    let nonce = client.get_nonce(&kp.account_id.to_b58()).await?;
    let tips = client.get_dag_tips().await?;

    let timestamp = chrono::Utc::now().timestamp();

    // Serialize body (does NOT include pow_nonce — stable for mining).
    let body_fields = chronx_core::transaction::TransactionBody {
        parents: &tips,
        timestamp,
        nonce,
        from: &kp.account_id,
        actions: &actions,
        auth_scheme: &AuthScheme::SingleSig,
    };
    let body_bytes = bincode::serialize(&body_fields)?;

    info!("Mining PoW (difficulty={})...", POW_INITIAL_DIFFICULTY);
    let pow_nonce = mine_pow(&body_bytes, POW_INITIAL_DIFFICULTY);
    info!("PoW solved: nonce={}", pow_nonce);

    let signature = kp.sign(&body_bytes);
    let tx_id = tx_id_from_body(&body_bytes);

    Ok(Transaction {
        tx_id,
        parents: tips,
        timestamp,
        nonce,
        from: kp.account_id.clone(),
        actions,
        pow_nonce,
        signatures: vec![signature],
        auth_scheme: AuthScheme::SingleSig,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_keypair(keyfile: &PathBuf) -> anyhow::Result<KeyPair> {
    let json = std::fs::read_to_string(keyfile)
        .with_context(|| format!("reading keyfile {}", keyfile.display()))?;
    let kp: KeyPair =
        serde_json::from_str(&json).context("parsing keyfile — is it a valid ChronX keyfile?")?;
    Ok(kp)
}

fn kx_to_chronos(kx: f64) -> u128 {
    (kx * CHRONOS_PER_KX as f64) as u128
}

fn expand_tilde(path: &PathBuf) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            return PathBuf::from(home).join(stripped);
        }
    }
    path.clone()
}
