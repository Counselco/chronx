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

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use tracing::info;

use chronx_core::{
    constants::{CHRONOS_PER_KX, POW_INITIAL_DIFFICULTY},
    transaction::{
        Action, AuthScheme, Transaction,
        CreateInvoiceAction, FulfillInvoiceAction, CancelInvoiceAction,
        CreateCreditAction, DrawCreditAction, RevokeCreditAction,
        CreateDepositAction, SettleDepositAction, Compounding,
        CreateConditionalAction, AttestConditionalAction, ConditionalFallback,
        CreateLedgerEntryAction, LedgerEntryType,
    },
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

    /// Create an email time-lock (uses sender's own pubkey; claimable via code).
    EmailTimelock {
        /// Recipient email address.
        #[arg(long)]
        email: String,
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

    /// Send a cascade of time-locked email payments with one shared claim code.
    Cascade {
        /// Recipient email address.
        #[arg(long)]
        email: String,
        /// JSON array of stages: [{"amount_kx":100,"lock_seconds":0}, ...]
        #[arg(long)]
        stages: String,
        /// Optional memo (max 256 chars).
        #[arg(long)]
        memo: Option<String>,
    },

    /// Register a verifier (governance-only).
    VerifierRegister {
        /// Verifier display name.
        #[arg(long)]
        name: String,
        /// Verifier wallet address (base-58).
        #[arg(long)]
        wallet: String,
        /// Bond amount in KX.
        #[arg(long)]
        bond: u64,
        /// Verifier Dilithium2 public key (hex).
        #[arg(long)]
        pubkey: String,
        /// Jurisdiction code (e.g. "US-DE").
        #[arg(long)]
        jurisdiction: String,
        /// Role: "VerifasVault" or "BondedFinder".
        #[arg(long)]
        role: String,
    },


    /// Claim email locks using a claim code (used by relay auto-delivery).
    ClaimByCode {
        /// The claim code (e.g. KX-XXXX-XXXX-XXXX-XXXX).
        #[arg(long)]
        claim_code: String,
    },

    /// MISAI executor withdraws KX from a live Type M lock for AI-managed trading.
    /// The executor wallet keyfile must be used to sign the transaction.
    ExecutorWithdraw {
        /// Lock ID (TxId hex of the Type M lock to withdraw from).
        #[arg(long)]
        lock_id: String,
    },

    /// Print genesis/protocol info from the node.
    Info,

    /// Create an invoice requesting payment.
    CreateInvoice {
        /// Amount in KX.
        #[arg(long)]
        amount: f64,
        /// Expiry in days from now.
        #[arg(long)]
        expiry_days: u64,
        /// Optional payer wallet (base-58). If omitted, invoice is OPEN.
        #[arg(long)]
        payer: Option<String>,
        /// Optional memo text.
        #[arg(long)]
        memo: Option<String>,
    },

    /// Create a credit authorization for a beneficiary.
    CreateCredit {
        /// Beneficiary wallet (base-58).
        #[arg(long)]
        beneficiary: String,
        /// Credit ceiling in KX.
        #[arg(long)]
        ceiling: f64,
        /// Expiry in days from now.
        #[arg(long)]
        expiry_days: u64,
        /// Optional per-draw maximum in KX.
        #[arg(long)]
        per_draw: Option<f64>,
    },

    /// Draw from a credit authorization.
    DrawCredit {
        /// Credit ID (hex).
        #[arg(long)]
        credit_id: String,
        /// Amount in KX.
        #[arg(long)]
        amount: f64,
    },

    /// Create an interest-bearing deposit.
    CreateDeposit {
        /// Obligor wallet (base-58).
        #[arg(long)]
        obligor: String,
        /// Principal in KX.
        #[arg(long)]
        amount: f64,
        /// Interest rate in basis points.
        #[arg(long)]
        rate_bps: u64,
        /// Term in days.
        #[arg(long)]
        term_days: u64,
        /// Compounding: simple, daily, monthly, annually.
        #[arg(long, default_value = "simple")]
        compounding: String,
    },

    /// Create a conditional payment requiring attestor approval.
    CreateConditional {
        /// Recipient wallet (base-58).
        #[arg(long)]
        recipient: String,
        /// Amount in KX.
        #[arg(long)]
        amount: f64,
        /// Attestor wallet(s) — can specify multiple.
        #[arg(long)]
        attestor: Vec<String>,
        /// Minimum attestors needed.
        #[arg(long)]
        min_attestors: u32,
        /// Expiry in days from now.
        #[arg(long)]
        expiry_days: u64,
        /// Fallback: void, return, escrow.
        #[arg(long, default_value = "return")]
        fallback: String,
        /// Condition type: SingleAttestation (default), OracleTrigger
        #[arg(long)]
        condition_type: Option<String>,
        /// Oracle pair (e.g. "KX/USD")
        #[arg(long)]
        oracle_pair: Option<String>,
        /// Oracle trigger threshold (e.g. 0.99 = fires at 99% of creation price)
        #[arg(long)]
        oracle_trigger_threshold: Option<f64>,
        /// Oracle trigger direction: Below or Above
        #[arg(long)]
        oracle_trigger_direction: Option<String>,
        /// Wallet that receives success payment on clean expiry
        #[arg(long)]
        success_payment_wallet: Option<String>,
        /// Success payment amount in KX
        #[arg(long)]
        success_payment_kx: Option<f64>,
        /// Expiry in seconds (overrides --expiry-days if set)
        #[arg(long)]
        expiry_seconds: Option<u64>,
    },

    /// Attest (approve) a conditional payment.
    AttestConditional {
        /// Type V ID (hex).
        #[arg(long)]
        type_v_id: String,
    },

    /// Create a ledger entry (bonded agents only).
    CreateLedgerEntry {
        /// Promise ID (hex).
        #[arg(long)]
        promise_id: String,
        /// Entry type: decision, summary, sign-of-life, beneficiary-identified.
        #[arg(long, name = "type")]
        entry_type: String,
        /// Content hash (hex).
        #[arg(long)]
        content_hash: String,
        /// Summary text.
        #[arg(long)]
        summary: String,
    },


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
            let to_id =
                AccountId::from_b58(&to).map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            let chronos = kx_to_chronos(amount);
            let tx = build_and_sign(
                &kp,
                vec![Action::Transfer {
                    to: to_id,
                    amount: chronos,
                    memo: None,
                    memo_encrypted: true,
                    memo_public: false,
                    pay_as_amount: None,
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Submitted: {}", tx_id);
            Ok(())
        }

        Command::Timelock {
            to_pubkey,
            amount,
            unlock,
            memo,
        } => {
            let kp = load_keypair(&keyfile)?;
            let pk_bytes = hex::decode(&to_pubkey).context("decoding recipient public key hex")?;
            let chronos = kx_to_chronos(amount);
            let tx = build_and_sign(
                &kp,
                vec![Action::TimeLockCreate {
                    recipient: DilithiumPublicKey(pk_bytes),
                    amount: chronos,
                    unlock_at: unlock,
                    memo,
                    cancellation_window_secs: None,
                    notify_recipient: None,
                    tags: None,
                    private: None,
                    expiry_policy: None,
                    split_policy: None,
                    claim_attempts_max: None,
                    recurring: None,
                    lock_marker: None,
                    oracle_hint: None,
                    jurisdiction_hint: None,
                    governance_proposal_id: None,
                    client_ref: None,
                    email_recipient_hash: None,
                    claim_window_secs: None,
                    unclaimed_action: None,
                lock_type: None,
                lock_metadata: None,
                    agent_managed: None,
                    grantor_axiom_consent_hash: None,
                    investable_fraction: None,
                    risk_level: None,
                    investment_exclusions: None,
                    grantor_intent: None,
                    sign_of_life_interval_days: None,
                    sign_of_life_grace_days: None,
                    guardian_pubkey: None,
                    guardian_until: None,
                    alt_guardian_pubkey: None,
                    beneficiary_description: None,
                    beneficiary_description_hash: None,
                    convert_to: None, authorized_claimants: None, succession_group: None, backup_executors: None, executor_threshold: None,
                    memo_encrypted: true,
                    memo_public: false,
                    pay_as_amount: None,
                    beneficiary_package: None,
                
                    transferable: None,
                    current_owner_account: None,
                    transfer_history: None,
                    terms_visibility: None,
                    tranche_info: None,
                    retirement_status: None,
                    retired_fraction: None,

                    escalation_wallet: None,
                    escalation_lock_seconds: None,
                    min_attestors_pct: None,
                    required_hedge_ids: None,
                    success_payment_wallet: None,
                    success_payment_chronos: None,
                    condition_type: None,
                    oracle_pair: None,
                    oracle_trigger_threshold: None,
                    oracle_trigger_direction: None,
                    linked_instrument_id: None,
}],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("TimeLock created: {}", tx_id);
            Ok(())
        }

        Command::EmailTimelock {
            email,
            amount,
            unlock,
            memo,
        } => {
            use chronx_core::UnclaimedAction;
            use rand::Rng;

            let kp = load_keypair(&keyfile)?;
            let chronos = kx_to_chronos(amount);

            // Generate claim code: KX-XXXX-XXXX-XXXX-XXXX
            let mut rng = rand::thread_rng();
            let segments: Vec<String> = (0..4)
                .map(|_| {
                    let n: u32 = rng.gen_range(0..36u32.pow(4));
                    let chars: Vec<char> = (0..4)
                        .map(|i| {
                            let d = ((n / 36u32.pow(i)) % 36) as u8;
                            if d < 10 { (b'0' + d) as char } else { (b'A' + d - 10) as char }
                        })
                        .collect();
                    chars.into_iter().collect()
                })
                .collect();
            let claim_code = format!("KX-{}-{}-{}-{}", segments[0], segments[1], segments[2], segments[3]);

            // BLAKE3(claim_code) → lock_marker (0xC5 marker + 32 bytes)
            let code_hash = blake3::hash(claim_code.as_bytes());
            let mut ext = vec![0xC5u8];
            ext.extend_from_slice(code_hash.as_bytes());

            // BLAKE3(lowercase email) → email_recipient_hash
            let email_hash = blake3::hash(email.trim().to_lowercase().as_bytes());
            let email_hash_bytes: [u8; 32] = *email_hash.as_bytes();

            let tx = build_and_sign(
                &kp,
                vec![Action::TimeLockCreate {
                    recipient: kp.public_key.clone(),
                    amount: chronos,
                    unlock_at: unlock,
                    memo,
                    cancellation_window_secs: Some(259_200),
                    notify_recipient: None,
                    tags: None,
                    private: None,
                    expiry_policy: None,
                    split_policy: None,
                    claim_attempts_max: None,
                    recurring: None,
                    lock_marker: Some(ext),
                    oracle_hint: None,
                    jurisdiction_hint: None,
                    governance_proposal_id: None,
                    client_ref: None,
                    email_recipient_hash: Some(email_hash_bytes),
                    claim_window_secs: Some(259_200),
                    unclaimed_action: Some(UnclaimedAction::RevertToSender),
                    lock_type: None,
                    lock_metadata: None,
                    agent_managed: None,
                    grantor_axiom_consent_hash: None,
                    investable_fraction: None,
                    risk_level: None,
                    investment_exclusions: None,
                    grantor_intent: None,
                    sign_of_life_interval_days: None,
                    sign_of_life_grace_days: None,
                    guardian_pubkey: None,
                    guardian_until: None,
                    alt_guardian_pubkey: None,
                    beneficiary_description: None,
                    beneficiary_description_hash: None,
                    convert_to: None, authorized_claimants: None, succession_group: None, backup_executors: None, executor_threshold: None,
                    memo_encrypted: true,
                    memo_public: false,
                    pay_as_amount: None,
                    beneficiary_package: None,
                
                    transferable: None,
                    current_owner_account: None,
                    transfer_history: None,
                    terms_visibility: None,
                    tranche_info: None,
                    retirement_status: None,
                    retired_fraction: None,

                    escalation_wallet: None,
                    escalation_lock_seconds: None,
                    min_attestors_pct: None,
                    required_hedge_ids: None,
                    success_payment_wallet: None,
                    success_payment_chronos: None,
                    condition_type: None,
                    oracle_pair: None,
                    oracle_trigger_threshold: None,
                    oracle_trigger_direction: None,
                    linked_instrument_id: None,
}],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Submitted: {}", tx_id);
            println!("ClaimCode: {}", claim_code);
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

        Command::Recover {
            target,
            new_key,
            evidence,
            bond,
        } => {
            let kp = load_keypair(&keyfile)?;
            let target_id = AccountId::from_b58(&target)
                .map_err(|e| anyhow::anyhow!("invalid target account: {e}"))?;
            let new_pk_bytes = hex::decode(&new_key).context("decoding proposed owner key hex")?;
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

        Command::ChallengeRecovery {
            target,
            counter_evidence,
            bond,
        } => {
            let kp = load_keypair(&keyfile)?;
            let target_id = AccountId::from_b58(&target)
                .map_err(|e| anyhow::anyhow!("invalid target account: {e}"))?;
            let ev_bytes =
                hex::decode(&counter_evidence).context("decoding counter-evidence hash hex")?;
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

        Command::VoteRecovery {
            target,
            approve,
            fee_bid,
        } => {
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

        Command::Cascade {
            email,
            stages,
            memo,
        } => {
            use chronx_core::UnclaimedAction;
            use rand::Rng;

            let kp = load_keypair(&keyfile)?;

            // Parse stages JSON
            #[derive(serde::Deserialize)]
            struct Stage {
                amount_kx: f64,
                lock_seconds: i64,
            }
            let parsed: Vec<Stage> =
                serde_json::from_str(&stages).context("parsing stages JSON")?;

            if parsed.is_empty() {
                bail!("stages array cannot be empty");
            }

            // Generate claim code: KX-XXXX-XXXX-XXXX-XXXX
            let mut rng = rand::thread_rng();
            let segments: Vec<String> = (0..4)
                .map(|_| {
                    let n: u32 = rng.gen_range(0..36u32.pow(4));
                    let chars: Vec<char> = (0..4)
                        .map(|i| {
                            let d = ((n / 36u32.pow(i)) % 36) as u8;
                            if d < 10 {
                                (b'0' + d) as char
                            } else {
                                (b'A' + d - 10) as char
                            }
                        })
                        .collect();
                    chars.into_iter().collect()
                })
                .collect();
            let claim_code = format!(
                "KX-{}-{}-{}-{}",
                segments[0], segments[1], segments[2], segments[3]
            );

            // BLAKE3(claim_code) → lock_marker (0xC5 marker + 32 bytes)
            let code_hash = blake3::hash(claim_code.as_bytes());
            let mut ext = vec![0xC5u8];
            ext.extend_from_slice(code_hash.as_bytes());

            // BLAKE3(lowercase email) → email_recipient_hash
            let email_hash = blake3::hash(email.trim().to_lowercase().as_bytes());
            let email_hash_bytes: [u8; 32] = *email_hash.as_bytes();

            let now = chrono::Utc::now().timestamp();

            // Build one TimeLockCreate action per stage
            let actions: Vec<Action> = parsed
                .iter()
                .map(|s| {
                    let unlock_at = if s.lock_seconds <= 0 {
                        now
                    } else {
                        now + s.lock_seconds
                    };
                    Action::TimeLockCreate {
                        recipient: kp.public_key.clone(),
                        amount: kx_to_chronos(s.amount_kx),
                        unlock_at,
                        memo: memo.clone(),
                        cancellation_window_secs: Some(259_200),
                        notify_recipient: None,
                        tags: None,
                        private: None,
                        expiry_policy: None,
                        split_policy: None,
                        claim_attempts_max: None,
                        recurring: None,
                        lock_marker: Some(ext.clone()),
                        oracle_hint: None,
                        jurisdiction_hint: None,
                        governance_proposal_id: None,
                        client_ref: None,
                        email_recipient_hash: Some(email_hash_bytes),
                        claim_window_secs: Some(259_200),
                        unclaimed_action: Some(UnclaimedAction::RevertToSender),
                        lock_type: None,
                        lock_metadata: None,
                        agent_managed: None,
                        grantor_axiom_consent_hash: None,
                        investable_fraction: None,
                        risk_level: None,
                        investment_exclusions: None,
                        grantor_intent: None,
                    sign_of_life_interval_days: None,
                    sign_of_life_grace_days: None,
                    guardian_pubkey: None,
                    guardian_until: None,
                    alt_guardian_pubkey: None,
                    beneficiary_description: None,
                    beneficiary_description_hash: None,
                    convert_to: None, authorized_claimants: None, succession_group: None, backup_executors: None, executor_threshold: None,
                        memo_encrypted: true,
                        memo_public: false,
                        pay_as_amount: None,
                        beneficiary_package: None,
                    
                        transferable: None,
                        current_owner_account: None,
                        transfer_history: None,
                        terms_visibility: None,
                        tranche_info: None,
                        retirement_status: None,
                        retired_fraction: None,

                        escalation_wallet: None,
                        escalation_lock_seconds: None,
                        min_attestors_pct: None,
                        required_hedge_ids: None,
                        success_payment_wallet: None,
                        success_payment_chronos: None,
                        condition_type: None,
                        oracle_pair: None,
                        oracle_trigger_threshold: None,
                        oracle_trigger_direction: None,
                        linked_instrument_id: None,
}
                })
                .collect();

            let n_stages = parsed.len();
            let total_kx: f64 = parsed.iter().map(|s| s.amount_kx).sum();
            println!(
                "Building cascade: {} stages, {} KX total...",
                n_stages, total_kx
            );

            let tx = build_and_sign(&kp, actions, &client).await?;
            let tx_id = client.send_transaction(&tx).await?;

            println!("Submitted:  {}", tx_id);
            println!("ClaimCode:  {}", claim_code);
            println!("Email:      {}", email);
            for (i, s) in parsed.iter().enumerate() {
                let unlock = if s.lock_seconds <= 0 {
                    now
                } else {
                    now + s.lock_seconds
                };
                println!(
                    "  Stage {}: {:>8.2} KX — unlock_at {} (lock {} sec)",
                    i + 1,
                    s.amount_kx,
                    unlock,
                    s.lock_seconds
                );
            }
            Ok(())
        }

        Command::VerifierRegister { name, wallet, bond, pubkey, jurisdiction, role } => {
            let kp = load_keypair(&keyfile)?;
            let tx = build_and_sign(
                &kp,
                vec![Action::VerifierRegister {
                    verifier_name: name,
                    wallet_address: wallet,
                    bond_amount_kx: bond,
                    dilithium2_public_key_hex: pubkey,
                    jurisdiction,
                    role,
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("VerifierRegister submitted: {}", tx_id);
            Ok(())
        }


        Command::ClaimByCode { claim_code } => {
            let kp = load_keypair(&keyfile)?;
            let code = claim_code.trim().to_uppercase();
            let target_hash = hex::encode(blake3::hash(code.as_bytes()).as_bytes());

            // Look up locks by claim_secret_hash
            let cascade = client.get_cascade_details(&target_hash).await
                .context("looking up claim code")?;
            let locks = cascade["locks"].as_array()
                .ok_or_else(|| anyhow::anyhow!("claim code not found"))?;

            let now = chrono::Utc::now().timestamp();
            let actions: Vec<Action> = locks.iter()
                .filter(|l| l["status"].as_str() == Some("Pending"))
                .filter(|l| l["unlock_at"].as_i64().map_or(false, |u| now >= u))
                .filter_map(|l| {
                    let id_hex = l["lock_id"].as_str()?;
                    let lock_txid = TxId::from_hex(id_hex).ok()?;
                    Some(Action::TimeLockClaimWithSecret {
                        lock_id: TimeLockId(lock_txid),
                        claim_secret: code.clone(),
                    })
                })
                .collect();

            if actions.is_empty() {
                bail!("No claimable locks found for this code (may be immature or already claimed)");
            }
            let count = actions.len();
            let tx = build_and_sign(&kp, actions, &client).await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Claimed {} lock(s): {}", count, tx_id);
            Ok(())
        }
        Command::ExecutorWithdraw { lock_id } => {
            let kp = load_keypair(&keyfile)?;
            let lock_txid =
                TxId::from_hex(&lock_id).map_err(|e| anyhow::anyhow!("invalid lock id: {e}"))?;

            // The destination is the executor's own wallet (the keyfile being used).
            let destination = kp.account_id.clone();
            // The executor pubkey is the hex of the signing key.
            let executor_pubkey = hex::encode(&kp.public_key.0);

            let tx = build_and_sign(
                &kp,
                vec![Action::ExecutorWithdraw {
                    lock_id: TimeLockId(lock_txid),
                    destination: destination.clone(),
                    executor_pubkey,
                }],
                &client,
            )
            .await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("ExecutorWithdraw submitted: {}", tx_id);
            println!("Lock:        {}", lock_id);
            println!("Destination: {}", destination.to_b58());
            println!("Status: PendingExecutor — will finalize after configured delay.");
            println!("An alert email will be sent to alerts@misai.io.");
            Ok(())
        }


        Command::CreateInvoice { amount, expiry_days, payer, memo } => {
            let kp = load_keypair(&keyfile)?;
            let amount_chronos = kx_to_chronos(amount) as u64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let expiry = now + expiry_days * 86400;
            let id_data = bincode::serialize(&(kp.account_id.clone(), now, amount_chronos)).unwrap();
            let invoice_id: [u8; 32] = *blake3::hash(&id_data).as_bytes();

            let encrypted_memo = memo.as_ref().map(|m| m.as_bytes().to_vec());
            let memo_hash = memo.as_ref().map(|m| *blake3::hash(m.as_bytes()).as_bytes());

            let action = Action::CreateInvoice(CreateInvoiceAction {
                issuer_pubkey: kp.public_key.clone(),
                payer_pubkey: None, // OPEN invoice — payer resolution deferred to wallet GUI
                amount_chronos,
                invoice_id,
                expiry,
                encrypted_memo,
                memo_hash,
                authorized_payers: None,
            });

            let tx = build_and_sign(&kp, vec![action], &client).await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Invoice created. TxId: {}", tx_id);
            println!("Invoice ID: {}", hex::encode(invoice_id));
            Ok(())
        }

        Command::CreateCredit { beneficiary, ceiling, expiry_days, per_draw } => {
            let kp = load_keypair(&keyfile)?;
            let ceiling_chronos = kx_to_chronos(ceiling) as u64;
            let per_draw_chronos = per_draw.map(|v| kx_to_chronos(v) as u64);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let expiry = now + expiry_days * 86400;
            let id_data = bincode::serialize(&(kp.account_id.clone(), now, ceiling_chronos)).unwrap();
            let credit_id: [u8; 32] = *blake3::hash(&id_data).as_bytes();

            // Note: beneficiary pubkey resolution requires account lookup
            // For CLI, use an empty placeholder — full resolution in wallet GUI
            let _beneficiary_id = AccountId::from_b58(&beneficiary)
                .map_err(|e| anyhow::anyhow!("invalid beneficiary address: {e}"))?;

            let action = Action::CreateCredit(CreateCreditAction {
                grantor_pubkey: kp.public_key.clone(),
                beneficiary_pubkey: DilithiumPublicKey(Vec::new()),
                ceiling_chronos,
                per_draw_max_chronos: per_draw_chronos,
                expiry,
                credit_id,
                encrypted_terms: None,
                beneficiary_group: None,
            });

            let tx = build_and_sign(&kp, vec![action], &client).await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Credit authorization created. TxId: {}", tx_id);
            println!("Credit ID: {}", hex::encode(credit_id));
            Ok(())
        }

        Command::DrawCredit { credit_id, amount } => {
            let kp = load_keypair(&keyfile)?;
            let amount_chronos = kx_to_chronos(amount) as u64;
            let id_bytes = hex::decode(&credit_id).context("invalid credit_id hex")?;
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&id_bytes);

            let action = Action::DrawCredit(DrawCreditAction {
                beneficiary_pubkey: kp.public_key.clone(),
                credit_id: cid,
                amount_chronos,
            });

            let tx = build_and_sign(&kp, vec![action], &client).await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Credit drawn. TxId: {}", tx_id);
            Ok(())
        }

        Command::CreateDeposit { obligor, amount, rate_bps, term_days, compounding } => {
            let kp = load_keypair(&keyfile)?;
            let principal_chronos = kx_to_chronos(amount) as u64;
            let term_seconds = term_days * 86400;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let id_data = bincode::serialize(&(kp.account_id.clone(), now, principal_chronos)).unwrap();
            let deposit_id: [u8; 32] = *blake3::hash(&id_data).as_bytes();

            let comp = match compounding.as_str() {
                "daily" => Compounding::Daily,
                "monthly" => Compounding::Monthly,
                "annually" => Compounding::Annually,
                _ => Compounding::Simple,
            };

            let _obligor_id = AccountId::from_b58(&obligor)
                .map_err(|e| anyhow::anyhow!("invalid obligor address: {e}"))?;

            let action = Action::CreateDeposit(CreateDepositAction {
                depositor_pubkey: kp.public_key.clone(),
                obligor_pubkey: DilithiumPublicKey(Vec::new()),
                principal_chronos,
                rate_basis_points: rate_bps,
                term_seconds,
                compounding: comp,
                penalty_basis_points: None,
                deposit_id,
            });

            let tx = build_and_sign(&kp, vec![action], &client).await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Deposit created. TxId: {}", tx_id);
            println!("Deposit ID: {}", hex::encode(deposit_id));
            Ok(())
        }

        Command::CreateConditional { recipient, amount, attestor, min_attestors, expiry_days, fallback, condition_type, oracle_pair, oracle_trigger_threshold, oracle_trigger_direction, success_payment_wallet, success_payment_kx, expiry_seconds } => {
            let kp = load_keypair(&keyfile)?;
            let amount_chronos = kx_to_chronos(amount) as u64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let valid_until = now + expiry_days * 86400;
            let id_data = bincode::serialize(&(kp.account_id.clone(), now, amount_chronos)).unwrap();
            let type_v_id: [u8; 32] = *blake3::hash(&id_data).as_bytes();

            let fb = match fallback.as_str() {
                "void" => ConditionalFallback::Void,
                "escrow" => ConditionalFallback::Escrow,
                _ => ConditionalFallback::Return,
            };

            let _recipient_id = AccountId::from_b58(&recipient)
                .map_err(|e| anyhow::anyhow!("invalid recipient address: {e}"))?;

            let valid_until_final = if let Some(secs) = expiry_seconds {
                now + secs
            } else {
                valid_until
            };
            let spc = success_payment_kx.map(|kx| (kx * 1_000_000.0) as u64);
            let action = Action::CreateConditional(CreateConditionalAction {
                sender_pubkey: kp.public_key.clone(),
                recipient_pubkey: DilithiumPublicKey(Vec::new()),
                amount_chronos,
                attestor_pubkeys: Vec::new(),
                min_attestors,
                attestation_memo: None,
                valid_until: valid_until_final,
                fallback: fb,
                encrypted_terms: None,
                type_v_id,
                attestor_group: None,
                condition_type: condition_type.clone(),
                oracle_pair: oracle_pair.clone(),
                oracle_trigger_threshold: oracle_trigger_threshold.clone(),
                oracle_trigger_direction: oracle_trigger_direction.clone(),
                success_payment_wallet: success_payment_wallet.clone(),
                success_payment_chronos: spc,
            });

            let tx = build_and_sign(&kp, vec![action], &client).await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Conditional payment created. TxId: {}", tx_id);
            println!("Type V ID: {}", hex::encode(type_v_id));
            Ok(())
        }

        Command::AttestConditional { type_v_id } => {
            let kp = load_keypair(&keyfile)?;
            let id_bytes = hex::decode(&type_v_id).context("invalid type_v_id hex")?;
            let mut vid = [0u8; 32];
            vid.copy_from_slice(&id_bytes);

            let action = Action::AttestConditional(AttestConditionalAction {
                attestor_pubkey: kp.public_key.clone(),
                type_v_id: vid,
                attestation_memo: None,
                release_amount_chronos: None,
            });

            let tx = build_and_sign(&kp, vec![action], &client).await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Conditional attested. TxId: {}", tx_id);
            Ok(())
        }

        Command::CreateLedgerEntry { promise_id, entry_type, content_hash, summary } => {
            let kp = load_keypair(&keyfile)?;
            let pid_bytes = hex::decode(&promise_id).context("invalid promise_id hex")?;
            let mut pid = [0u8; 32];
            pid.copy_from_slice(&pid_bytes);
            let ch_bytes = hex::decode(&content_hash).context("invalid content_hash hex")?;
            let mut ch = [0u8; 32];
            ch.copy_from_slice(&ch_bytes);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let id_data = bincode::serialize(&(kp.account_id.clone(), now, &promise_id)).unwrap();
            let entry_id: [u8; 32] = *blake3::hash(&id_data).as_bytes();

            let et = match entry_type.as_str() {
                "decision" => LedgerEntryType::Decision,
                "summary" => LedgerEntryType::Summary,
                "sign-of-life" => LedgerEntryType::SignOfLife,
                "beneficiary-identified" => LedgerEntryType::BeneficiaryIdentified,
                "audit" => LedgerEntryType::Audit,
                "milestone" => LedgerEntryType::Milestone,
                "identity-verified" => LedgerEntryType::IdentityVerified,
                "identity-revoked" => LedgerEntryType::IdentityRevoked,
                _ => LedgerEntryType::Summary,
            };

            let action = Action::CreateLedgerEntry(CreateLedgerEntryAction {
                author_pubkey: kp.public_key.clone(),
                mandate_id: None,
                promise_id: Some(pid),
                entry_type: et,
                content_hash: ch,
                content_summary: summary.into_bytes(),
                promise_chain_hash: None,
                external_ref: None,
                entry_id,
            });

            let tx = build_and_sign(&kp, vec![action], &client).await?;
            let tx_id = client.send_transaction(&tx).await?;
            println!("Ledger entry created. TxId: {}", tx_id);
            println!("Entry ID: {}", hex::encode(entry_id));
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

    // Generate all four keypairs.
    let public_sale_kp = KeyPair::generate();
    let treasury_kp = KeyPair::generate();
    let humanity_kp = KeyPair::generate();
    let node_rewards_kp = KeyPair::generate();

    // Write each private keyfile.
    let ps_path = out_dir.join("public_sale.json");
    let tr_path = out_dir.join("treasury.json");
    let hu_path = out_dir.join("humanity.json");
    let nr_path = out_dir.join("node_rewards.json");

    std::fs::write(&ps_path, serde_json::to_string_pretty(&public_sale_kp)?)
        .with_context(|| format!("writing {}", ps_path.display()))?;
    std::fs::write(&tr_path, serde_json::to_string_pretty(&treasury_kp)?)
        .with_context(|| format!("writing {}", tr_path.display()))?;
    std::fs::write(&hu_path, serde_json::to_string_pretty(&humanity_kp)?)
        .with_context(|| format!("writing {}", hu_path.display()))?;
    std::fs::write(&nr_path, serde_json::to_string_pretty(&node_rewards_kp)?)
        .with_context(|| format!("writing {}", nr_path.display()))?;

    // Build GenesisParams (public keys only) and write genesis-params.json.
    // Generate milestone and reserve keypairs (v8.0)
    let milestone_kp = KeyPair::generate();
    let reserve_kp = KeyPair::generate();
    let params = GenesisParams {
        public_sale_key: public_sale_kp.public_key.clone(),
        treasury_key: treasury_kp.public_key.clone(),
        humanity_key: humanity_kp.public_key.clone(),
        node_rewards_key: node_rewards_kp.public_key.clone(),
        founder_key: chronx_core::types::DilithiumPublicKey(vec![0u8; 1312]),
        misai_key: chronx_core::types::DilithiumPublicKey(vec![0u8; 1312]),
        verifas_key: chronx_core::types::DilithiumPublicKey(vec![0u8; 1312]),
        milestone_key: milestone_kp.public_key.clone(),
        reserve_key: reserve_kp.public_key.clone(),
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
    println!("Node Rewards");
    println!("  Account:  {}", node_rewards_kp.account_id.to_b58());
    println!("  PubKey:   {}", hex::encode(&node_rewards_kp.public_key.0));
    println!("  Keyfile:  {}", nr_path.display());
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
        tx_version: 1,
        client_ref: None,
        fee_chronos: 0,
        expires_at: None,
        sender_public_key: Some(kp.public_key.clone()),
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

fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            return PathBuf::from(home).join(stripped);
        }
    }
    path.to_path_buf()
}
