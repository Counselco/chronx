/// Submit a ChildChainRecord to the ChronX DAG.
///
/// Usage:
///   oracom-submit --keyfile oracom-oracle-key.json \
///     --node http://127.0.0.1:8545 \
///     --namespace oracom \
///     --record-id "oracom:weather:noaa-lax-20260328" \
///     --payload '{"source_id":"noaa-weather","value":12.4,...}' \
///     [--previous-record-id "oracom:weather:noaa-lax-20260327"]
///
/// The binary handles: key loading, tx construction, PoW mining, signing, RPC submission.
/// Designed to be called by the oracom-harvester Python scripts.

use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::Parser;
use serde::Deserialize;

use chronx_core::constants::POW_INITIAL_DIFFICULTY;
use chronx_core::transaction::{Action, AuthScheme, Transaction, TransactionBody};
use chronx_core::types::{AccountId, DilithiumPublicKey, TxId};
use chronx_crypto::{hash::tx_id_from_body, mine_pow};

#[derive(Parser)]
#[command(name = "oracom-submit", about = "Submit a ChildChainRecord to ChronX")]
struct Args {
    /// Path to the Oracom oracle keypair JSON file.
    #[arg(long)]
    keyfile: PathBuf,

    /// ChronX node RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    node: String,

    /// Child chain namespace.
    #[arg(long, default_value = "oracom")]
    namespace: String,

    /// Unique record ID (e.g. "oracom:weather:noaa-lax-20260328").
    #[arg(long)]
    record_id: String,

    /// JSON payload string (the data record).
    #[arg(long)]
    payload: String,

    /// Optional previous record ID for chaining.
    #[arg(long)]
    previous_record_id: Option<String>,
}

#[derive(Deserialize)]
struct OracleKey {
    public_key: String,
    secret_key: String,
    account_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load oracle key
    let key_json = std::fs::read_to_string(&args.keyfile)
        .with_context(|| format!("reading keyfile {}", args.keyfile.display()))?;
    let oracle_key: OracleKey = serde_json::from_str(&key_json).context("parsing keyfile")?;

    let pk_bytes = hex::decode(&oracle_key.public_key).context("decoding public key hex")?;
    let sk_bytes = hex::decode(&oracle_key.secret_key).context("decoding secret key hex")?;
    let account_id = AccountId::from_b58(&oracle_key.account_id)
        .map_err(|e| anyhow::anyhow!("invalid account_id: {e}"))?;

    // Build keypair
    let kp = chronx_crypto::KeyPair::from_raw(pk_bytes.clone(), sk_bytes);

    // Compute BLAKE3 hash of payload
    let payload_hash: [u8; 32] = *blake3::hash(args.payload.as_bytes()).as_bytes();

    // Create owner signature over the payload
    let owner_signature = kp.sign(args.payload.as_bytes());

    // Build the action
    let action = Action::ChildChainRecord {
        namespace: args.namespace.clone(),
        record_id: args.record_id.clone(),
        payload: args.payload.clone(),
        payload_hash,
        owner_signature,
        previous_record_id: args.previous_record_id.clone(),
    };

    // Fetch nonce and DAG tips from node
    let client = reqwest::Client::new();

    let nonce = rpc_get_nonce(&client, &args.node, &oracle_key.account_id).await?;
    let tips = rpc_get_dag_tips(&client, &args.node).await?;
    let timestamp = chrono::Utc::now().timestamp();

    // Build transaction body
    let actions = vec![action];
    let auth_scheme = AuthScheme::SingleSig;
    let body = TransactionBody {
        parents: &tips,
        timestamp,
        nonce,
        from: &account_id,
        actions: &actions,
        auth_scheme: &auth_scheme,
    };
    let body_bytes = bincode::serialize(&body).context("serializing tx body")?;

    // Mine PoW
    let pow_nonce = mine_pow(&body_bytes, POW_INITIAL_DIFFICULTY);

    // Sign
    let signature = kp.sign(&body_bytes);

    // Compute tx_id
    let tx_id = tx_id_from_body(&body_bytes);

    // Assemble transaction
    let tx = Transaction {
        tx_id,
        parents: tips,
        timestamp,
        nonce,
        from: account_id,
        actions,
        pow_nonce,
        signatures: vec![signature],
        auth_scheme,
        tx_version: 1,
        client_ref: None,
        fee_chronos: 0,
        expires_at: None,
        sender_public_key: Some(DilithiumPublicKey(pk_bytes)),
    };

    // Serialize and submit
    let tx_bytes = bincode::serialize(&tx).context("serializing transaction")?;
    let tx_hex = hex::encode(&tx_bytes);
    let tx_id_str = rpc_send_transaction(&client, &args.node, &tx_hex).await?;

    // Output JSON result for Python to parse
    let result = serde_json::json!({
        "tx_id": tx_id_str,
        "namespace": args.namespace,
        "record_id": args.record_id,
        "payload_hash": hex::encode(payload_hash),
    });
    println!("{}", serde_json::to_string(&result)?);

    Ok(())
}

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let resp = client.post(url).json(&body).send().await
        .with_context(|| format!("RPC call to {}", url))?;
    let json: serde_json::Value = resp.json().await.context("parsing RPC response")?;
    if let Some(err) = json.get("error") {
        bail!("RPC error: {}", err);
    }
    Ok(json["result"].clone())
}

async fn rpc_get_nonce(client: &reqwest::Client, url: &str, account_id: &str) -> anyhow::Result<u64> {
    let result = rpc_call(client, url, "chronx_getAccount", serde_json::json!([account_id])).await?;
    if result.is_null() {
        return Ok(0);
    }
    result["nonce"].as_u64().context("missing nonce in account response")
}

async fn rpc_get_dag_tips(client: &reqwest::Client, url: &str) -> anyhow::Result<Vec<TxId>> {
    let result = rpc_call(client, url, "chronx_getDagTips", serde_json::json!([])).await?;
    let hex_list: Vec<String> = serde_json::from_value(result).context("parsing tips")?;
    hex_list.iter()
        .map(|h| TxId::from_hex(h).map_err(|e| anyhow::anyhow!("invalid tip: {e}")))
        .collect()
}

async fn rpc_send_transaction(client: &reqwest::Client, url: &str, tx_hex: &str) -> anyhow::Result<String> {
    let result = rpc_call(client, url, "chronx_sendTransaction", serde_json::json!([tx_hex])).await?;
    result.as_str().map(|s| s.to_string()).context("expected tx_id from sendTransaction")
}
