//! End-to-end smoke test for chronx-node.
//!
//! Starts a real node process with a fresh genesis, submits transactions via
//! JSON-RPC, and asserts state changes are correctly reflected.
//!
//! Run with:
//!   cargo test -p chronx-node --test smoke

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chronx_core::constants::CHRONOS_PER_KX;
use chronx_core::transaction::{Action, AuthScheme, Transaction};
use chronx_core::types::TxId;
use chronx_crypto::{hash::tx_id_from_body, mine_pow, KeyPair};
use chronx_genesis::GenesisParams;

// ── Node lifecycle ────────────────────────────────────────────────────────────

struct NodeGuard {
    child: Child,
    data_dir: PathBuf,
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Find a free TCP port on loopback.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ── RPC helpers ───────────────────────────────────────────────────────────────

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("RPC call {method} failed: {e}"));
    let json: serde_json::Value = resp.json().await.expect("parse RPC JSON");
    if let Some(err) = json.get("error") {
        panic!("RPC error from {method}: {err}");
    }
    json["result"].clone()
}

/// Poll until the RPC server responds or the timeout elapses.
async fn wait_for_rpc(client: &reqwest::Client, url: &str, timeout: Duration) -> bool {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "chronx_getGenesisInfo",
        "params": [],
        "id": 1
    });
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(resp) = client.post(url).json(&body).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn get_balance(client: &reqwest::Client, url: &str, account_id: &str) -> u128 {
    let result = rpc_call(client, url, "chronx_getBalance", serde_json::json!([account_id])).await;
    result.as_str().unwrap().parse().expect("parse balance")
}

async fn get_nonce(client: &reqwest::Client, url: &str, account_id: &str) -> u64 {
    let result =
        rpc_call(client, url, "chronx_getAccount", serde_json::json!([account_id])).await;
    if result.is_null() {
        return 0;
    }
    result["nonce"].as_u64().expect("nonce field")
}

async fn get_dag_tips(client: &reqwest::Client, url: &str) -> Vec<TxId> {
    let result = rpc_call(client, url, "chronx_getDagTips", serde_json::json!([])).await;
    let hex_list: Vec<String> = serde_json::from_value(result).expect("tips list");
    hex_list
        .iter()
        .map(|h| TxId::from_hex(h).expect("tip hex"))
        .collect()
}

async fn send_tx(client: &reqwest::Client, url: &str, tx: &Transaction) -> String {
    let bytes = bincode::serialize(tx).expect("serialize tx");
    let tx_hex = hex::encode(bytes);
    let result =
        rpc_call(client, url, "chronx_sendTransaction", serde_json::json!([tx_hex])).await;
    result.as_str().expect("tx_id string").to_string()
}

// ── Transaction builder ───────────────────────────────────────────────────────

fn build_tx(kp: &KeyPair, nonce: u64, parents: Vec<TxId>, actions: Vec<Action>) -> Transaction {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut tx = Transaction {
        tx_id: TxId::from_bytes([0u8; 32]),
        parents,
        timestamp: ts,
        nonce,
        from: kp.account_id.clone(),
        actions,
        pow_nonce: 0,
        signatures: vec![],
        auth_scheme: AuthScheme::SingleSig,
        tx_version: 1,
        client_ref: None,
        fee_chronos: 0,
        expires_at: None,
    };
    let body_bytes = tx.body_bytes();
    tx.pow_nonce = mine_pow(&body_bytes, 0); // difficulty 0 — instant
    tx.tx_id = tx_id_from_body(&body_bytes);
    tx.signatures = vec![kp.sign(&body_bytes)];
    tx
}

// ── Smoke test ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn smoke_transfer_and_timelock() {
    // ── 1. Prepare temp dir and genesis params ────────────────────────────────
    let data_dir =
        std::env::temp_dir().join(format!("chronx_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    std::fs::create_dir_all(&data_dir).unwrap();

    let public_sale_kp = KeyPair::generate();
    let treasury_kp = KeyPair::generate();
    let humanity_kp = KeyPair::generate();

    let params = GenesisParams {
        public_sale_key: public_sale_kp.public_key.clone(),
        treasury_key:    treasury_kp.public_key.clone(),
        humanity_key:    humanity_kp.public_key.clone(),
    };
    let params_path = data_dir.join("genesis-params.json");
    std::fs::write(&params_path, serde_json::to_string(&params).unwrap()).unwrap();

    // ── 2. Start node ─────────────────────────────────────────────────────────
    let rpc_port = free_port();
    let p2p_port = free_port();
    let rpc_url = format!("http://127.0.0.1:{}", rpc_port);

    let node_bin = env!("CARGO_BIN_EXE_chronx-node");
    let child = Command::new(node_bin)
        .args([
            "--data-dir",       data_dir.join("state").to_str().unwrap(),
            "--rpc-addr",       &format!("127.0.0.1:{}", rpc_port),
            "--p2p-listen",     &format!("/ip4/127.0.0.1/tcp/{}", p2p_port),
            "--genesis-params", params_path.to_str().unwrap(),
            "--pow-difficulty", "0",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn chronx-node");

    let _guard = NodeGuard { child, data_dir };

    // ── 3. Wait for RPC ready ─────────────────────────────────────────────────
    let http = reqwest::Client::new();
    assert!(
        wait_for_rpc(&http, &rpc_url, Duration::from_secs(20)).await,
        "chronx-node did not become ready within 20 seconds"
    );

    // ── 4. Verify genesis balance for public_sale ─────────────────────────────
    let ps_b58 = public_sale_kp.account_id.to_b58();
    let genesis_bal = get_balance(&http, &rpc_url, &ps_b58).await;
    assert_eq!(
        genesis_bal,
        7_268_000_000u128 * CHRONOS_PER_KX,
        "public_sale genesis balance should be 7,268,000,000 KX"
    );

    // ── 5. Transfer 1000 KX public_sale → alice ───────────────────────────────
    let alice = KeyPair::generate();
    let tips = get_dag_tips(&http, &rpc_url).await;
    let nonce = get_nonce(&http, &rpc_url, &ps_b58).await;
    let tx1 = build_tx(
        &public_sale_kp,
        nonce,
        tips,
        vec![Action::Transfer {
            to: alice.account_id.clone(),
            amount: 1_000 * CHRONOS_PER_KX,
        }],
    );
    send_tx(&http, &rpc_url, &tx1).await;

    // Allow time for the node's main loop to process the tx.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // ── 6. Verify alice received 1000 KX ──────────────────────────────────────
    let alice_b58 = alice.account_id.to_b58();
    let alice_bal = get_balance(&http, &rpc_url, &alice_b58).await;
    assert_eq!(alice_bal, 1_000 * CHRONOS_PER_KX, "alice should have 1000 KX");

    let ps_bal_after = get_balance(&http, &rpc_url, &ps_b58).await;
    assert_eq!(
        ps_bal_after,
        (7_268_000_000u128 - 1_000) * CHRONOS_PER_KX,
        "public_sale should be reduced by 1000 KX"
    );

    // ── 7. Create a timelock public_sale → bob (200 KX, unlock in 1 year) ──────
    // Note: alice's account was auto-created with an empty pubkey when she
    // received funds (Transfer doesn't carry recipient pubkey), so alice cannot
    // sign transactions yet. We test TimeLockCreate from the well-keyed
    // public_sale account instead.
    let bob = KeyPair::generate();
    let unlock_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 86_400 * 365;

    let tips2 = get_dag_tips(&http, &rpc_url).await;
    let ps_nonce2 = get_nonce(&http, &rpc_url, &ps_b58).await;
    let tx2 = build_tx(
        &public_sale_kp,
        ps_nonce2,
        tips2,
        vec![Action::TimeLockCreate {
            recipient: bob.public_key.clone(),
            amount: 200 * CHRONOS_PER_KX,
            unlock_at,
            memo: Some("smoke test timelock".into()),
            cancellation_window_secs: None,
            notify_recipient: None,
            tags: None,
            private: None,
            expiry_policy: None,
            split_policy: None,
            claim_attempts_max: None,
            recurring: None,
            extension_data: None,
            oracle_hint: None,
            jurisdiction_hint: None,
            governance_proposal_id: None,
            client_ref: None,
        }],
    );
    send_tx(&http, &rpc_url, &tx2).await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    // ── 8. Verify public_sale's balance is now reduced by a further 200 KX ────
    let ps_bal_final = get_balance(&http, &rpc_url, &ps_b58).await;
    assert_eq!(
        ps_bal_final,
        (7_268_000_000u128 - 1_000 - 200) * CHRONOS_PER_KX,
        "public_sale should be reduced by 1000 + 200 KX"
    );
}
