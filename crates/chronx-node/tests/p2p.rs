//! P2P integration test for chronx-node.
//!
//! Starts two node processes:
//!   Node A — bootstrap node (no peers)
//!   Node B — joins by dialing node A
//!
//! Submits a transaction to node A and verifies that node B receives and
//! applies it via GossipSub propagation.
//!
//! Run with:
//!   cargo test -p chronx-node --test p2p

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
) -> Option<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let resp = client.post(url).json(&body).send().await.ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;
    if json.get("error").is_some() {
        return None;
    }
    Some(json["result"].clone())
}

async fn rpc_call_unwrap(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    rpc_call(client, url, method, params)
        .await
        .unwrap_or_else(|| panic!("RPC call {method} returned error/none"))
}

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

async fn get_peer_multiaddr(client: &reqwest::Client, url: &str) -> String {
    let result = rpc_call_unwrap(client, url, "chronx_getNetworkInfo", serde_json::json!([])).await;
    result["peer_multiaddr"]
        .as_str()
        .expect("peer_multiaddr field")
        .to_string()
}

async fn get_balance(client: &reqwest::Client, url: &str, account_id: &str) -> u128 {
    let result =
        rpc_call_unwrap(client, url, "chronx_getBalance", serde_json::json!([account_id])).await;
    result.as_str().unwrap().parse().unwrap()
}

async fn get_nonce(client: &reqwest::Client, url: &str, account_id: &str) -> u64 {
    let result =
        rpc_call_unwrap(client, url, "chronx_getAccount", serde_json::json!([account_id])).await;
    if result.is_null() {
        return 0;
    }
    result["nonce"].as_u64().unwrap_or(0)
}

async fn get_dag_tips(client: &reqwest::Client, url: &str) -> Vec<TxId> {
    let result =
        rpc_call_unwrap(client, url, "chronx_getDagTips", serde_json::json!([])).await;
    let hex_list: Vec<String> = serde_json::from_value(result).unwrap();
    hex_list.iter().map(|h| TxId::from_hex(h).unwrap()).collect()
}

async fn send_tx(client: &reqwest::Client, url: &str, tx: &Transaction) -> String {
    let bytes = bincode::serialize(tx).unwrap();
    let tx_hex = hex::encode(bytes);
    let result =
        rpc_call_unwrap(client, url, "chronx_sendTransaction", serde_json::json!([tx_hex])).await;
    result.as_str().unwrap().to_string()
}

/// Poll until a tx is visible via `chronx_getTransaction` on the given node.
async fn wait_for_tx(
    client: &reqwest::Client,
    url: &str,
    tx_id: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let result = rpc_call(
            client,
            url,
            "chronx_getTransaction",
            serde_json::json!([tx_id]),
        )
        .await;
        if let Some(v) = result {
            if !v.is_null() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    false
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
    };
    let body_bytes = tx.body_bytes();
    tx.pow_nonce = mine_pow(&body_bytes, 0);
    tx.tx_id = tx_id_from_body(&body_bytes);
    tx.signatures = vec![kp.sign(&body_bytes)];
    tx
}

// ── Helpers to spawn nodes ────────────────────────────────────────────────────

fn genesis_params_for(dir: &PathBuf) -> (KeyPair, PathBuf) {
    let public_sale_kp = KeyPair::generate();
    let treasury_kp = KeyPair::generate();
    let humanity_kp = KeyPair::generate();
    let params = GenesisParams {
        public_sale_key: public_sale_kp.public_key.clone(),
        treasury_key:    treasury_kp.public_key.clone(),
        humanity_key:    humanity_kp.public_key.clone(),
    };
    let params_path = dir.join("genesis-params.json");
    std::fs::write(&params_path, serde_json::to_string(&params).unwrap()).unwrap();
    (public_sale_kp, params_path)
}

fn spawn_node(
    data_dir: &PathBuf,
    rpc_port: u16,
    p2p_port: u16,
    params_path: &PathBuf,
    bootstrap: Option<&str>,
) -> Child {
    let node_bin = env!("CARGO_BIN_EXE_chronx-node");
    let mut cmd = Command::new(node_bin);
    cmd.args([
        "--data-dir",       data_dir.join("state").to_str().unwrap(),
        "--rpc-addr",       &format!("127.0.0.1:{}", rpc_port),
        "--p2p-listen",     &format!("/ip4/127.0.0.1/tcp/{}", p2p_port),
        "--genesis-params", params_path.to_str().unwrap(),
        "--pow-difficulty", "0",
    ]);
    if let Some(bs) = bootstrap {
        cmd.args(["--bootstrap", bs]);
    }
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn chronx-node")
}

// ── P2P test ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn p2p_gossip_propagation() {
    let http = reqwest::Client::new();

    // ── 1. Shared genesis (both nodes start from the same genesis) ────────────
    let base_dir = std::env::temp_dir().join(format!("chronx_p2p_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base_dir);

    let dir_a = base_dir.join("node_a");
    let dir_b = base_dir.join("node_b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    // Both nodes share genesis params so they agree on the genesis state.
    let (public_sale_kp, params_path_a) = genesis_params_for(&dir_a);
    // Node B uses the same genesis-params.json (copy it).
    let params_path_b = dir_b.join("genesis-params.json");
    std::fs::copy(&params_path_a, &params_path_b).unwrap();

    // ── 2. Start node A (bootstrap node, no peers) ────────────────────────────
    let rpc_a = free_port();
    let p2p_a = free_port();
    let url_a = format!("http://127.0.0.1:{}", rpc_a);

    let child_a = spawn_node(&dir_a, rpc_a, p2p_a, &params_path_a, None);
    let _guard_a = NodeGuard { child: child_a, data_dir: dir_a };

    assert!(
        wait_for_rpc(&http, &url_a, Duration::from_secs(20)).await,
        "node A did not become ready"
    );

    // ── 3. Discover node A's peer multiaddr ───────────────────────────────────
    let peer_multiaddr_a = get_peer_multiaddr(&http, &url_a).await;
    assert!(
        peer_multiaddr_a.contains("/p2p/"),
        "expected /p2p/ in multiaddr, got: {peer_multiaddr_a}"
    );

    // ── 4. Start node B, bootstrapping off node A ─────────────────────────────
    let rpc_b = free_port();
    let p2p_b = free_port();
    let url_b = format!("http://127.0.0.1:{}", rpc_b);

    let child_b = spawn_node(&dir_b, rpc_b, p2p_b, &params_path_b, Some(&peer_multiaddr_a));
    let _guard_b = NodeGuard { child: child_b, data_dir: base_dir };

    assert!(
        wait_for_rpc(&http, &url_b, Duration::from_secs(20)).await,
        "node B did not become ready"
    );

    // ── 5. Wait for GossipSub mesh to form ───────────────────────────────────
    // Heartbeat fires every 1 second; wait 4s to be safe.
    tokio::time::sleep(Duration::from_secs(4)).await;

    // ── 6. Submit a transfer on node A ────────────────────────────────────────
    let ps_b58 = public_sale_kp.account_id.to_b58();
    let alice = KeyPair::generate();

    let tips = get_dag_tips(&http, &url_a).await;
    let nonce = get_nonce(&http, &url_a, &ps_b58).await;
    let tx = build_tx(
        &public_sale_kp,
        nonce,
        tips,
        vec![Action::Transfer {
            to: alice.account_id.clone(),
            amount: 500 * CHRONOS_PER_KX,
        }],
    );
    let tx_id_hex = send_tx(&http, &url_a, &tx).await;

    // ── 7. Verify node A applied it ───────────────────────────────────────────
    assert!(
        wait_for_tx(&http, &url_a, &tx_id_hex, Duration::from_secs(5)).await,
        "node A did not apply the transaction"
    );

    // ── 8. Verify node B received and applied it via gossip ───────────────────
    assert!(
        wait_for_tx(&http, &url_b, &tx_id_hex, Duration::from_secs(10)).await,
        "node B did not receive the transaction via GossipSub within 10 seconds"
    );

    // ── 9. Assert state consistency: both nodes agree on alice's balance ───────
    let bal_a = get_balance(&http, &url_a, &alice.account_id.to_b58()).await;
    let bal_b = get_balance(&http, &url_b, &alice.account_id.to_b58()).await;
    assert_eq!(bal_a, 500 * CHRONOS_PER_KX, "node A: wrong alice balance");
    assert_eq!(bal_b, 500 * CHRONOS_PER_KX, "node B: wrong alice balance");
    assert_eq!(bal_a, bal_b, "nodes disagree on alice's balance");
}
