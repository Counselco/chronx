use anyhow::{bail, Context};

use chronx_core::transaction::Transaction;
use chronx_core::types::TxId;

/// Simple JSON-RPC 2.0 client used by the wallet to talk to a running node.
///
/// Uses raw HTTP POST with serde_json rather than the full jsonrpsee client
/// to keep the wallet binary lean and dependency-minimal.
pub struct WalletRpcClient {
    url: String,
    client: reqwest::Client,
}

// ── We use reqwest for HTTP JSON-RPC calls ─────────────────────────────────
// Add reqwest to Cargo.toml in chronx-wallet when wiring this up.
// For now, we provide the struct with stub implementations that will be
// replaced once reqwest is added to the workspace.

impl WalletRpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Call a JSON-RPC method and return the `result` field.
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("connecting to node at {}", self.url))?;

        let json: serde_json::Value = resp.json().await.context("parsing RPC response")?;

        if let Some(err) = json.get("error") {
            bail!("RPC error: {}", err);
        }

        Ok(json["result"].clone())
    }

    /// Get account nonce.
    pub async fn get_nonce(&self, account_id: &str) -> anyhow::Result<u64> {
        let result = self
            .call(
                "chronx_getAccount",
                serde_json::json!([account_id]),
            )
            .await?;

        if result.is_null() {
            // New account — nonce is 0.
            return Ok(0);
        }

        let nonce = result["nonce"]
            .as_u64()
            .context("missing nonce in account response")?;
        Ok(nonce)
    }

    /// Get account balance in Chronos.
    pub async fn get_balance(&self, account_id: &str) -> anyhow::Result<u128> {
        let result = self
            .call(
                "chronx_getBalance",
                serde_json::json!([account_id]),
            )
            .await?;

        let bal_str = result.as_str().context("expected string balance")?;
        let bal: u128 = bal_str.parse().context("parsing balance")?;
        Ok(bal)
    }

    /// Get current DAG tips as TxIds.
    pub async fn get_dag_tips(&self) -> anyhow::Result<Vec<TxId>> {
        let result = self
            .call("chronx_getDagTips", serde_json::json!([]))
            .await?;

        let hex_list: Vec<String> =
            serde_json::from_value(result).context("parsing tips response")?;

        hex_list
            .iter()
            .map(|h| {
                TxId::from_hex(h).map_err(|e| anyhow::anyhow!("invalid tip hex: {e}"))
            })
            .collect()
    }

    /// Submit a signed transaction. Returns the TxId hex.
    pub async fn send_transaction(&self, tx: &Transaction) -> anyhow::Result<String> {
        let bytes = bincode::serialize(tx).context("serializing transaction")?;
        let tx_hex = hex::encode(&bytes);

        let result = self
            .call("chronx_sendTransaction", serde_json::json!([tx_hex]))
            .await?;

        result
            .as_str()
            .map(|s| s.to_string())
            .context("expected tx_id string from sendTransaction")
    }

    /// Get genesis/protocol info.
    pub async fn get_genesis_info(&self) -> anyhow::Result<chronx_rpc::RpcGenesisInfo> {
        let result = self
            .call("chronx_getGenesisInfo", serde_json::json!([]))
            .await?;
        let info: chronx_rpc::RpcGenesisInfo =
            serde_json::from_value(result).context("parsing genesis info")?;
        Ok(info)
    }
}
