use chronx_core::types::DilithiumPublicKey;
use serde::{Deserialize, Serialize};

/// Public keys for the genesis allocations.
///
/// In production these come from a secure key ceremony;
/// in tests, fresh keypairs are generated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisParams {
    /// Dilithium2 public key that controls the public sale allocation.
    pub public_sale_key: DilithiumPublicKey,
    /// Dilithium2 public key that controls treasury time-lock claims.
    pub treasury_key: DilithiumPublicKey,
    /// Dilithium2 public key registered for the humanity stake.
    pub humanity_key: DilithiumPublicKey,
    /// Dilithium2 public key that controls node rewards time-lock claims.
    #[serde(default = "default_dilithium_key")]
    pub node_rewards_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Founder allocation .
    #[serde(default = "default_dilithium_key")]
    pub founder_key: DilithiumPublicKey,
    /// Dilithium2 public key for the MISAI Bond allocation .
    #[serde(default = "default_dilithium_key")]
    pub misai_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Verifas Bond allocation .
    #[serde(default = "default_dilithium_key")]
    pub verifas_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Milestone 2076 wallet .
    #[serde(default = "default_dilithium_key")]
    pub milestone_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Protocol Reserve wallet .
    #[serde(default = "default_dilithium_key")]
    pub reserve_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Faucet allocation .
    #[serde(default = "default_dilithium_key")]
    pub faucet_key: DilithiumPublicKey,
    /// Immutable axioms text, stored in genesis metadata .
    #[serde(default)]
    pub axioms: Option<String>,
    #[serde(default = "default_rate_limit_tx")]
    pub rate_limit_tx_per_wallet_per_minute: u64,
    #[serde(default = "default_rate_limit_loan")]
    pub rate_limit_loan_actions_per_wallet_per_day: u64,
    #[serde(default = "default_channel_threshold")]
    pub channel_threshold_daily_tx: u64,
    #[serde(default = "default_channel_min_lock")]
    pub channel_open_min_lock_kx: u64,
    #[serde(default = "default_sweep_loan")]
    pub sweep_loan_interval_seconds: u64,
    #[serde(default = "default_sweep_email")]
    pub sweep_email_lock_interval_seconds: u64,
    #[serde(default = "default_sweep_timelock")]
    pub sweep_matured_timelock_interval_seconds: u64,
    #[serde(default = "default_loan_min_settlement")]
    pub loan_min_settlement_chronos: u64,
    #[serde(default = "default_sweep_humanity")]
    pub sweep_humanity_stake_interval_seconds: u64,
    #[serde(default = "default_sweep_guardian")]
    pub sweep_guardian_transition_interval_seconds: u64,
    #[serde(default = "default_sweep_promise")]
    pub sweep_promise_chain_interval_seconds: u64,
    #[serde(default = "default_sweep_executor")]
    pub sweep_executor_interval_seconds: u64,
    #[serde(default = "default_pay_as_max_usd")]
    pub pay_as_max_usd: f64,
    #[serde(default = "default_pay_as_enabled")]
    pub pay_as_enabled: bool,
}

/// Default placeholder key — real genesis must supply real keys.
fn default_dilithium_key() -> DilithiumPublicKey {
    DilithiumPublicKey(vec![0u8; 1312])
}

fn default_rate_limit_tx() -> u64 { 10 }
fn default_rate_limit_loan() -> u64 { 100 }
fn default_channel_threshold() -> u64 { 1000 }
fn default_channel_min_lock() -> u64 { 1 }
fn default_sweep_loan() -> u64 { 3600 }
fn default_sweep_email() -> u64 { 300 }
fn default_sweep_timelock() -> u64 { 60 }
fn default_loan_min_settlement() -> u64 { 1000 }

fn default_sweep_humanity() -> u64 { 86400 }
fn default_sweep_guardian() -> u64 { 3600 }
fn default_sweep_promise() -> u64 { 86400 }
fn default_sweep_executor() -> u64 { 60 }

fn default_pay_as_max_usd() -> f64 { 100.0 }
fn default_pay_as_enabled() -> bool { true }
