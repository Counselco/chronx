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
    /// Dilithium2 public key for the Founder allocation (v5.0).
    #[serde(default = "default_dilithium_key")]
    pub founder_key: DilithiumPublicKey,
    /// Dilithium2 public key for the MISAI Bond allocation (v5.0).
    #[serde(default = "default_dilithium_key")]
    pub misai_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Verifas Bond allocation (v5.0).
    #[serde(default = "default_dilithium_key")]
    pub verifas_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Milestone 2076 wallet (v8.0).
    #[serde(default = "default_dilithium_key")]
    pub milestone_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Protocol Reserve wallet (v8.0).
    #[serde(default = "default_dilithium_key")]
    pub reserve_key: DilithiumPublicKey,
    /// Dilithium2 public key for the Faucet allocation (Genesis 8).
    #[serde(default = "default_dilithium_key")]
    pub faucet_key: DilithiumPublicKey,
    /// Immutable axioms text, stored in genesis metadata (v5.0).
    #[serde(default)]
    pub axioms: Option<String>,
}

/// Default placeholder key — real genesis must supply real keys.
fn default_dilithium_key() -> DilithiumPublicKey {
    DilithiumPublicKey(vec![0u8; 1312])
}
