use chronx_core::types::DilithiumPublicKey;
use serde::{Deserialize, Serialize};

/// Public keys for the three genesis allocations.
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
    /// This key is unlockable Jan 1, 2127 — or recoverable via the
    /// ChronX recovery protocol if the key is lost before then.
    pub humanity_key: DilithiumPublicKey,
}
