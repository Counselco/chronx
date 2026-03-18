use chronx_core::types::{AccountId, DilithiumPublicKey};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::hash::account_id_from_pubkey;

/// A ChronX keypair: Dilithium2 public + secret keys with derived AccountId.
///
/// The secret key is held in a `Zeroizing<Vec<u8>>` to wipe memory on drop.
#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    pub account_id: AccountId,
    pub public_key: DilithiumPublicKey,
    secret_key: Vec<u8>,
}

impl KeyPair {
    /// Generate a fresh Dilithium2 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium2::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let account_id = account_id_from_pubkey(&pk_bytes);
        Self {
            account_id,
            public_key: DilithiumPublicKey(pk_bytes),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    /// Sign `message` using this keypair's secret key.
    pub fn sign(&self, message: &[u8]) -> chronx_core::types::DilithiumSignature {
        let sk = Zeroizing::new(self.secret_key.clone());
        crate::dilithium::sign(&sk, message).expect("sign with valid secret key is infallible")
    }

    /// Return a read-only view of the secret key bytes.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    /// Restore a KeyPair from raw bytes (e.g. loaded from wallet file).
    pub fn from_raw(pk_bytes: Vec<u8>, sk_bytes: Vec<u8>) -> Self {
        let account_id = account_id_from_pubkey(&pk_bytes);
        Self {
            account_id,
            public_key: DilithiumPublicKey(pk_bytes),
            secret_key: sk_bytes,
        }
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // Zeroize the secret key bytes on drop.
        use zeroize::Zeroize;
        self.secret_key.zeroize();
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyPair {{ account_id: {:?} }}", self.account_id)
    }
}
