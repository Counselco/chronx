use chronx_core::types::{DilithiumPublicKey, DilithiumSignature};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid public key length: expected {expected}, got {got}")]
    InvalidPublicKeyLength { expected: usize, got: usize },
}

/// Sign `message` with a Dilithium2 secret key.
/// Returns a detached signature.
pub fn sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<DilithiumSignature, SignatureError> {
    let sk = dilithium2::SecretKey::from_bytes(secret_key_bytes)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let sig = dilithium2::detached_sign(message, &sk);
    Ok(DilithiumSignature(sig.as_bytes().to_vec()))
}

/// Verify a detached Dilithium2 signature.
pub fn verify_signature(
    public_key: &DilithiumPublicKey,
    message: &[u8],
    signature: &DilithiumSignature,
) -> Result<(), SignatureError> {
    let pk = dilithium2::PublicKey::from_bytes(&public_key.0).map_err(|_| {
        SignatureError::InvalidPublicKeyLength {
            expected: dilithium2::public_key_bytes(),
            got: public_key.0.len(),
        }
    })?;
    let sig = dilithium2::DetachedSignature::from_bytes(&signature.0)
        .map_err(|_| SignatureError::InvalidSignature)?;
    dilithium2::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| SignatureError::InvalidSignature)
}

/// Stateless signer helper used by transaction builders.
pub struct ChronxSigner {
    pub public_key: DilithiumPublicKey,
    secret_key_bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl ChronxSigner {
    pub fn from_secret_key_bytes(sk_bytes: Vec<u8>, pk_bytes: Vec<u8>) -> Self {
        Self {
            public_key: DilithiumPublicKey(pk_bytes),
            secret_key_bytes: zeroize::Zeroizing::new(sk_bytes),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<DilithiumSignature, SignatureError> {
        sign(&self.secret_key_bytes, message)
    }

    pub fn verify(&self, message: &[u8], sig: &DilithiumSignature) -> Result<(), SignatureError> {
        verify_signature(&self.public_key, message, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_dilithium::dilithium2;

    #[test]
    fn sign_verify_round_trip() {
        let (pk, sk) = dilithium2::keypair();
        let pk_bytes = DilithiumPublicKey(pk.as_bytes().to_vec());
        let message = b"the ledger for long-horizon human promises";

        let signer =
            ChronxSigner::from_secret_key_bytes(sk.as_bytes().to_vec(), pk.as_bytes().to_vec());
        let sig = signer.sign(message).unwrap();
        assert!(verify_signature(&pk_bytes, message, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let (pk, sk) = dilithium2::keypair();
        let pk_bytes = DilithiumPublicKey(pk.as_bytes().to_vec());
        let signer =
            ChronxSigner::from_secret_key_bytes(sk.as_bytes().to_vec(), pk.as_bytes().to_vec());
        let sig = signer.sign(b"original").unwrap();
        assert!(verify_signature(&pk_bytes, b"tampered", &sig).is_err());
    }
}
