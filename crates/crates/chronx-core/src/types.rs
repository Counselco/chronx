use serde::{Deserialize, Serialize};
use std::fmt;

/// Balance in Chronos (1 KX = 1_000_000 Chronos). u128 supports the full
/// supply of 8_270_000_000_000_000 Chronos with room to spare.
pub type Balance = u128;

/// Unix timestamp (seconds, UTC).
pub type Timestamp = i64;

/// Transaction sequence number per account (monotonically increasing).
pub type Nonce = u64;

// ── AccountId ────────────────────────────────────────────────────────────────

/// 32-byte account identifier derived as BLAKE3(dilithium_public_key).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId(pub [u8; 32]);

impl AccountId {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Base-58 encoded string representation.
    pub fn to_b58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    pub fn from_b58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Self(arr))
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_b58())
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({})", &self.to_b58()[..8])
    }
}

// ── TxId ─────────────────────────────────────────────────────────────────────

/// 32-byte transaction identifier: BLAKE3 of the canonical serialized tx body.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TxId(pub [u8; 32]);

impl TxId {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Self(arr))
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({}…)", &self.to_hex()[..16])
    }
}

// ── TimeLockId ───────────────────────────────────────────────────────────────

/// Unique identifier for a time-lock contract: derived from the creating TxId.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct TimeLockId(pub TxId);

impl fmt::Display for TimeLockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TL:{}", self.0)
    }
}

// ── DilithiumPublicKey ────────────────────────────────────────────────────────

/// Dilithium2 public key (1312 bytes per NIST FIPS 204).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DilithiumPublicKey(pub Vec<u8>);

impl fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DilithiumPublicKey({}b)", self.0.len())
    }
}

/// Dilithium2 signature (2420 bytes per NIST FIPS 204).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DilithiumSignature(pub Vec<u8>);

impl fmt::Debug for DilithiumSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DilithiumSignature({}b)", self.0.len())
    }
}

// ── EvidenceHash ─────────────────────────────────────────────────────────────

/// 32-byte hash committing to off-chain recovery evidence (e.g. identity docs).
/// The protocol does not interpret this data — it is a commitment only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct EvidenceHash(pub [u8; 32]);

impl EvidenceHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}
