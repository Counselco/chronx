use chronx_core::types::TxId;

/// Compute BLAKE3 hash of arbitrary bytes → 32-byte array.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Derive an AccountId from a raw public key bytes using BLAKE3.
pub fn account_id_from_pubkey(pubkey_bytes: &[u8]) -> chronx_core::types::AccountId {
    chronx_core::types::AccountId::from_bytes(blake3_hash(pubkey_bytes))
}

/// Derive a TxId from the canonical transaction body bytes using BLAKE3.
pub fn tx_id_from_body(body_bytes: &[u8]) -> TxId {
    TxId::from_bytes(blake3_hash(body_bytes))
}
