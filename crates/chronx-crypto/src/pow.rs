use sha3::{Digest, Sha3_256};

/// Verify that sha3_256(body_bytes || pow_nonce) has `difficulty` leading zero bits.
pub fn verify_pow(body_bytes: &[u8], pow_nonce: u64, difficulty: u8) -> bool {
    let hash = pow_hash(body_bytes, pow_nonce);
    leading_zero_bits(&hash) >= difficulty
}

/// Find a `pow_nonce` such that sha3_256(body_bytes || nonce) has >= `difficulty`
/// leading zero bits. Returns the winning nonce.
pub fn mine_pow(body_bytes: &[u8], difficulty: u8) -> u64 {
    for nonce in 0u64.. {
        if verify_pow(body_bytes, nonce, difficulty) {
            return nonce;
        }
    }
    unreachable!("PoW loop exhausted u64 range")
}

fn pow_hash(body_bytes: &[u8], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(body_bytes);
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

fn leading_zero_bits(hash: &[u8; 32]) -> u8 {
    let mut count = 0u8;
    for byte in hash {
        let lz = byte.leading_zeros() as u8;
        count += lz;
        if lz < 8 {
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_round_trip() {
        let body = b"test transaction body";
        let difficulty = 8; // easy for tests
        let nonce = mine_pow(body, difficulty);
        assert!(verify_pow(body, nonce, difficulty));
        assert!(!verify_pow(body, nonce + 1, difficulty));
    }

    #[test]
    fn leading_zeros_correct() {
        let mut hash = [0u8; 32];
        hash[0] = 0b00001111;
        assert_eq!(leading_zero_bits(&hash), 4);

        let mut hash2 = [0u8; 32];
        hash2[0] = 0b00000001;
        assert_eq!(leading_zero_bits(&hash2), 7);
    }
}
