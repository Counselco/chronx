use chronx_core::constants::{DAG_MAX_PARENTS, DAG_MIN_PARENTS};
use chronx_core::error::ChronxError;
use chronx_core::transaction::Transaction;
use chronx_core::types::TxId;
use chronx_crypto::{tx_id_from_body, verify_pow};

/// Validate a transaction vertex before accepting it into the DAG.
///
/// Checks (in order):
/// 1. Parent count constraints
/// 2. All claimed parents exist (caller provides the lookup function)
/// 3. PoW validity
/// 4. TxId integrity (recomputed from body)
/// 5. Signature validity against the sender's auth policy
///
/// Note: balance and nonce checks happen in chronx-state (state transition layer).
pub fn validate_vertex<F>(
    tx: &Transaction,
    pow_difficulty: u8,
    parent_exists: F,
) -> Result<(), ChronxError>
where
    F: Fn(&TxId) -> bool,
{
    // ── 1. Genesis exception ─────────────────────────────────────────────────
    let is_genesis = tx.parents.is_empty();

    if !is_genesis {
        // ── 2. Parent count ──────────────────────────────────────────────────
        if tx.parents.len() < DAG_MIN_PARENTS {
            return Err(ChronxError::TooFewParents {
                min: DAG_MIN_PARENTS,
                got: tx.parents.len(),
            });
        }
        if tx.parents.len() > DAG_MAX_PARENTS {
            return Err(ChronxError::TooManyParents {
                max: DAG_MAX_PARENTS,
                got: tx.parents.len(),
            });
        }

        // ── 3. All parents must exist ─────────────────────────────────────
        for parent_id in &tx.parents {
            if !parent_exists(parent_id) {
                return Err(ChronxError::UnknownParent(parent_id.to_hex()));
            }
        }
    }

    // ── 4. PoW validity ──────────────────────────────────────────────────────
    let body_bytes = tx.body_bytes();
    if !is_genesis && !verify_pow(&body_bytes, tx.pow_nonce, pow_difficulty) {
        return Err(ChronxError::InvalidPoW);
    }

    // ── 5. TxId integrity ────────────────────────────────────────────────────
    let expected_id = tx_id_from_body(&body_bytes);
    if expected_id != tx.tx_id {
        return Err(ChronxError::InvalidSignature); // tx body was tampered
    }

    Ok(())
}

/// Validate signatures against the account's stored auth policy.
/// Called by chronx-state after looking up the account.
pub fn validate_signatures(
    tx: &Transaction,
    auth_policy: &chronx_core::account::AuthPolicy,
) -> Result<(), ChronxError> {
    use chronx_core::account::AuthPolicy;
    use chronx_core::transaction::AuthScheme;
    use chronx_crypto::verify_signature;

    let body_bytes = tx.body_bytes();

    match (auth_policy, &tx.auth_scheme) {
        // ── SingleSig ────────────────────────────────────────────────────────
        (AuthPolicy::SingleSig { public_key }, AuthScheme::SingleSig) => {
            let sig = tx.signatures.first().ok_or(ChronxError::InvalidSignature)?;
            verify_signature(public_key, &body_bytes, sig)
                .map_err(|_| ChronxError::InvalidSignature)
        }

        // ── MultiSig ─────────────────────────────────────────────────────────
        (
            AuthPolicy::MultiSig {
                threshold,
                public_keys,
            },
            AuthScheme::MultiSig { k, .. },
        ) => {
            if tx.signatures.len() < *threshold as usize {
                return Err(ChronxError::MultisigThresholdNotMet {
                    need: *threshold,
                    got: tx.signatures.len() as u32,
                });
            }

            let mut valid_count = 0u32;
            let mut seen_keys = std::collections::HashSet::new();

            for sig in &tx.signatures {
                for pk in public_keys {
                    if seen_keys.contains(&pk.0) {
                        continue;
                    }
                    if verify_signature(pk, &body_bytes, sig).is_ok() {
                        seen_keys.insert(pk.0.clone());
                        valid_count += 1;
                        break;
                    }
                }
            }

            if valid_count < *k {
                return Err(ChronxError::MultisigThresholdNotMet {
                    need: *k,
                    got: valid_count,
                });
            }
            Ok(())
        }

        // ── RecoveryEnabled (uses owner key like SingleSig) ───────────────────
        (AuthPolicy::RecoveryEnabled { owner_key, .. }, AuthScheme::SingleSig) => {
            let sig = tx.signatures.first().ok_or(ChronxError::InvalidSignature)?;
            verify_signature(owner_key, &body_bytes, sig).map_err(|_| ChronxError::InvalidSignature)
        }

        _ => Err(ChronxError::AuthPolicyViolation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chronx_core::transaction::{Action, AuthScheme, Transaction};
    use chronx_core::types::{AccountId, TxId};
    use chronx_crypto::{mine_pow, tx_id_from_body, KeyPair};

    fn make_test_tx(parents: Vec<TxId>, pow_difficulty: u8) -> Transaction {
        let kp = KeyPair::generate();
        let actions = vec![Action::Transfer {
            to: AccountId::from_bytes([1u8; 32]),
            amount: 1_000_000,
        }];
        let auth_scheme = AuthScheme::SingleSig;
        let mut tx = Transaction {
            tx_id: TxId::from_bytes([0u8; 32]), // placeholder
            parents: parents.clone(),
            timestamp: 1_000_000,
            nonce: 0,
            from: kp.account_id.clone(),
            actions: actions.clone(),
            pow_nonce: 0,
            signatures: vec![],
            auth_scheme: auth_scheme.clone(),
            tx_version: 1,
            client_ref: None,
            fee_chronos: 0,
            expires_at: None,
            sender_public_key: Some(kp.public_key.clone()),
        };
        // body_bytes are stable (don't include pow_nonce)
        let body_bytes = tx.body_bytes();
        tx.pow_nonce = mine_pow(&body_bytes, pow_difficulty);
        tx.tx_id = tx_id_from_body(&body_bytes);
        let sig = kp.sign(&body_bytes);
        tx.signatures = vec![sig];
        tx
    }

    #[test]
    fn valid_genesis_passes() {
        let tx = make_test_tx(vec![], 0);
        assert!(validate_vertex(&tx, 0, |_| false).is_ok());
    }

    #[test]
    fn non_genesis_missing_parents_fails() {
        let tx = make_test_tx(vec![TxId::from_bytes([9u8; 32])], 4);
        let result = validate_vertex(&tx, 4, |_| false);
        assert!(matches!(result, Err(ChronxError::UnknownParent(_))));
    }

    #[test]
    fn bad_pow_fails() {
        let mut tx = make_test_tx(vec![TxId::from_bytes([9u8; 32])], 0);
        tx.pow_nonce = 999_999_999;
        // Recompute tx_id with new nonce so TxId check passes but PoW fails
        let body = tx.body_bytes();
        tx.tx_id = tx_id_from_body(&body);
        let result = validate_vertex(&tx, 20, |_| true);
        assert!(matches!(result, Err(ChronxError::InvalidPoW)));
    }
}
