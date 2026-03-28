//! BLAKE3 balance Merkle tree for ChronX state commitments.
//!
//! Sorted-leaf binary Merkle tree over (AccountId, balance) pairs.
//! Used to produce a deterministic 32-byte state root after each transaction,
//! enabling ZK light client proofs and supply invariant verification.

use crate::constants::TOTAL_SUPPLY_CHRONOS;
use crate::types::AccountId;

// ── Merkle Proof ─────────────────────────────────────────────────────────────

/// Sibling hashes along the path from a leaf to the root.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Each entry: (sibling_hash, is_left) — is_left means the sibling is on the left.
    pub siblings: Vec<([u8; 32], bool)>,
}

// ── Balance Merkle Tree ──────────────────────────────────────────────────────

/// A sorted-leaf binary Merkle tree over account balances.
///
/// Leaves are sorted by `AccountId` bytes for determinism.
/// Leaf hash: `BLAKE3(account_id_bytes || balance.to_le_bytes())`.
/// Internal nodes: `BLAKE3(left_child || right_child)`.
pub struct BalanceMerkleTree {
    /// Sorted (AccountId, balance_chronos) pairs.
    leaves: Vec<(AccountId, u128)>,
    /// Computed leaf hashes (same order as `leaves`).
    leaf_hashes: Vec<[u8; 32]>,
    /// The Merkle root.
    root: [u8; 32],
}

impl Default for BalanceMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl BalanceMerkleTree {
    /// Empty tree with an all-zero root.
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            leaf_hashes: Vec::new(),
            root: [0u8; 32],
        }
    }

    /// Build a tree from all accounts. Sorts by AccountId first.
    pub fn from_accounts(accounts: &[(AccountId, u128)]) -> Self {
        if accounts.is_empty() {
            return Self::new();
        }

        let mut sorted: Vec<(AccountId, u128)> = accounts.to_vec();
        sorted.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));

        let leaf_hashes: Vec<[u8; 32]> = sorted
            .iter()
            .map(|(id, bal)| Self::compute_leaf(id, *bal))
            .collect();

        let root = Self::compute_root(&leaf_hashes);

        Self {
            leaves: sorted,
            leaf_hashes,
            root,
        }
    }

    /// Hash a single leaf: `BLAKE3(account_id_bytes || balance.to_le_bytes())`.
    pub fn compute_leaf(account_id: &AccountId, balance: u128) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(account_id.as_bytes());
        hasher.update(&balance.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Compute the Merkle root from an array of leaf hashes.
    ///
    /// - Empty: `[0u8; 32]`
    /// - Single leaf: the leaf hash itself
    /// - Otherwise: pair leaves, hash pairs, repeat until one root.
    ///   Odd layer → last node is promoted unpaired.
    pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));

            let mut i = 0;
            while i + 1 < current_level.len() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&current_level[i]);
                hasher.update(&current_level[i + 1]);
                next_level.push(*hasher.finalize().as_bytes());
                i += 2;
            }

            // Odd node — promote unpaired.
            if i < current_level.len() {
                next_level.push(current_level[i]);
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Return the current root.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Update one account's balance and recompute the root.
    pub fn update(&mut self, account_id: &AccountId, new_balance: u128) {
        // Find or insert the account in sorted order.
        match self
            .leaves
            .binary_search_by(|(id, _)| id.0.cmp(&account_id.0))
        {
            Ok(idx) => {
                self.leaves[idx].1 = new_balance;
                self.leaf_hashes[idx] = Self::compute_leaf(account_id, new_balance);
            }
            Err(idx) => {
                self.leaves
                    .insert(idx, (account_id.clone(), new_balance));
                self.leaf_hashes
                    .insert(idx, Self::compute_leaf(account_id, new_balance));
            }
        }

        self.root = Self::compute_root(&self.leaf_hashes);
    }

    /// Generate a Merkle proof for the leaf at `account_id`.
    /// Returns `None` if the account is not in the tree.
    pub fn proof(&self, account_id: &AccountId) -> Option<MerkleProof> {
        let leaf_idx = self
            .leaves
            .binary_search_by(|(id, _)| id.0.cmp(&account_id.0))
            .ok()?;

        let mut siblings = Vec::new();
        let mut current_level: Vec<[u8; 32]> = self.leaf_hashes.clone();
        let mut idx = leaf_idx;

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            let mut next_idx = 0;
            let mut i = 0;

            while i + 1 < current_level.len() {
                if i == idx || i + 1 == idx {
                    // This pair contains our node.
                    let is_left = idx == i + 1; // sibling is on the left
                    let sibling = if is_left {
                        current_level[i]
                    } else {
                        current_level[i + 1]
                    };
                    siblings.push((sibling, is_left));
                    next_idx = next_level.len();
                }

                let mut hasher = blake3::Hasher::new();
                hasher.update(&current_level[i]);
                hasher.update(&current_level[i + 1]);
                next_level.push(*hasher.finalize().as_bytes());
                i += 2;
            }

            // Odd node — promoted unpaired (no sibling to record).
            if i < current_level.len() {
                if i == idx {
                    // Our node is the odd one — promoted without a sibling.
                    next_idx = next_level.len();
                }
                next_level.push(current_level[i]);
            }

            current_level = next_level;
            idx = next_idx;
        }

        Some(MerkleProof { siblings })
    }

    /// Verify that a leaf is in the tree given a Merkle proof.
    pub fn verify(
        root: &[u8; 32],
        account_id: &AccountId,
        balance: u128,
        proof: &MerkleProof,
    ) -> bool {
        let mut current = Self::compute_leaf(account_id, balance);

        for (sibling, is_left) in &proof.siblings {
            let mut hasher = blake3::Hasher::new();
            if *is_left {
                hasher.update(sibling);
                hasher.update(&current);
            } else {
                hasher.update(&current);
                hasher.update(sibling);
            }
            current = *hasher.finalize().as_bytes();
        }

        current == *root
    }
}

// ── Supply Invariant ─────────────────────────────────────────────────────────

/// Sum of all locked KX amounts (Chronos) in active (non-terminal) timelocks.
pub fn compute_total_locked_chronos(timelocks: &[crate::account::TimeLockContract]) -> u128 {
    timelocks
        .iter()
        .filter(|t| !t.status.is_terminal())
        .map(|t| t.amount)
        .sum()
}

/// Verify the supply invariant:
/// `total_spendable + total_locked == TOTAL_SUPPLY_CHRONOS`
pub fn verify_supply_invariant(total_spendable: u128, total_locked: u128) -> bool {
    total_spendable
        .checked_add(total_locked)
        .map(|sum| sum == TOTAL_SUPPLY_CHRONOS)
        .unwrap_or(false)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(byte: u8) -> AccountId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        AccountId(bytes)
    }

    #[test]
    fn test_empty_tree() {
        let tree = BalanceMerkleTree::new();
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_single_account() {
        let accounts = vec![(make_id(1), 1000u128)];
        let tree = BalanceMerkleTree::from_accounts(&accounts);
        let expected = BalanceMerkleTree::compute_leaf(&make_id(1), 1000);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_deterministic_root() {
        let accounts = vec![
            (make_id(3), 300),
            (make_id(1), 100),
            (make_id(2), 200),
        ];
        let tree1 = BalanceMerkleTree::from_accounts(&accounts);

        // Same accounts in different order → same root.
        let accounts2 = vec![
            (make_id(1), 100),
            (make_id(2), 200),
            (make_id(3), 300),
        ];
        let tree2 = BalanceMerkleTree::from_accounts(&accounts2);

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_balances_different_root() {
        let a = vec![(make_id(1), 100), (make_id(2), 200)];
        let b = vec![(make_id(1), 100), (make_id(2), 201)];
        let tree_a = BalanceMerkleTree::from_accounts(&a);
        let tree_b = BalanceMerkleTree::from_accounts(&b);
        assert_ne!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn test_supply_invariant() {
        let total = TOTAL_SUPPLY_CHRONOS;
        let spendable = total - 1_000_000;
        let locked = 1_000_000;
        assert!(verify_supply_invariant(spendable, locked));
        assert!(!verify_supply_invariant(spendable, locked + 1));
    }

    #[test]
    fn test_merkle_proof_valid() {
        let accounts: Vec<(AccountId, u128)> = (1..=5u8)
            .map(|i| (make_id(i), i as u128 * 1000))
            .collect();

        let tree = BalanceMerkleTree::from_accounts(&accounts);
        let root = tree.root();

        // Verify proof for each account.
        for (id, bal) in &accounts {
            let proof = tree.proof(id).expect("proof should exist");
            assert!(
                BalanceMerkleTree::verify(&root, id, *bal, &proof),
                "proof failed for account {:?}",
                id.0[0]
            );
        }
    }

    #[test]
    fn test_merkle_proof_invalid_balance() {
        let accounts: Vec<(AccountId, u128)> = (1..=5u8)
            .map(|i| (make_id(i), i as u128 * 1000))
            .collect();

        let tree = BalanceMerkleTree::from_accounts(&accounts);
        let root = tree.root();

        // Proof for account 3 with wrong balance must fail.
        let proof = tree.proof(&make_id(3)).unwrap();
        assert!(!BalanceMerkleTree::verify(
            &root,
            &make_id(3),
            9999,
            &proof
        ));
    }

    #[test]
    fn test_update_changes_root() {
        let accounts = vec![(make_id(1), 100), (make_id(2), 200)];
        let mut tree = BalanceMerkleTree::from_accounts(&accounts);
        let old_root = tree.root();

        tree.update(&make_id(2), 300);
        assert_ne!(tree.root(), old_root);

        // Matches a fresh tree with the updated balance.
        let fresh = BalanceMerkleTree::from_accounts(&[(make_id(1), 100), (make_id(2), 300)]);
        assert_eq!(tree.root(), fresh.root());
    }

    #[test]
    fn test_update_inserts_new_account() {
        let accounts = vec![(make_id(1), 100), (make_id(3), 300)];
        let mut tree = BalanceMerkleTree::from_accounts(&accounts);

        tree.update(&make_id(2), 200);

        let fresh = BalanceMerkleTree::from_accounts(&[
            (make_id(1), 100),
            (make_id(2), 200),
            (make_id(3), 300),
        ]);
        assert_eq!(tree.root(), fresh.root());
    }
}
