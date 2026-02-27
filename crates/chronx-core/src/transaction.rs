use serde::{Deserialize, Serialize};

use crate::types::{
    AccountId, Balance, DilithiumPublicKey, DilithiumSignature, EvidenceHash, Nonce, TimeLockId,
    Timestamp, TxId,
};

// ── AuthScheme ────────────────────────────────────────────────────────────────

/// Describes which authentication proof accompanies this transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthScheme {
    /// Single Dilithium2 signature.
    SingleSig,
    /// k-of-n Dilithium2 multisig.
    MultiSig { k: u32, n: u32 },
}

// ── Action ────────────────────────────────────────────────────────────────────

/// Every state-changing operation in the ChronX DAG is one of these variants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Action {
    // ── Transfers ────────────────────────────────────────────────────────────

    /// Send KX from one account to another.
    Transfer {
        to: AccountId,
        amount: Balance,
    },

    // ── Time-lock contracts ───────────────────────────────────────────────────

    /// Lock `amount` Chronos until `unlock_at`. Only `recipient` may claim.
    /// Irrevocable: sender cannot cancel after creation.
    /// Regulatory note: locks protocol tokens only; no interest accrues;
    /// amount locked == amount claimable.
    TimeLockCreate {
        recipient: DilithiumPublicKey,
        amount: Balance,
        /// Unix timestamp (UTC) after which the recipient may claim.
        unlock_at: Timestamp,
        /// Optional human-readable memo (max 256 bytes, stored in DAG).
        memo: Option<String>,
    },

    /// Claim a matured time-lock. Callable only by the registered recipient.
    TimeLockClaim {
        lock_id: TimeLockId,
    },

    /// Mark a time-lock for sale at `ask_price` Chronos.
    /// Data structure present; execution engine INACTIVE at V1 launch.
    /// Secondary market scaffold — not a protocol guarantee of any return.
    TimeLockSell {
        lock_id: TimeLockId,
        ask_price: Balance,
    },

    // ── Account recovery ──────────────────────────────────────────────────────

    /// Initiate recovery of `target_account`.
    /// Requester posts a bond and commits to evidence hash.
    StartRecovery {
        target_account: AccountId,
        proposed_owner_key: DilithiumPublicKey,
        evidence_hash: EvidenceHash,
        bond_amount: Balance,
    },

    /// Challenge an in-progress recovery.
    ChallengeRecovery {
        target_account: AccountId,
        counter_evidence_hash: EvidenceHash,
        bond_amount: Balance,
    },

    /// Finalize an approved recovery after delay + challenge window.
    FinalizeRecovery {
        target_account: AccountId,
    },

    // ── Verifier registry ─────────────────────────────────────────────────────

    /// Register as a recovery verifier by staking collateral.
    RegisterVerifier {
        stake_amount: Balance,
    },

    /// Cast a signed verifier vote on an active recovery.
    VoteRecovery {
        target_account: AccountId,
        approve: bool,
        /// Verifier's fee bid (Chronos). Paid from recovery bond if approved.
        fee_bid: Balance,
    },
}

// ── Transaction ───────────────────────────────────────────────────────────────

/// A fully-formed, signed ChronX transaction. This is a DAG vertex payload.
///
/// The transaction ID (`tx_id`) is computed as BLAKE3 of the canonical
/// bincode serialization of all fields EXCEPT `signatures`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique identifier (BLAKE3 of body fields).
    pub tx_id: TxId,

    /// Parent vertex IDs in the DAG (1–8 refs; 0 only for genesis).
    pub parents: Vec<TxId>,

    /// UTC Unix timestamp when this transaction was created.
    pub timestamp: Timestamp,

    /// Monotonically increasing per-account counter (replay protection).
    pub nonce: Nonce,

    /// The account authorizing this transaction.
    pub from: AccountId,

    /// The state transition(s) this transaction applies.
    pub actions: Vec<Action>,

    /// PoW nonce: sha3_256(body_bytes || pow_nonce) must have
    /// `difficulty` leading zero bits.
    pub pow_nonce: u64,

    /// Cryptographic proof(s) satisfying `from`'s AuthPolicy.
    pub signatures: Vec<DilithiumSignature>,

    /// Which auth scheme was used.
    pub auth_scheme: AuthScheme,
}

/// The body bytes that are hashed to produce tx_id and covered by signatures.
/// Excludes `tx_id`, `signatures`, and `pow_nonce`.
/// PoW is a separate commitment: sha3_256(body_bytes || pow_nonce_le).
/// This keeps body_bytes stable during PoW mining (no circular dependency).
#[derive(Serialize)]
pub struct TransactionBody<'a> {
    pub parents: &'a Vec<TxId>,
    pub timestamp: Timestamp,
    pub nonce: Nonce,
    pub from: &'a AccountId,
    pub actions: &'a Vec<Action>,
    pub auth_scheme: &'a AuthScheme,
}

impl Transaction {
    /// Extract the body for hashing / signing.
    /// Does NOT include pow_nonce — PoW is verified separately via verify_pow(body_bytes, pow_nonce).
    pub fn body(&self) -> TransactionBody<'_> {
        TransactionBody {
            parents: &self.parents,
            timestamp: self.timestamp,
            nonce: self.nonce,
            from: &self.from,
            actions: &self.actions,
            auth_scheme: &self.auth_scheme,
        }
    }

    /// Serialize the body to canonical bytes (bincode).
    pub fn body_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.body()).expect("body serialization is infallible")
    }
}
