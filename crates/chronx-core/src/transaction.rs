use serde::{Deserialize, Serialize};

use crate::types::{
    AccountId, Balance, DilithiumPublicKey, DilithiumSignature, EvidenceHash, Nonce, TimeLockId,
    Timestamp, TxId,
};

fn default_tx_version() -> u16 {
    1
}

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
    Transfer { to: AccountId, amount: Balance },

    // ── Time-lock contracts ───────────────────────────────────────────────────
    /// Lock `amount` Chronos until `unlock_at`. Only `recipient` may claim.
    /// Regulatory note: locks protocol tokens only; no interest accrues;
    /// amount locked == amount claimable.
    TimeLockCreate {
        recipient: DilithiumPublicKey,
        amount: Balance,
        /// Unix timestamp (UTC) after which the recipient may claim.
        unlock_at: Timestamp,
        /// Optional human-readable memo (max 256 bytes, stored in DAG).
        memo: Option<String>,
        // ── Extensibility fields (all optional / defaulted) ──────────────────
        /// Seconds after creation the sender may cancel. None = irrevocable.
        cancellation_window_secs: Option<u32>,
        /// Whether to flag this lock for recipient notification systems.
        notify_recipient: Option<bool>,
        /// User-defined labels (max 5, max 32 chars each).
        tags: Option<Vec<String>>,
        /// If true, hide memo and amount from public explorer.
        private: Option<bool>,
        /// What happens if funds are unclaimed after grace period.
        expiry_policy: Option<crate::account::ExpiryPolicy>,
        /// Future multi-recipient split (scaffold, inactive V1).
        split_policy: Option<crate::account::SplitPolicy>,
        /// Max failed claim attempts before Ambiguous mode.
        claim_attempts_max: Option<u8>,
        /// Recurring lock schedule (scaffold, inactive V1).
        recurring: Option<crate::account::RecurringPolicy>,
        /// Reserved bytes for future extensions (max 1 KB).
        extension_data: Option<Vec<u8>>,
        /// Suggested fiat currency for oracle at claim time.
        oracle_hint: Option<String>,
        /// ISO country code hint for lane selection.
        jurisdiction_hint: Option<String>,
        /// Optional governance proposal link.
        governance_proposal_id: Option<String>,
        /// Client-side deduplication reference (16 bytes, opaque).
        client_ref: Option<[u8; 16]>,
    },

    /// Claim a matured time-lock. Callable only by the registered recipient.
    TimeLockClaim { lock_id: TimeLockId },

    /// Mark a time-lock for sale at `ask_price` Chronos.
    /// Data structure present; execution engine INACTIVE at V1 launch.
    /// Secondary market scaffold — not a protocol guarantee of any return.
    TimeLockSell {
        lock_id: TimeLockId,
        ask_price: Balance,
    },

    /// Cancel a time-lock within its `cancellation_window_secs`.
    /// Only the original sender may cancel. Returns funds to sender.
    /// Fails if the lock has no cancellation window or the window has expired.
    CancelTimeLock { lock_id: TimeLockId },

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
    FinalizeRecovery { target_account: AccountId },

    // ── Verifier registry ─────────────────────────────────────────────────────
    /// Register as a recovery verifier by staking collateral.
    RegisterVerifier { stake_amount: Balance },

    /// Cast a signed verifier vote on an active recovery.
    VoteRecovery {
        target_account: AccountId,
        approve: bool,
        /// Verifier's fee bid (Chronos). Paid from recovery bond if approved.
        fee_bid: Balance,
    },

    // ── V2 Claims state machine ───────────────────────────────────────────────
    /// Open the claims process for a matured V1 lock.
    /// Snapshots V_claim from oracle and assigns the claim lane.
    OpenClaim { lock_id: TimeLockId },

    /// Commit a hash of the claim payload. Agent posts a bond.
    /// commit_hash = blake3(payload_bytes || salt_bytes).
    SubmitClaimCommit {
        lock_id: TimeLockId,
        commit_hash: [u8; 32],
        bond_amount: Balance,
    },

    /// Reveal the payload and salt; include any required certificates.
    RevealClaim {
        lock_id: TimeLockId,
        payload: Vec<u8>,
        salt: [u8; 32],
        certificates: Vec<crate::claims::Certificate>,
    },

    /// Challenge a revealed claim. Challenger posts a bond and commits
    /// to a hash of counter-evidence.
    ChallengeClaimReveal {
        lock_id: TimeLockId,
        evidence_hash: [u8; 32],
        bond_amount: Balance,
    },

    /// Finalize a claim after the challenge window has closed.
    /// Unchallenged reveal → agent wins. Challenged → challenger wins (MVP).
    FinalizeClaim { lock_id: TimeLockId },

    // ── Provider registry ─────────────────────────────────────────────────────
    /// Register the sender as a certificate provider.
    /// provider_class is a free string (e.g. "court", "kyc", "compliance").
    RegisterProvider {
        provider_class: String,
        jurisdictions: Vec<String>,
        bond_amount: Balance,
    },

    /// Revoke a provider. Self-revoke or future governance call.
    RevokeProvider { provider_id: AccountId },

    /// Rotate the active signing key for the caller's provider record.
    RotateProviderKey { new_public_key: DilithiumPublicKey },

    // ── Certificate schema registry ───────────────────────────────────────────
    /// Register a new certificate schema on-chain.
    RegisterSchema {
        name: String,
        version: u32,
        /// Blake3 hash of the canonical required-field specification.
        required_fields_hash: [u8; 32],
        /// (provider_class, min_count) — which classes may issue and how many.
        provider_class_thresholds: Vec<(String, u32)>,
        min_providers: u32,
        max_cert_age_secs: i64,
        bond_amount: Balance,
    },

    /// Deactivate a schema (no new claims may reference it).
    DeactivateSchema { schema_id: crate::claims::SchemaId },

    // ── Oracle ────────────────────────────────────────────────────────────────
    /// Submit a KX price observation. Caller must be a registered provider
    /// of class "oracle".
    SubmitOraclePrice {
        /// Trading pair, e.g. "KX/USD".
        pair: String,
        /// Price in USD cents (fixed-point with 2 decimal places).
        price_cents: u64,
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

    // ── V3 extensibility fields (serde(default) for backward compat) ─────────
    /// Transaction struct version. 1 = current.
    #[serde(default = "default_tx_version")]
    pub tx_version: u16,
    /// Client-side deduplication reference (16 bytes, opaque).
    #[serde(default)]
    pub client_ref: Option<[u8; 16]>,
    /// Fee in Chronos. Always 0 for now; field reserved for future fee market.
    #[serde(default)]
    pub fee_chronos: u128,
    /// If the transaction is not confirmed by this Unix timestamp, drop it from
    /// the mempool. None = no expiry.
    #[serde(default)]
    pub expires_at: Option<i64>,

    // ── V3.3 Key registration (P2PKH first-spend pattern) ────────────────────
    /// The sender's Dilithium2 public key, required on the first transaction
    /// from any account that was created via Transfer (and thus has no stored
    /// public key). The engine checks `account_id_from_pubkey(key) == from`
    /// and, on success, updates the account's auth_policy permanently so all
    /// future transactions can be verified without this field.
    /// Wallets SHOULD always include this field — it is silently ignored for
    /// accounts whose public key is already registered.
    #[serde(default)]
    pub sender_public_key: Option<crate::types::DilithiumPublicKey>,
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
