//! chronx-core::claims
//!
//! Data structures for the V2 Claims Resolution Framework.
//!
//! Design principles:
//! - lock_version controls which claim path applies; V0 locks keep legacy behaviour.
//! - PolicyId / SchemaId are opaque u64 indices into on-chain registries.
//! - Provider classes are free strings — adding a new class needs no code change.
//! - All registry records are serde-round-trippable for storage in sled trees.

use serde::{Deserialize, Serialize};

use crate::types::{AccountId, Balance, DilithiumPublicKey, DilithiumSignature, Timestamp, TxId};

// ── Opaque identifiers ────────────────────────────────────────────────────────

/// Opaque on-chain identifier for a `ClaimPolicy` record.
pub type PolicyId = u64;

/// Opaque on-chain identifier for a `CertificateSchema` record.
pub type SchemaId = u64;

// ── Lane ─────────────────────────────────────────────────────────────────────

/// Claim lane determined by fiat-equivalent value at claim-open time.
/// Lane governs bond sizes, time windows, and which certificate types are
/// permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimLane {
    /// Very small value; streamlined process; court/outcome certs disallowed.
    Trivial = 0,
    /// Mid-tier value; standard certificate requirements.
    Standard = 1,
    /// High value; elevated bonds, longer windows, full certificate suite.
    Elevated = 2,
}

impl ClaimLane {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => ClaimLane::Trivial,
            1 => ClaimLane::Standard,
            _ => ClaimLane::Elevated,
        }
    }
}

// ── Slash reason ──────────────────────────────────────────────────────────────

/// Why a claim was slashed (used in `TimeLockStatus::ClaimSlashed`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashReason {
    /// Revealed payload hash did not match the committed hash.
    RevealHashMismatch,
    /// Agent did not reveal within the reveal window.
    RevealTimeout,
    /// A challenger proved the revealed claim was invalid.
    SuccessfulChallenge,
    /// Required compliance certificate was absent or from an unapproved provider.
    InvalidComplianceCert,
    /// Ambiguous lock timed out without a valid outcome certificate.
    AmbiguityTimeout,
}

// ── Certificate ───────────────────────────────────────────────────────────────

/// A signed certificate submitted as part of a claim reveal.
///
/// `schema_id` references the on-chain `CertificateSchema` that defines
/// what `payload` must contain and which provider classes may issue it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Certificate {
    /// Which schema this certificate conforms to.
    pub schema_id: SchemaId,
    /// The issuing provider's AccountId (used to look up their status).
    pub issuer: AccountId,
    /// Opaque certificate payload (schema-specific).
    pub payload: Vec<u8>,
    /// Provider's Dilithium2 signature over (schema_id_le8 || issuer_bytes32 || payload).
    pub signature: DilithiumSignature,
}

// ── ClaimState ────────────────────────────────────────────────────────────────

/// Per-lock claim state stored in the `claims` sled tree.
///
/// The `TimeLockStatus` enum tracks the current phase; this struct carries
/// the detailed data (bonds, commits, reveals, challenges) so that
/// `TimeLockStatus` remains lean.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimState {
    /// Lock this claim is for (= primary key in sled).
    pub lock_id: TxId,
    /// Lane assigned at open_claim time.
    pub lane: u8,
    /// USD value of the lock in cents at claim-open time (from oracle).
    pub v_claim_snapshot: u64,
    /// When open_claim was submitted.
    pub opened_at: Timestamp,
    /// Agent that submitted the commit (set by submit_claim_commit).
    pub agent_id: Option<AccountId>,
    /// Commit hash submitted by agent.
    pub commit_hash: Option<[u8; 32]>,
    /// Bond posted by agent (in Chronos).
    pub commit_bond: Balance,
    /// When the commit was submitted.
    pub committed_at: Option<Timestamp>,
    /// Payload revealed by agent.
    pub revealed_payload: Option<Vec<u8>>,
    /// Salt used in commit hash = blake3(payload || salt).
    pub revealed_salt: Option<[u8; 32]>,
    /// Certificates submitted with the reveal.
    pub certificates: Vec<Certificate>,
    /// When the reveal was submitted.
    pub revealed_at: Option<Timestamp>,
    /// Challenger account (set by challenge_claim_reveal).
    pub challenger: Option<AccountId>,
    /// Bond posted by challenger.
    pub challenge_bond: Balance,
    /// Hash of evidence submitted by challenger.
    pub challenge_evidence_hash: Option<[u8; 32]>,
    /// When the challenge was submitted.
    pub challenged_at: Option<Timestamp>,
}

impl ClaimState {
    pub fn new(lock_id: TxId, lane: u8, v_claim_snapshot: u64, opened_at: Timestamp) -> Self {
        Self {
            lock_id,
            lane,
            v_claim_snapshot,
            opened_at,
            agent_id: None,
            commit_hash: None,
            commit_bond: 0,
            committed_at: None,
            revealed_payload: None,
            revealed_salt: None,
            certificates: vec![],
            revealed_at: None,
            challenger: None,
            challenge_bond: 0,
            challenge_evidence_hash: None,
            challenged_at: None,
        }
    }
}

// ── ProviderRecord ────────────────────────────────────────────────────────────

/// Status of a registered provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderStatus {
    Active,
    Revoked { revoked_at: Timestamp },
}

/// An on-chain provider capable of issuing certificates.
///
/// `provider_id` = sender's AccountId (32 bytes).
/// Adding a new provider class ("court", "bank", "kycprovider", …) requires
/// only a `RegisterProvider` transaction — no code changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderRecord {
    /// AccountId of the provider (= primary key).
    pub provider_id: AccountId,
    /// Active signing keys (rotatable via `RotateProviderKey`).
    pub public_keys: Vec<DilithiumPublicKey>,
    /// Free-form class label, e.g. "court", "kyc", "compliance", "notary".
    pub provider_class: String,
    /// ISO-3166-1 alpha-2 jurisdiction codes where this provider is recognised.
    pub jurisdictions: Vec<String>,
    /// Current status.
    pub status: ProviderStatus,
    /// Bond posted at registration (returned on clean revocation).
    pub registration_bond: Balance,
    /// When the provider was registered.
    pub registered_at: Timestamp,
}

// ── CertificateSchema ─────────────────────────────────────────────────────────

/// Signature rules for a certificate schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRules {
    /// Minimum number of distinct providers that must sign.
    pub min_providers: u32,
    /// Maximum age of any certificate (seconds). Older certs are rejected.
    pub max_cert_age_secs: i64,
}

/// An on-chain schema describing what a certificate must contain and who
/// may issue it.
///
/// Schemas are versioned: `update_schema` bumps `version` only; new schemas
/// must be registered fresh.  Deactivated schemas may no longer be used in
/// new claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateSchema {
    /// Sequential on-chain ID.
    pub schema_id: SchemaId,
    /// Human-readable name (e.g. "ComplianceCertificate", "OutcomeCertificate").
    pub name: String,
    /// Schema version (bumped by update_schema).
    pub version: u32,
    /// Blake3 hash of the canonical required-field specification JSON.
    pub required_fields_hash: [u8; 32],
    /// (provider_class, min_count) pairs — which classes may issue and how many.
    pub provider_class_thresholds: Vec<(String, u32)>,
    /// Signature rules.
    pub signature_rules: SignatureRules,
    /// Whether new claims may reference this schema.
    pub active: bool,
    /// Who registered this schema.
    pub registered_by: AccountId,
    /// When.
    pub registered_at: Timestamp,
}

// ── LaneThresholds ────────────────────────────────────────────────────────────

/// Per-lane thresholds, bonds, and time windows stored in a `ClaimPolicy`.
/// All fields are governance-updatable without a code change.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LaneThresholds {
    /// Below this USD-cents value → Trivial lane.
    pub trivial_max_usd_cents: u64,
    /// Below this → Standard lane; at or above → Elevated.
    pub standard_max_usd_cents: u64,
    /// Minimum agent bond per lane (Chronos).
    pub trivial_bond_chronos: Balance,
    pub standard_bond_chronos: Balance,
    pub elevated_bond_chronos: Balance,
    /// Reveal window per lane (seconds from commit).
    pub trivial_reveal_window_secs: i64,
    pub standard_reveal_window_secs: i64,
    pub elevated_reveal_window_secs: i64,
    /// Challenge window per lane (seconds from reveal).
    pub trivial_challenge_window_secs: i64,
    pub standard_challenge_window_secs: i64,
    pub elevated_challenge_window_secs: i64,
}

impl LaneThresholds {
    /// Protocol defaults.
    pub fn default_thresholds() -> Self {
        use crate::constants::CHRONOS_PER_KX;
        Self {
            trivial_max_usd_cents: 100_000,    // $1,000
            standard_max_usd_cents: 5_000_000, // $50,000
            trivial_bond_chronos: 10 * CHRONOS_PER_KX,
            standard_bond_chronos: 100 * CHRONOS_PER_KX,
            elevated_bond_chronos: 500 * CHRONOS_PER_KX,
            trivial_reveal_window_secs: 7 * 24 * 3600,
            standard_reveal_window_secs: 14 * 24 * 3600,
            elevated_reveal_window_secs: 30 * 24 * 3600,
            trivial_challenge_window_secs: 7 * 24 * 3600,
            standard_challenge_window_secs: 14 * 24 * 3600,
            elevated_challenge_window_secs: 21 * 24 * 3600,
        }
    }

    pub fn lane_for(&self, v_claim_usd_cents: u64) -> ClaimLane {
        if v_claim_usd_cents < self.trivial_max_usd_cents {
            ClaimLane::Trivial
        } else if v_claim_usd_cents < self.standard_max_usd_cents {
            ClaimLane::Standard
        } else {
            ClaimLane::Elevated
        }
    }

    pub fn min_bond(&self, lane: ClaimLane) -> Balance {
        match lane {
            ClaimLane::Trivial => self.trivial_bond_chronos,
            ClaimLane::Standard => self.standard_bond_chronos,
            ClaimLane::Elevated => self.elevated_bond_chronos,
        }
    }

    pub fn reveal_window(&self, lane: ClaimLane) -> i64 {
        match lane {
            ClaimLane::Trivial => self.trivial_reveal_window_secs,
            ClaimLane::Standard => self.standard_reveal_window_secs,
            ClaimLane::Elevated => self.elevated_reveal_window_secs,
        }
    }

    pub fn challenge_window(&self, lane: ClaimLane) -> i64 {
        match lane {
            ClaimLane::Trivial => self.trivial_challenge_window_secs,
            ClaimLane::Standard => self.standard_challenge_window_secs,
            ClaimLane::Elevated => self.elevated_challenge_window_secs,
        }
    }
}

// ── ClaimPolicy ───────────────────────────────────────────────────────────────

/// An on-chain policy governing how claims against a lock are resolved.
///
/// Policies are referenced by `TimeLockContract::claim_policy`.
/// Locks with `claim_policy = None` use the default V0 direct-claim path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimPolicy {
    pub policy_id: PolicyId,
    pub name: String,
    pub version: u32,
    /// Certificate schema IDs that claimants may submit.
    pub allowed_cert_schemas: Vec<SchemaId>,
    /// Per-lane configuration.
    pub thresholds: LaneThresholds,
    /// If true, a ComplianceCertificate schema cert is mandatory.
    pub requires_compliance_cert: bool,
    /// Which schema ID is the required compliance certificate.
    pub compliance_cert_schema_id: Option<SchemaId>,
    /// If true, locks without a unique identifier enter Ambiguous mode.
    pub ambiguity_mode_enabled: bool,
    /// Trivial lane does NOT permit court/outcome certificates by default.
    pub trivial_lane_allowed_schemas: Vec<SchemaId>,
    pub active: bool,
    pub registered_by: AccountId,
    pub registered_at: Timestamp,
}

// ── Oracle ────────────────────────────────────────────────────────────────────

/// A single price submission from an approved oracle provider.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleSubmission {
    /// The submitting account (must be a registered oracle provider).
    pub submitter: AccountId,
    /// Trading pair, e.g. "KX/USD".
    pub pair: String,
    /// Price in USD cents (fixed-point, 2 decimals).
    pub price_cents: u64,
    /// When submitted.
    pub submitted_at: Timestamp,
}

/// Aggregated oracle snapshot (median of recent submissions).
///
/// Computed and stored whenever a new submission arrives.
/// `open_claim` uses the snapshot at the moment it is called to fix V_claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleSnapshot {
    pub pair: String,
    /// Median price in USD cents.
    pub price_cents: u64,
    /// How many submissions contributed.
    pub num_submissions: u32,
    /// Latest submission timestamp used.
    pub updated_at: Timestamp,
}
