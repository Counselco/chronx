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

// ── AuthorizedSet (used by 6 payment types) ──────────────────

/// A set of wallets authorized to interact with a payment instrument.
/// Used by Invoice (payers), TimeLock (claimants), Credit (beneficiaries),
/// Conditional (attestors), Succession, and AI Lock (backup executors).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AuthorizedSet {
    /// Short inline list of authorized public keys.
    Wallets(Vec<DilithiumPublicKey>),
    /// Reference a TYPE_G Wallet Group by its 32-byte ID.
    Group([u8; 32]),
}

// ── Wallet Group structs ──────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CreateGroupAction {
    pub owner_pubkey: DilithiumPublicKey,
    pub group_id: [u8; 32],
    pub name_hash: [u8; 32],
    pub members: Vec<DilithiumPublicKey>,
    pub encrypted_meta: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AddGroupMemberAction {
    pub owner_pubkey: DilithiumPublicKey,
    pub group_id: [u8; 32],
    pub new_member: DilithiumPublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RemoveGroupMemberAction {
    pub owner_pubkey: DilithiumPublicKey,
    pub group_id: [u8; 32],
    pub member: DilithiumPublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DissolveGroupAction {
    pub owner_pubkey: DilithiumPublicKey,
    pub group_id: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransferGroupOwnershipAction {
    pub owner_pubkey: DilithiumPublicKey,
    pub group_id: [u8; 32],
    pub new_owner: DilithiumPublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GroupStatus { Active, Dissolved }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GroupRecord {
    pub group_id: [u8; 32],
    pub owner_pubkey: DilithiumPublicKey,
    pub name_hash: [u8; 32],
    pub members: Vec<DilithiumPublicKey>,
    pub member_count: u64,
    pub created_at: u64,
    pub status: GroupStatus,
}

// ── Action ────────────────────────────────────────────────────────────────────


// ── Payment Type Action Structs ──────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CreateInvoiceAction {
    pub issuer_pubkey: DilithiumPublicKey,
    pub payer_pubkey: Option<DilithiumPublicKey>,
    pub amount_chronos: u64,
    pub invoice_id: [u8; 32],
    pub expiry: u64,
    pub encrypted_memo: Option<Vec<u8>>,
    pub memo_hash: Option<[u8; 32]>,
    /// Optional set of authorized payers (inline list or Group ref).
    #[serde(default)]
    pub authorized_payers: Option<AuthorizedSet>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FulfillInvoiceAction {
    pub payer_pubkey: DilithiumPublicKey,
    pub invoice_id: [u8; 32],
    pub amount_chronos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CancelInvoiceAction {
    pub issuer_pubkey: DilithiumPublicKey,
    pub invoice_id: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CreateCreditAction {
    pub grantor_pubkey: DilithiumPublicKey,
    pub beneficiary_pubkey: DilithiumPublicKey,
    pub ceiling_chronos: u64,
    pub per_draw_max_chronos: Option<u64>,
    pub expiry: u64,
    pub credit_id: [u8; 32],
    pub encrypted_terms: Option<Vec<u8>>,
    /// Optional group whose members may also draw.
    #[serde(default)]
    pub beneficiary_group: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DrawCreditAction {
    pub beneficiary_pubkey: DilithiumPublicKey,
    pub credit_id: [u8; 32],
    pub amount_chronos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RevokeCreditAction {
    pub grantor_pubkey: DilithiumPublicKey,
    pub credit_id: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Compounding {
    Simple,
    Daily,
    Monthly,
    Annually,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CreateDepositAction {
    pub depositor_pubkey: DilithiumPublicKey,
    pub obligor_pubkey: DilithiumPublicKey,
    pub principal_chronos: u64,
    pub rate_basis_points: u64,
    pub term_seconds: u64,
    pub compounding: Compounding,
    pub penalty_basis_points: Option<u64>,
    pub deposit_id: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SettleDepositAction {
    pub obligor_pubkey: DilithiumPublicKey,
    pub deposit_id: [u8; 32],
    pub amount_chronos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConditionalFallback {
    Void,
    Return,
    Escrow,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CreateConditionalAction {
    pub sender_pubkey: DilithiumPublicKey,
    pub recipient_pubkey: DilithiumPublicKey,
    pub amount_chronos: u64,
    pub attestor_pubkeys: Vec<DilithiumPublicKey>,
    pub min_attestors: u32,
    pub attestation_memo: Option<String>,
    pub valid_until: u64,
    pub fallback: ConditionalFallback,
    pub encrypted_terms: Option<Vec<u8>>,
    pub type_v_id: [u8; 32],
    /// Optional group whose members may also attest.
    #[serde(default)]
    pub attestor_group: Option<[u8; 32]>,
    // -- OracleTrigger fields (set by CLI, stored in ConditionalRecord) --
    #[serde(default)]
    pub condition_type: Option<String>,
    #[serde(default)]
    pub oracle_pair: Option<String>,
    #[serde(default)]
    pub oracle_trigger_threshold: Option<f64>,
    #[serde(default)]
    pub oracle_trigger_direction: Option<String>,
    #[serde(default)]
    pub success_payment_wallet: Option<String>,
    #[serde(default)]
    pub success_payment_chronos: Option<u64>,
    // ── Genesis Zero — HedgeKX limit orders + TWAP fills ────────────
    /// Maximum basis points per annum the buyer will pay. None = accept market rate.
    #[serde(default)]
    pub max_rate_bps: Option<u32>,
    /// Hedge execution method. None = Immediate (default).
    #[serde(default)]
    pub hedge_execution: Option<HedgeExecution>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AttestConditionalAction {
    pub attestor_pubkey: DilithiumPublicKey,
    pub type_v_id: [u8; 32],
    pub attestation_memo: Option<String>,
    /// If Some(n): release exactly n Chronos (must be <= remaining locked amount).
    /// If None: release full remaining amount (backward compatible).
    #[serde(default)]
    pub release_amount_chronos: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum LedgerEntryType {
    Decision,
    Summary,
    Audit,
    Milestone,
    SignOfLife,
    GuardianTransition,
    LifeUnconfirmed,
    BeneficiaryIdentified,
    IdentityVerified,
    IdentityRevoked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CreateLedgerEntryAction {
    pub author_pubkey: DilithiumPublicKey,
    pub mandate_id: Option<[u8; 32]>,
    pub promise_id: Option<[u8; 32]>,
    pub entry_type: LedgerEntryType,
    pub content_hash: [u8; 32],
    pub content_summary: Vec<u8>,
    pub promise_chain_hash: Option<[u8; 32]>,
    pub external_ref: Option<String>,
    pub entry_id: [u8; 32],
}


// ── Sign of Life types ─────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SignOfLifeStatus {
    Active,
    GracePeriod,
    Transitioned,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SignOfLifeResponsible {
    Grantor,
    Guardian,
}

// ── Genesis 10a — PAY_AS DENOMINATION ──────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PayAsDenomination {
    FixedKX,
    UsdEquivalentAtCreation { rate_microcents_per_kx: u64 },
    UsdEquivalentAtMaturity,
    EurEquivalentAtCreation { rate_microeuros_per_kx: u64 },
    EurEquivalentAtMaturity,
}

// ── Genesis 10a — LOAN PAYMENT STAGE ───────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum LoanPaymentType {
    InterestOnly,
    PrincipalOnly,
    PrincipalAndInterest,
    BulletFinal,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LoanPaymentStage {
    pub due_at: u64,
    pub amount_kx: u64,
    pub pay_as: PayAsDenomination,
    pub payment_type: LoanPaymentType,
    pub stage_index: u32,
}

// ── Genesis 10a — LATE FEE SCHEDULE ────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LateFeeStage {
    pub days_overdue: u32,
    pub fee_pct: u8,
    pub fee_minimum_kx: u64,
    pub fee_maximum_kx: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum LateFeeSchedule {
    None,
    Flat { fee_kx: u64 },
    Tiered { stages: Vec<LateFeeStage> },
}

// ── Genesis 10a — PREPAYMENT TERMS ─────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PrepaymentTerms {
    Prohibited,
    AllowedAtPar,
    AllowedWithPenalty { penalty_pct: u8, penalty_minimum_kx: u64 },
    AllowedWithDiscount { discount_pct: u8, discount_maximum_kx: u64 },
}

// ── Genesis 10a — HEDGE REQUIREMENT ────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum HedgeCoverageType {
    PrincipalOnly,
    PrincipalAndInterest,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HedgeRequirement {
    pub minimum_coverage_pct: u8,
    pub coverage_type: HedgeCoverageType,
    pub funding_deadline_days: u16,
}

// ── Genesis 10a — ORACLE POLICY ────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum OracleFallback {
    UseLastKnownPrice,
    SuspendAndNotify,
    UseSevenDayAverage,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OraclePolicy {
    pub retry_window_days: u8,
    pub retry_interval_hours: u8,
    pub fallback: OracleFallback,
}

impl Default for OraclePolicy {
    fn default() -> Self {
        OraclePolicy {
            retry_window_days: 3,
            retry_interval_hours: 6,
            fallback: OracleFallback::UseSevenDayAverage,
        }
    }
}


// -- Genesis Zero -- Obligation Transfer Layer --------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(Default)]
pub enum TransferFlag {
    /// Default -- transferable freely.
    #[default]
    Free,
    /// Transferable with conditions.
    Restricted(TransferConditions),
    /// Not transferable.
    Locked,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransferConditions {
    pub accredited_only: bool,
    pub jurisdiction_blacklist: Vec<String>,
    pub jurisdiction_whitelist: Vec<String>,
    pub governance_unlock_at: Option<u64>,
    pub lender_consent_required: bool,
    pub borrower_consent_required: bool,
    pub min_hold_period_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(Default)]
pub enum TermsVisibility {
    /// Default -- terms not public.
    #[default]
    Private,
    /// Terms visible to all.
    Public,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(Default)]
pub enum ClaimType {
    /// Whole obligation (default).
    #[default]
    Whole,
    /// Yield stream only.
    YieldOnly,
    /// Principal at maturity only.
    PrincipalOnly,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(Default)]
pub enum RetirementStatus {
    #[default]
    Active,
    PartiallyRetired,
    FullyRetired,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransferRecord {
    pub from_wallet: AccountId,
    pub to_wallet: AccountId,
    pub consideration_kx: u64,
    pub consideration_currency: Option<String>,
    pub transferred_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrancheInfo {
    pub parent_obligation_id: TxId,
    pub tranche_number: u32,
    pub tranche_total: u32,
    pub claim_type: ClaimType,
    pub claim_on_collateral: Option<TxId>,
}

// -- Genesis Zero -- Obligation Action Structs --------------------------------

/// Transfer ownership of an obligation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObligationTransfer {
    pub obligation_id: TxId,
    pub from_wallet: AccountId,
    pub to_wallet: AccountId,
    pub consideration_kx: u64,
    pub consideration_currency: Option<String>,
    pub signed_by: AccountId,
}

/// Split one obligation into N tranches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObligationTranche {
    pub parent_obligation_id: TxId,
    pub tranche_count: u32,
    pub face_value_per_tranche_kx: u64,
    pub claim_types: Vec<ClaimType>,
    pub signed_by: AccountId,
}

/// Retire all or part of an obligation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObligationRetire {
    pub obligation_id: TxId,
    pub retiring_wallet: AccountId,
    pub retire_fraction: f64,
    pub announcement: Option<String>,
}

/// Update transfer flag (lender only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransferFlagUpdate {
    pub obligation_id: TxId,
    pub lender_wallet: AccountId,
    pub new_flag: TransferFlag,
}

/// Update terms visibility (lender only, either direction).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TermsVisibilityUpdate {
    pub obligation_id: TxId,
    pub lender_wallet: AccountId,
    pub new_visibility: TermsVisibility,
}


// -- Escalation and failure actions (scaffold) --------------------------------

/// Escalate a conditional lock (TYPE V) to a higher authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EscalateConditionalAction {
    /// Lock ID being escalated.
    pub conditional_id: String,
    /// Who is escalating.
    pub escalator_pubkey: Vec<u8>,
    /// "CourtOrder", "DisputeFiled", "AttestorIncapacity", "BondSlash"
    pub escalation_type: String,
    /// BLAKE3 of supporting document.
    pub evidence_hash: Vec<u8>,
    /// Required, public, immutable.
    pub memo: String,
}

/// Declare an attestor group has failed (KXGC or Foundation only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeclareAttestorFailureAction {
    /// TYPE G group that has failed.
    pub group_id: String,
    /// Must be KXGC or Foundation wallet.
    pub declaring_wallet: String,
    /// "CriminalProceeding", "Dissolution", "BondDefaulted", "Incapacitated"
    pub failure_type: String,
    /// BLAKE3 of supporting evidence.
    pub evidence_hash: Vec<u8>,
    /// Required, public, immutable.
    pub memo: String,
}

/// Slash a Tier 1 bond and cascade obligations to KXGC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BondSlashCascadeAction {
    /// Tier 1 bond lock ID to slash.
    pub tier1_bond_id: String,
    /// Amount in chronos to slash.
    pub slash_amount_chronos: u64,
    /// KXGC formally assumes the slashed obligations.
    pub kxgc_assumption: bool,
    /// Required, public, immutable.
    pub memo: String,
}

/// Every state-changing operation in the ChronX DAG is one of these variants.
// TimeLockCreate carries a full DilithiumPublicKey (1312 bytes for Dilithium2). Boxing it
// would push derefs into every match arm across the entire codebase. The size is intentional.
// ── TYPE A — Authority Grant ─────────────────────────────────────────────────

/// Authority tier: Tier1 (granted by KXGC) or Tier2 (sub-granted by Tier1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthorityType {
    Tier1,
    Tier2,
}

/// Status of an authority grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthorityStatus {
    Active,
    PendingRevocation,
    Revoked,
    Expired,
}

/// TYPE A — Authority Grant action.
/// Enables KXGC to authorize Tier 1 participants (and Tier 1 to authorize
/// Tier 2) with specific operational parameters. All grants public on DAG.
/// Revocable with protocol-enforced notice period.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityGrantAction {
    /// The wallet receiving authority.
    pub grantee_wallet: AccountId,
    /// TIER_1 or TIER_2.
    pub authority_type: AuthorityType,
    /// Maximum coverage ratio (total obligations / KX on deposit). e.g. 5.0 = 5x.
    pub max_coverage_ratio: f64,
    /// Maximum fraction MISAI may manage. e.g. 0.25 = 25%.
    pub max_investable_pct: f64,
    /// Absolute hard cap in KX regardless of coverage ratio.
    pub max_obligations_kx: u64,
    /// Whether grantee may authorize the next tier down.
    pub can_subgrant: bool,
    /// Sub-grant max coverage ratio (cannot exceed grantor own limits).
    pub subgrant_max_coverage: f64,
    /// Sub-grant max investable pct (cannot exceed grantor own limits).
    pub subgrant_max_invest: f64,
    /// Activation timestamp (unix UTC).
    pub effective_from: u64,
    /// Expiry timestamp. None = indefinite.
    pub effective_until: Option<u64>,
    /// Notice period in seconds before revocation executes. Default 2592000 (30 days).
    pub revocation_notice_seconds: u64,
    /// Optional memo (public, max 256 bytes).
    pub memo: Option<String>,
}

/// TYPE A — Authority Revoke action.
/// Grantor revokes a previously issued authority grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityRevokeAction {
    /// Reference to original grant vertex.
    pub grant_vertex_id: TxId,
    /// Reason (required, immutable, max 512 bytes).
    pub reason: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Action {
    // ── Transfers ────────────────────────────────────────────────────────────
    /// Send KX from one account to another.
    Transfer {
        to: AccountId,
        amount: Balance,
        #[serde(default)]
        memo: Option<String>,
        #[serde(default = "default_true")]
        memo_encrypted: bool,
        #[serde(default)]
        memo_public: bool,
        /// Target amount in the convert_to_suggestion currency.
        /// Example: convert_to_suggestion="USDC", pay_as_amount=Some(500.0)
        /// means "deliver the KX equivalent of 500 USDC at maturity".
        /// None = plain KX promise, deliver full locked amount.
        #[serde(default)]
        pay_as_amount: Option<f64>,
    },

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
        /// If true (default), memo is encrypted by sender before submission.
        /// Node stores ciphertext only.
        #[serde(default = "default_true")]
        memo_encrypted: bool,
        /// If true, memo is publicly visible. Requires verified sender identity
        /// (TYPE L IdentityVerified) and unlock <= 365 days.
        #[serde(default)]
        memo_public: bool,
        /// Target amount in the convert_to_suggestion currency.
        /// Example: convert_to_suggestion="USDC", pay_as_amount=Some(500.0)
        /// means "deliver the KX equivalent of 500 USDC at maturity".
        /// None = plain KX promise, deliver full locked amount.
        #[serde(default)]
        pay_as_amount: Option<f64>,
        /// What happens if funds are unclaimed after grace period.
        expiry_policy: Option<crate::account::ExpiryPolicy>,
        /// Future multi-recipient split (scaffold, inactive V1).
        split_policy: Option<crate::account::SplitPolicy>,
        /// Max failed claim attempts before Ambiguous mode.
        claim_attempts_max: Option<u8>,
        /// Recurring lock schedule (scaffold, inactive V1).
        recurring: Option<crate::account::RecurringPolicy>,
        /// Reserved bytes for future extensions (max 1 KB).
        lock_marker: Option<Vec<u8>>,
        /// Suggested fiat currency for oracle at claim time.
        oracle_hint: Option<String>,
        /// ISO country code hint for lane selection.
        jurisdiction_hint: Option<String>,
        /// Optional governance proposal link.
        governance_proposal_id: Option<String>,
        /// Client-side deduplication reference (16 bytes, opaque).
        client_ref: Option<[u8; 16]>,
        // ── V3.1 email lock fields ─────────────────────────────────────────────
        /// BLAKE3 hash of recipient's email. Never store plaintext.
        #[serde(default)]
        email_recipient_hash: Option<[u8; 32]>,
        /// Seconds from creation the recipient has to claim before unclaimed_action.
        #[serde(default)]
        claim_window_secs: Option<u64>,
        /// What happens if the claim window expires without a claim.
        #[serde(default)]
        unclaimed_action: Option<crate::account::UnclaimedAction>,
        /// Lock type tag (e.g. "S" = standard, "M" = AI-managed, "Y" = yield-bearing default). Open string field.
        #[serde(default)]
        lock_type: Option<String>,
        /// If true, suppress HedgeKX minting mandate even for TYPE_Y locks.
        #[serde(default)]
        yield_opt_out: Option<bool>,
        /// Arbitrary JSON metadata associated with this lock.
        #[serde(default)]
        lock_metadata: Option<String>,

        // ── — AI Agent management fields ─────────────────────────
        /// If true, this lock's investable fraction is managed by a registered AI agent.
        #[serde(default)]
        agent_managed: Option<bool>,
        /// BLAKE3 of combined promise_axioms+trading_axioms. Required if agent_managed.
        #[serde(default)]
        grantor_axiom_consent_hash: Option<String>,
        /// Fraction of promise value offered for AI investment (0.0 to 1.0).
        #[serde(default)]
        investable_fraction: Option<f64>,
        /// Risk level (1-100) from wallet slider.
        #[serde(default)]
        risk_level: Option<u32>,
        /// Comma-separated exclusion list.
        #[serde(default)]
        investment_exclusions: Option<String>,
        /// Free text grantor intent (max MISAI_LOAN_PACKAGE_MAX_INTENT_CHARS chars).
        #[serde(default)]
        grantor_intent: Option<String>,

        // ── — Sign of Life fields ────────────────────────────
        /// Interval in days between required sign-of-life attestations.
        #[serde(default)]
        sign_of_life_interval_days: Option<u64>,
        /// Grace period in days after missed sign-of-life before guardian transition.
        #[serde(default)]
        sign_of_life_grace_days: Option<u64>,
        /// Guardian pubkey — receives funds if sign of life is missed.
        #[serde(default)]
        guardian_pubkey: Option<DilithiumPublicKey>,
        /// Guardian authority expires at this Unix timestamp.
        #[serde(default)]
        guardian_until: Option<u64>,
        /// Alternate guardian pubkey (backup).
        #[serde(default)]
        alt_guardian_pubkey: Option<DilithiumPublicKey>,
        /// Human-readable beneficiary description (encrypted or plaintext).
        #[serde(default)]
        beneficiary_description: Option<String>,
        /// BLAKE3 hash of the beneficiary description.
        #[serde(default)]
        beneficiary_description_hash: Option<[u8; 32]>,
        /// Suggestion-only field: grantor's preferred conversion currency at maturity.
        /// No protocol behavior — KX always releases as KX. Max 50 chars.
        #[serde(default)]
        convert_to: Option<String>,

        // ── — Wallet Group fields ────────────────────────────
        /// Optional set of wallets/group authorized to claim this lock.
        #[serde(default)]
        authorized_claimants: Option<AuthorizedSet>,
        /// Optional group for succession routing.
        #[serde(default)]
        succession_group: Option<[u8; 32]>,
        /// Optional backup AI executors for Type M locks.
        #[serde(default)]
        backup_executors: Option<Vec<DilithiumPublicKey>>,
        /// Minimum number of executors that must agree (threshold).
        #[serde(default)]
        executor_threshold: Option<u8>,
// Genesis 10a: PAY_AS denomination for this lock        #[serde(default)]        pay_as: Option<PayAsDenomination>,

        /// Verifas beneficiary identification package.
        /// Free-form text encrypted to Verifas HSM public key.
        #[serde(default)]
        beneficiary_package: Option<Vec<u8>>,
        // -- Genesis Zero -- Obligation Transfer fields ----------------------
        #[serde(default)]
        transferable: Option<TransferFlag>,
        #[serde(default)]
        current_owner_account: Option<AccountId>,
        #[serde(default)]
        transfer_history: Option<Vec<TransferRecord>>,
        #[serde(default)]
        terms_visibility: Option<TermsVisibility>,
        #[serde(default)]
        tranche_info: Option<TrancheInfo>,
        #[serde(default)]
        retirement_status: Option<RetirementStatus>,
        #[serde(default)]
        retired_fraction: Option<f64>,
        // -- Escalation --
        #[serde(default)]
        escalation_wallet: Option<String>,
        #[serde(default)]
        escalation_lock_seconds: Option<u64>,

        // -- Attestor group protection --
        /// Fraction of attestor group that must attest (0.0-1.0). Floor: 0.50.
        #[serde(default)]
        min_attestors_pct: Option<f64>,

        // -- Hedge linkage --
        /// Lock IDs of hedge instruments that must be active before this lock is Active.
        #[serde(default)]
        required_hedge_ids: Option<Vec<String>>,

        /// Wallet that receives premium on clean expiry (no trigger fired).
        #[serde(default)]
        success_payment_wallet: Option<String>,

        /// Amount in chronos to pay to success_payment_wallet on clean expiry.
        #[serde(default)]
        success_payment_chronos: Option<u64>,

        // -- Condition type (scaffold -- not yet functional) --
        /// "SingleAttestation" (default), "OracleTrigger", "CompoundAND", "LinkedSpring"
        #[serde(default)]
        condition_type: Option<String>,

        /// Oracle price pair, e.g. "KX/USD". Used with OracleTrigger.
        #[serde(default)]
        oracle_pair: Option<String>,

        /// Fires if price crosses this threshold (e.g. 0.92 = 92% of creation price).
        #[serde(default)]
        oracle_trigger_threshold: Option<f64>,

        /// "Below" or "Above".
        #[serde(default)]
        oracle_trigger_direction: Option<String>,

        /// Used with LinkedSpring -- instrument that must have already fired.
        #[serde(default)]
        linked_instrument_id: Option<String>,

        // ── Extension rights (Genesis Zero — TimeLockExtend) ─────────────
        /// If true: borrower may extend without lender approval (pre-authorized).
        #[serde(default)]
        extension_right: Option<bool>,
        /// Maximum number of extensions permitted (default 1 from governance).
        #[serde(default)]
        max_extensions: Option<u32>,

        // ── TWAP execution (Genesis Zero — PAY_AS) ──────────────────────
        /// PAY_AS execution method. None = governance decides at maturity.
        #[serde(default)]
        pay_as_execution: Option<PayAsExecution>,

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

    // ── Secure email claims ───────────────────────────────────────────────────
    /// Claim an email-based time-lock using a plaintext claim secret.
    ///
    /// The node verifies BLAKE3(claim_secret) against the hash stored during
    /// lock creation (in the `email_claim_hashes` DB tree). If they match and
    /// the claim window has not expired, KX is transferred to the claimer's
    /// account regardless of their public key.
    ///
    /// Added as a NEW variant (discriminant 21) rather than modifying the
    /// existing `TimeLockClaim` variant, to preserve backward compatibility
    /// with all existing serialised vertices in the DAG.
    TimeLockClaimWithSecret {
        lock_id: TimeLockId,
        /// The plaintext claim secret (e.g. "KX-7F3A-9B2C-E1D4-5H6K").
        /// The node computes BLAKE3(claim_secret.as_bytes()) and compares
        /// against the stored hash.
        claim_secret: String,
    },

    /// Manually reclaim an expired email lock whose claim window has passed.
    /// The submitting account must be the original sender. Returns the locked
    /// funds to the sender's balance and sets status to Reverted.
    ReclaimExpiredLock {
        lock_id: TimeLockId,
    },

    // ── — Verified Delivery Protocol ────────────────────────────────
    /// Register a bonded verifier in the on-chain registry.
    /// Only the governance wallet (currently Founder) may submit this action.
    VerifierRegister {
        verifier_name: String,
        wallet_address: String,
        bond_amount_kx: u64,
        dilithium2_public_key_hex: String,
        jurisdiction: String,
        /// "VerifasVault" or "BondedFinder"
        role: String,
    },

    // ── — AI Agent Architecture ─────────────────────────────────
    /// Register an AI agent in the on-chain registry.
    /// Only the governance wallet may submit this action.
    AgentRegister {
        agent_name: String,
        agent_wallet: String,
        agent_code_hash: String,
        kyber_public_key_hex: String,
        operator_wallet: String,
        jurisdiction: String,
    },

    /// Update an agent's code hash and Kyber public key.
    /// Only the operator_wallet of the existing agent record may submit.
    AgentCodeUpdate {
        agent_wallet: String,
        new_code_hash: String,
        new_kyber_public_key_hex: String,
    },

    /// MISAI accepts an agent-managed promise and commits to a return date.
    /// Triggers loan disbursement and encrypted package generation.
    AgentLoanRequest {
        lock_id: String,
        agent_wallet: String,
        investable_fraction: f64,
        proposed_return_date: u64,
        agent_axiom_consent_hash: String,
    },

    // ── MISAI ExecutorWithdraw ────────────────────────────────────────────────
    /// The registered MISAI executor withdraws KX from a live Type M lock
    /// before its maturity date, for the purpose of AI-managed trading.
    ///
    /// Validation:
    /// - lock must be Type M (lock_type == "M")
    /// - signer must be the registered MISAI executor
    /// - destination must match db.get_meta("misai_executor_wallet")
    /// - lock status must be Pending
    /// - lock_metadata must not be null
    /// - rate limit: max 3 per 24-hour window
    ///
    /// On acceptance, lock transitions to PendingExecutor for a configurable
    /// delay (default 24 hours) before finalization.
    ExecutorWithdraw {
        lock_id: TimeLockId,
        /// Where to send the KX (must match registered executor wallet).
        destination: AccountId,
        /// The executor's Dilithium2 public key hex (for verification).
        executor_pubkey: String,
    },

    // ── — TYPE I Invoice ──────────────────────────────────────────
    /// Create a new invoice requesting payment.
    CreateInvoice(CreateInvoiceAction),

    /// Fulfill (pay) an existing invoice.
    FulfillInvoice(FulfillInvoiceAction),

    /// Cancel an open invoice (issuer only).
    CancelInvoice(CancelInvoiceAction),

    // ── — TYPE C Credit Authorization ─────────────────────────────
    /// Authorize a credit line for a beneficiary.
    CreateCredit(CreateCreditAction),

    /// Draw funds from an authorized credit line.
    DrawCredit(DrawCreditAction),

    /// Revoke an open credit line (grantor only).
    RevokeCredit(RevokeCreditAction),

    // ── — TYPE Y Interest Bearing Deposit ─────────────────────────
    /// Create a deposit with interest terms.
    CreateDeposit(CreateDepositAction),

    /// Settle a matured deposit (obligor pays back principal + interest).
    SettleDeposit(SettleDepositAction),

    // ── — TYPE V Conditional Validity ─────────────────────────────
    /// Create a conditional payment requiring attestor approval.
    CreateConditional(CreateConditionalAction),

    /// Attest (approve) a conditional payment.
    AttestConditional(AttestConditionalAction),

    // ── — TYPE L Ledger Entry ─────────────────────────────────────
    /// Create an immutable ledger entry (bonded agents only).
    CreateLedgerEntry(CreateLedgerEntryAction),

    // ── Wallet Group ─────────────────────────────────
    /// Create a new on-chain wallet group.
    CreateGroup(CreateGroupAction),
    /// Add a member to an existing group.
    AddGroupMember(AddGroupMemberAction),
    /// Remove a member from a group.
    RemoveGroupMember(RemoveGroupMemberAction),
    /// Dissolve a group (record kept forever, status = Dissolved).
    DissolveGroup(DissolveGroupAction),
    /// Transfer group ownership to a new owner.
    TransferGroupOwnership(TransferGroupOwnershipAction),

    /// Reject an invoice (payer only). Sets status to Rejected, no KX cost.
    RejectInvoice {
        invoice_id: [u8; 32],
        memo: Option<String>,
    },

    // ── Genesis 10a — Loan Primitives ──────────────────────────────────────

    // -- Loan Offer/Acceptance Protocol (replaces LoanCreate) --
    LoanOffer(LoanOffer),
    LoanAcceptance(LoanAcceptance),
    LoanDecline(LoanDecline),
    LoanOfferWithdrawn(LoanOfferWithdrawn),
    LoanPayerUpdate(LoanPayerUpdate),

    /// MISAI publishes when payment missed > grace_period (MISAI-only, submitted once)
    DefaultRecord {
        loan_id: [u8; 32],
        missed_stage_index: u32,
        missed_amount_kx: u64,
        late_fees_accrued_kx: u64,
        days_overdue: u32,
        outstanding_balance_kx: u64,
        stages_remaining: u32,
        defaulted_at: u64,
        memo: String,
    },

    /// Both parties reinstate a defaulted loan (dual signature, no time limit)
    LoanReinstatement {
        loan_id: [u8; 32],
        cure_amount_kx: u64,
        new_stages: Vec<LoanPaymentStage>,
        memo: Option<String>,
    },

    /// Lender writes off loan — unilateral, irrevocable (lender signature only)
    LoanWriteOff {
        loan_id: [u8; 32],
        outstanding_balance_kx: u64,
        write_off_date: u64,
        memo: Option<String>,
    },

    /// Both parties agree to early payoff per prepayment terms (dual signature)
    LoanEarlyPayoff {
        loan_id: [u8; 32],
        payoff_amount_kx: u64,
        memo: Option<String>,
    },

    /// MISAI publishes when all stages paid (MISAI-only)
    LoanCompletion {
        loan_id: [u8; 32],
        total_paid_kx: u64,
        completion_date: u64,
        stages_completed: u32,
        memo: String,
    },

    /// Lender attaches a memo to a default record (one per default, max 512 chars).
    LenderMemo {
        loan_id: [u8; 32],
        default_record_id: [u8; 32],
        memo: String,
        lender_signature: DilithiumSignature,
    },

    // ── Genesis 10c: Payment Channels ────────────────────────────────
    ChannelOpen {
        channel_id: [u8; 32],
        counterparty: AccountId,
        locked_chronos: u64,
        metadata: Option<String>,
    },
    ChannelClose {
        channel_id: [u8; 32],
        net_settlement_chronos: i64,
        payment_count: u64,
        final_state_hash: [u8; 32],
    },
    // ── Genesis 10c: Loan Exit (explicit exit action) ────────────────
    LoanExit {
        loan_id: [u8; 32],
        exiting_party_signature: DilithiumSignature,
    },

    // ── v2.5.29: Loan secondary market + rescission ──────────────────
    /// Transfer loan to new lender. DISABLED until governance activation.
    LoanTransfer {
        loan_id: String,
        new_lender_wallet: String,
        transfer_price_chronos: u64,
        memo: Option<String>,
    },

    /// Right of rescission cancellation during window.
    /// Available to either party before rescission_expires_at.
    LoanRescissionCancel {
        loan_id: String,
        cancelled_by: String,
        reason: Option<String>,
    },

    /// Waive the rescission period — skip the remaining wait and
    /// activate the loan immediately. Either party may call this.
    LoanRescissionWaive {
        loan_id: String,
        waived_by: String,
    },

    /// Credit history visibility preference.
    /// Latest entry for a wallet wins.
    /// Governed by: credit_visibility_enabled = false (dormant)
    CreditVisibilityUpdate {
        wallet_address: String,
        visibility: CreditVisibility,
    },

    /// Lender or MISAI flags a loan for dispute/review.
    /// governance: loan_flag_post_enabled = false (dormant)
    LoanFlagPost {
        loan_id: [u8; 32],
        flag_type: String,
        posted_by: String,
        memo: Option<String>,
        #[serde(default)]
        dispute_annotation: Option<String>,
    },

    /// Permanent purge of loan payment detail.
    /// governance: credit_history_purge_enabled = false
    CreditHistoryPurge {
        wallet_address: String,
        reason: Option<String>,
        acknowledged_irreversible: bool,
    },

    /// Foundation registers accredited lender.
    /// governance: accredited_lender_registry_enabled = false
    AccreditedLenderRegister {
        lender_wallet: String,
        institution_name: String,
        jurisdiction: String,
        license_reference: Option<String>,
        credit_weight_multiplier: u32,
    },

    /// Foundation revokes accredited lender status.
    /// governance: accredited_lender_registry_enabled = false
    AccreditedLenderRevoke {
        lender_wallet: String,
        reason: Option<String>,
    },

    /// Milestone draw request on a loan
    DrawRequest {
        loan_id: String,
        amount_chronos: u64,
        proof_hash: Option<String>,
        memo: Option<String>,
    },
    /// Approve a draw request
    DrawApproval {
        loan_id: String,
        draw_request_tx_id: String,
        amount_chronos: u64,
    },
    /// Decline a draw request
    DrawDecline {
        loan_id: String,
        draw_request_tx_id: String,
        reason: Option<String>,
    },
    /// Partial exit from an active loan

    // ── TYPE A — Authority Grant ─────────────────────────────────────────────
    /// Grant operational authority to a participant.
    AuthorityGrant(AuthorityGrantAction),

    /// Revoke a previously issued authority grant.
    AuthorityRevoke(AuthorityRevokeAction),

    PartialExit {
        loan_id: String,
        amount_chronos: u64,
    },

    // -- Genesis Zero -- Obligation Transfer actions -------------------------
    /// Transfer ownership of an obligation.
    ObligationTransfer(ObligationTransfer),

    /// Split one obligation into N tranches.
    ObligationTranche(ObligationTranche),

    /// Retire all or part of an obligation.
    ObligationRetire(ObligationRetire),

    /// Update transfer flag (lender only).
    TransferFlagUpdate(TransferFlagUpdate),

    /// Update terms visibility (lender only, either direction).
    TermsVisibilityUpdate(TermsVisibilityUpdate),
    // -- Escalation and failure actions (scaffold) ----------------------------
    /// Escalate a conditional lock to higher authority.
    EscalateConditional(EscalateConditionalAction),

    /// Declare an attestor group has failed.
    DeclareAttestorFailure(DeclareAttestorFailureAction),

    /// Slash a Tier 1 bond and cascade obligations to KXGC.
    BondSlashCascade(BondSlashCascadeAction),

    // ── Savings account actions ──────────────────────────────────────────────
    /// Move KX from spendable balance to savings bucket.
    CreateSavingsDeposit { amount_chronos: u64 },

    /// Move KX from savings bucket back to spendable balance.
    /// If savings is invested, queues withdrawal for next instrument expiry.
    WithdrawSavings { amount_chronos: u64 },

    // ── TYPE_Y: Interest Bearing Deposit — explicit default declaration ──
    /// Either depositor or obligor can declare default after grace period.
    DepositDefault {
        deposit_id: [u8; 32],
    },

    // ── Friendly Loan ──────────────────────────────────────────────────────
    FriendlyLoanCreate {
        borrower_email_hash: [u8; 32],
        borrower_wallet: Option<AccountId>,
        principal_usd: f64,
        term_days: u32,
        kx_collateral_chronos: u64,
        locked_kx_usd_rate: f64,
        repayment_base_address: String,
        memo: Option<String>,
    },
    FriendlyLoanRepay {
        loan_id: [u8; 32],
        repayment_usdc: f64,
        base_tx_hash: String,
    },
    FriendlyLoanWriteOff {
        loan_id: [u8; 32],
    },

    // ── TimeLockExtend (Genesis Zero) ────────────────────────────────────
    /// Extend an existing time-locked promise or loan instrument.
    /// Three trigger variants: lender-offered, borrower-requested, oracle-conditioned.
    TimeLockExtend {
        lock_id: [u8; 32],
        extension_seconds: u64,
        trigger: ExtensionTrigger,
        signature: DilithiumSignature,
        #[serde(default)]
        memo: Option<String>,
    },

    // ── LoanChargeOff (Genesis Zero) ─────────────────────────────────────
    /// Lender's formal accounting declaration that a receivable is no longer
    /// expected to be collected. Does NOT cancel the legal obligation — the DAG
    /// record of the original loan remains permanent and immutable.
    LoanChargeOff {
        loan_id: [u8; 32],
        charged_off_amount_usd: f64,
        charged_off_amount_kx: u128,
        reason: ChargeOffReason,
        #[serde(default)]
        supporting_evidence: Option<String>,
        lender_signature: DilithiumSignature,
        charged_off_at: u64,
        #[serde(default)]
        memo: Option<String>,
    },

}

/// Credit history visibility setting for a wallet.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub enum CreditVisibility {
    #[default]
    Private,
    Public,
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


// ── Genesis 10b — GOVERNANCE PARAMS ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GovernanceParams {
    pub min_loan_size_chronos: Option<u64>,
    pub approved_currencies: Vec<String>,
    pub deprecated_currencies: Vec<DeprecatedCurrency>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeprecatedCurrency {
    pub currency_code: String,
    pub successor_code: Option<String>,
    pub conversion_rate_numerator: Option<u64>,
    pub conversion_rate_denominator: Option<u64>,
}

// ================================================================
// RE-GENESIS 10 -- Collateralized Lending, Escrow, Variable Rates
// ================================================================

// -- Interest Rate Types --
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InterestRate {
    Fixed(u32),                          // basis points, immutable
    Variable {
        spread_bps: u32,                 // margin above index
        adjustment_period_seconds: u64,  // how often rate resets
        cap_bps: Option<u32>,            // maximum rate ceiling
        floor_bps: Option<u32>,          // minimum rate floor
        rate_source: RateSource,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RateSource {
    ExternalOracle(String),   // URL or identifier parties agreed to
    LenderProvided,           // lender submits RateAdjustment each period
    BothPartiesAgree,         // dual signature required each period
}

// -- Payment Match --
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PaymentMatch {
    Exact,
    WithinBps(u16),
    PartialAccepted,
    InstallmentsAllowed {
        count: u8,
        window_seconds: u64,
    },
    MinimumRequired {
        minimum_chronos: u64,
    },
}

// -- Default Triggers --
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DefaultTrigger {
    MissedPayment {
        grace_period_seconds: u64,
    },
    EscrowShortfall {
        escrow_id: [u8; 32],
        grace_period_seconds: u64,
    },
    CollateralUndersecured {
        liquidation_threshold_pct: u8,
    },
    CustomCondition {
        description: String,
        attestor: AccountId,
    },
}

// -- Rate Adjustment --
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RateAdjustment {
    pub loan_id: [u8; 32],
    pub new_rate_bps: u32,
    pub effective_date: u64,
    pub rate_source_snapshot: String,    // what oracle showed on this date
    pub lender_signature: DilithiumSignature,
}

// -- Loan Liquidation (MISAI-submitted) --
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoanLiquidation {
    pub loan_id: [u8; 32],
    pub collateral_lock_id: [u8; 32],
    pub trigger_reason: String,
    pub collateral_value_chronos: u64,
    pub outstanding_chronos: u64,
    pub liquidated_at: u64,
}

// -- Loan Resolution --
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoanResolution {
    pub loan_id: [u8; 32],
    pub resolution_type: ResolutionType,
    pub legal_reference: Option<String>,
    pub lender_signature: DilithiumSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResolutionType {
    CollateralLiquidated {
        proceeds_chronos: u64,
        deficiency_waived: bool,
        deficiency_chronos: Option<u64>,
    },
    CourtOrderedSettlement {
        settlement_amount_chronos: u64,
    },
    DebtForgiven,
    FullSatisfaction,
}

// -- Escrow Types --
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscrowCreate {
    pub escrow_id: [u8; 32],
    pub loan_id: [u8; 32],
    pub servicer: AccountId,
    pub initial_monthly_chronos: u64,
    pub lender_signature: DilithiumSignature,
    pub borrower_signature: DilithiumSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscrowDeposit {
    pub escrow_id: [u8; 32],
    pub loan_id: [u8; 32],
    pub amount_chronos: u64,
    pub period_month: u32,             // YYYYMM format
    pub borrower_signature: DilithiumSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscrowAdjustment {
    pub escrow_id: [u8; 32],
    pub loan_id: [u8; 32],
    pub new_monthly_chronos: u64,
    pub effective_month: u32,          // YYYYMM format
    pub reason: String,                // "Property tax increase, County of X"
    pub months_remaining: u32,
    pub lender_signature: DilithiumSignature,   // lender only -- no borrower sig needed
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscrowDisbursement {
    pub escrow_id: [u8; 32],
    pub loan_id: [u8; 32],
    pub amount_chronos: u64,
    pub payee_description: String,     // "County Tax Authority Q2 2026"
    pub disbursed_at: u64,
    pub lender_signature: DilithiumSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscrowReconciliation {
    pub escrow_id: [u8; 32],
    pub loan_id: [u8; 32],
    pub period_year: u32,
    pub collected_chronos: u64,
    pub disbursed_chronos: u64,
    pub surplus_chronos: i64,          // positive = return to borrower, negative = borrower owes
    pub lender_signature: DilithiumSignature,
}

// -- Micro Loan (AI agents) --
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MicroLoanCreate {
    pub loan_id: [u8; 32],
    pub lender: AccountId,
    pub borrower: AccountId,
    pub principal_chronos: u64,
    pub fee_chronos: u64,              // flat fee, not rate
    pub duration_seconds: u64,
    pub auto_liquidate: bool,          // collateral releases instantly on expiry
    pub collateral_lock_id: Option<[u8; 32]>,
    pub lender_signature: DilithiumSignature,
    pub borrower_signature: DilithiumSignature,
}

// ================================================================
// GENESIS 10 TRULY FINAL
// LoanType, RevivalCondition, ExitRights, LoanExit
// ================================================================

/// Who can exit a revolving loan and under what conditions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Default)]
pub enum ExitRights {
    /// Either party may exit with min_notice_seconds notice.
    #[default]
    EitherParty,
    /// Only the lender may call the loan.
    LenderOnly,
    /// Only the borrower may exit early.
    BorrowerOnly,
    /// Neither party may exit without the other's signed agreement.
    MutualConsent,
}


/// Condition checked by MISAI at each renewal period.
/// If condition fails, loan enters min_notice_seconds wind-down.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Default)]
pub enum RevivalCondition {
    /// Always renews unconditionally. Default.
    #[default]
    Always,
    /// Renews only if oracle reading is strictly below threshold_bps.
    OracleBelow {
        oracle_source: String,
        threshold_bps: u32,
    },
    /// Renews only if oracle reading is strictly above threshold_bps.
    OracleAbove {
        oracle_source: String,
        threshold_bps: u32,
    },
    /// Renews only if oracle reading falls within floor_bps..ceiling_bps.
    OracleBetween {
        oracle_source: String,
        floor_bps: u32,
        ceiling_bps: u32,
    },
    /// Renews only if a bonded attestor submits a signed confirmation.
    CustomAttestation {
        attestor: AccountId,
        description: String,
        attestation_window_seconds: u64,
    },
}


/// The complete loan type field on LoanCreate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Default)]
pub enum LoanType {
    /// Standard fixed payment schedule. Default.
    #[default]
    FixedSchedule,
    /// Revolving credit line.
    Revolving {
        renewal_period_seconds: u64,
        rate_cap_per_period_bps: u32,
        renewal_fee_bps: u32,
        min_notice_seconds: u64,
        #[serde(default)]
        exit_rights: ExitRights,
        max_term_seconds: Option<u64>,
        #[serde(default)]
        revival_condition: RevivalCondition,
    },
}


/// Filed by an eligible party to initiate exit from a revolving loan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoanExit {
    pub loan_id: [u8; 32],
    pub initiated_by: ExitInitiator,
    pub effective_at: u64,
    pub memo: Option<String>,
    pub signature: DilithiumSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExitInitiator {
    Lender,
    Borrower,
    MutualAgreement {
        lender_signature: DilithiumSignature,
        borrower_signature: DilithiumSignature,
    },
}

// ================================================================
// LOAN OFFER / ACCEPTANCE PROTOCOL
// Every loan requires offer + acceptance. No auto-acceptance.
// ================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoanOffer {
    pub loan_id: [u8; 32],
    pub lender_wallet: AccountId,
    pub borrower_wallet: AccountId,
    pub principal_chronos: u64,
    pub pay_as: Option<PayAsDenomination>,
    pub interest_rate: InterestRate,
    pub rate_source_description: Option<String>,
    pub loan_type: LoanType,
    pub payment_match: Option<PaymentMatch>,
    pub default_triggers: Vec<DefaultTrigger>,
    pub collateral_lock_id: Option<[u8; 32]>,
    pub liquidation_threshold_pct: Option<u8>,
    pub escrow_required: bool,
    pub escrow_id: Option<[u8; 32]>,
    pub servicer_portal_url: Option<String>,
    pub authorized_payers: Vec<AuthorizedPayer>,
    #[serde(default)]
    pub payment_source_policy: PaymentSourcePolicy,
    pub offer_expiry_seconds: Option<u64>,
    #[serde(default)]
    pub requires_autopay: bool,
    pub memo: Option<String>,
        #[serde(default)]
    pub channel_id: Option<[u8; 32]>,
    pub lender_signature: DilithiumSignature,
    #[serde(default)]
    pub min_credit_history_months: Option<u32>,
    #[serde(default)]
    pub require_accredited_lender_history: Option<bool>,
    #[serde(default)]
    pub require_public_credit_history: Option<bool>,
    #[serde(default)]
    pub milestone_draws_enabled: Option<bool>,
    #[serde(default)]
    pub lender_only_exit: Option<bool>,
    #[serde(default)]
    pub draw_requestor: Option<String>,
    // -- Genesis Zero -- Obligation Transfer fields --------------------------
    #[serde(default)]
    pub transferable: Option<TransferFlag>,
    #[serde(default)]
    pub current_owner: Option<AccountId>,
    #[serde(default)]
    pub transfer_history: Option<Vec<TransferRecord>>,
    #[serde(default)]
    pub terms_visibility: Option<TermsVisibility>,
    #[serde(default)]
    pub tranche_info: Option<TrancheInfo>,
    #[serde(default)]
    pub retirement_status: Option<RetirementStatus>,
    #[serde(default)]
    pub retired_fraction: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoanAcceptance {
    pub loan_id: [u8; 32],
    pub accepted_at: u64,
    pub borrower_signature: DilithiumSignature,
    /// Borrower self-declares age >= 18.
    #[serde(default)]
    pub age_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoanDecline {
    pub loan_id: [u8; 32],
    pub reason: Option<String>,
    pub declined_at: u64,
    pub borrower_signature: DilithiumSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoanOfferWithdrawn {
    pub loan_id: [u8; 32],
    pub reason: Option<String>,
    pub withdrawn_at: u64,
    pub lender_signature: DilithiumSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoanPayerUpdate {
    pub loan_id: [u8; 32],
    pub update: PayerUpdateAction,
    pub reason: Option<String>,
    pub lender_signature: DilithiumSignature,
    pub borrower_signature: DilithiumSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PayerUpdateAction {
    Add { wallet: AccountId, description: Option<String> },
    Remove { wallet: AccountId },
    Replace { old_wallet: AccountId, new_wallet: AccountId, description: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedPayer {
    pub wallet: AccountId,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Default)]
pub enum PaymentSourcePolicy {
    #[default]
    Open,
    Restricted,
    ExclusiveDelegate { payer: AccountId, description: String },
}


fn default_true() -> bool { true }

// ── ExtensionTrigger (Genesis Zero — TimeLockExtend) ─────────────────────────

/// Three extension trigger types for TimeLockExtend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExtensionTrigger {
    /// Lender proposes an extension; borrower must accept within window.
    LenderOffer {
        offered_by: AccountId,
        acceptance_window_secs: u64,
        requires_borrower_acceptance: bool,
    },
    /// Borrower requests an extension.
    /// If pre_authorized: true was set at lock creation → executes immediately.
    /// If pre_authorized: false → requires lender co-signature.
    BorrowerRequest {
        requested_by: AccountId,
        pre_authorized: bool,
    },
    /// Extension fires automatically when oracle attests condition.
    /// No signature from either party required — the oracle attestation is the trigger.
    OracleCondition {
        oracle_id: String,
        condition: String,
    },
}

// ── ChargeOffReason (Genesis Zero — LoanChargeOff) ───────────────────────────

/// Reason for charging off a loan receivable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChargeOffReason {
    EntityDissolved,
    NoContactExceededThreshold,
    BorrowerDeceased,
    InsolvencyConfirmed,
    OracleConfirmedUnrecoverable,
    Other(String),
}

impl std::fmt::Display for ChargeOffReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChargeOffReason::EntityDissolved => write!(f, "EntityDissolved"),
            ChargeOffReason::NoContactExceededThreshold => write!(f, "NoContactExceededThreshold"),
            ChargeOffReason::BorrowerDeceased => write!(f, "BorrowerDeceased"),
            ChargeOffReason::InsolvencyConfirmed => write!(f, "InsolvencyConfirmed"),
            ChargeOffReason::OracleConfirmedUnrecoverable => write!(f, "OracleConfirmedUnrecoverable"),
            ChargeOffReason::Other(s) => write!(f, "Other({})", s),
        }
    }
}

/// Record stored in the charge_offs sled tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargeOffRecord {
    pub loan_id: [u8; 32],
    pub charged_off_amount_usd: f64,
    pub charged_off_amount_kx: u128,
    pub reason: ChargeOffReason,
    pub supporting_evidence: Option<String>,
    pub lender_wallet: String,
    pub charged_off_at: u64,
    pub memo: Option<String>,
    pub tx_id: String,
}

/// Record stored in the lock_extension_offers sled tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockExtensionOfferRecord {
    pub lock_id: [u8; 32],
    pub extension_seconds: u64,
    pub offered_by: String,
    pub offered_at: u64,
    pub expires_at: u64,
    pub status: String,   // "pending", "accepted", "expired"
    pub tx_id: String,
}

/// Record stored in the lock_extension_requests sled tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockExtensionRequestRecord {
    pub lock_id: [u8; 32],
    pub extension_seconds: u64,
    pub requested_by: String,
    pub requested_at: u64,
    pub status: String,   // "pending", "approved", "executed"
    pub tx_id: String,
}

// ── PayAsExecution (Genesis Zero — TWAP) ─────────────────────────────────────

/// Execution method for PAY_AS KX→USDC conversions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PayAsExecution {
    /// Single conversion at current XChan rate. Default for small transactions.
    Immediate,
    /// Time-Weighted Average Price: spread conversion over time.
    Twap {
        /// Max % of XChan daily volume to sell per day. Default: governance param.
        max_daily_volume_pct: f64,
        /// Execute partial conversion every X hours. Default: 1.
        interval_hours: u32,
        /// Base address for USDC proceeds.
        proceeds_address: String,
        /// Begin immediately on maturity or draw. Default: true.
        auto_start: bool,
        /// If true: promise cannot execute by any other method. Grantor's instruction is final.
        required: bool,
    },
}

/// Record stored in the twap_orders sled tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwapOrderRecord {
    pub order_id: [u8; 32],
    pub source_tx_id: [u8; 32],
    pub wallet: String,
    pub kx_remaining: u128,
    pub kx_total: u128,
    pub max_daily_pct: f64,
    pub interval_hours: u32,
    pub proceeds_address: String,
    pub created_at: u64,
    pub last_executed_at: u64,
    pub status: String,   // "Active", "Complete", "Cancelled"
}

// ── HedgeExecution (Genesis Zero — HedgeKX limit orders + TWAP fills) ────────

/// Execution method for HedgeKX hedge requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HedgeExecution {
    /// Full amount or reject. Default.
    Immediate,
    /// Gradual fill as pool depth allows.
    Twap {
        /// Max % of pool depth to fill per day.
        max_daily_pool_pct: f64,
        /// Execute partial fill every X hours.
        interval_hours: u32,
        /// Accept partial fill if full fill is impossible within hedge duration.
        partial_fill_ok: bool,
    },
}

/// Response from HedgeKX when a hedge request is submitted with rate limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HedgeMatchResponse {
    pub filled_amount_usd: f64,
    pub rejected_reason: Option<String>,
    pub current_market_rate_bps: u32,
    pub suggested_duration_for_limit: Option<u32>,
    pub partial_fill_available_usd: f64,
    pub twap_order_id: Option<[u8; 32]>,
}

/// Record stored in the hedge_twap_orders sled tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HedgeTwapOrderRecord {
    pub order_id: [u8; 32],
    pub wallet: String,
    pub total_usd: f64,
    pub filled_usd: f64,
    pub max_rate_bps: Option<u32>,
    pub max_daily_pool_pct: f64,
    pub interval_hours: u32,
    pub partial_fill_ok: bool,
    pub created_at: u64,
    pub last_filled_at: u64,
    pub status: String,   // "Active", "Complete", "Cancelled", "PartialFill"
}
