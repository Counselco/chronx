use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::{
    RpcInvoiceRecord, RpcCreditRecord, RpcDepositRecord,
    RpcConditionalRecord, RpcLedgerEntryRecord,
    RpcSignOfLifeRecord, RpcPromiseChainRecord,
    RpcIdentityRecord,
    RpcAccount, RpcCascadeDetails, RpcChainStats, RpcClaimState, RpcGenesisInfo,
    RpcGlobalLockStats, RpcHumanityStakeBalance, RpcIncomingTransfer, RpcOutgoingTransfer, RpcNetworkInfo,
    RpcOracleSnapshot, RpcPromiseAxioms, RpcPromiseTriggerStatus, RpcProvider, RpcRecentTx,
    RpcSchema, RpcSearchQuery, RpcTimeLock, RpcVerifierRecord, RpcVersionInfo,
    RpcAgentRecord, RpcAgentLoanRecord, RpcAgentCustodyRecord, RpcAxiomConsentRecord, RpcInvestablePromise, RpcDetailedTx,
    RpcLoanPaymentStage, RpcLoanDefaultRecord, RpcOraclePrice, RpcLoanCounts,
};

/// ChronX JSON-RPC 2.0 API definition.
///
/// All method names are prefixed with "chronx_" via `namespace = "chronx"`.
#[rpc(server, namespace = "chronx")]
pub trait ChronxApi {
    /// Get full account state by base-58 account ID.
    #[method(name = "getAccount")]
    async fn get_account(&self, account_id: String) -> RpcResult<Option<RpcAccount>>;

    /// Get balance in Chronos by base-58 account ID.
    #[method(name = "getBalance")]
    async fn get_balance(&self, account_id: String) -> RpcResult<String>;

    /// Submit a signed transaction. `tx_hex` is hex-encoded bincode(Transaction).
    /// Returns the TxId hex on success.
    #[method(name = "sendTransaction")]
    async fn send_transaction(&self, tx_hex: String) -> RpcResult<String>;

    /// Get a transaction (DAG vertex) by its TxId hex.
    /// Returns decoded transaction details (JSON) or null if not found.
    #[method(name = "getTransaction")]
    async fn get_transaction(&self, tx_id: String) -> RpcResult<Option<RpcDetailedTx>>;

    /// List time-lock contracts where `account_id` is the sender or recipient.
    /// Sorted newest-first.
    #[method(name = "getLocks")]
    async fn get_locks(&self, account_id: String) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return the current DAG tip TxIds (as hex strings).
    #[method(name = "getDagTips")]
    async fn get_dag_tips(&self) -> RpcResult<Vec<String>>;

    /// Return genesis/protocol constants.
    #[method(name = "getGenesisInfo")]
    async fn get_genesis_info(&self) -> RpcResult<RpcGenesisInfo>;

    /// Return the node's P2P identity (peer multiaddress).
    /// Other nodes pass this as `--bootstrap` to connect.
    #[method(name = "getNetworkInfo")]
    async fn get_network_info(&self) -> RpcResult<RpcNetworkInfo>;

    // ── V2 Claims queries ─────────────────────────────────────────────────────

    /// Return all registered certificate providers.
    #[method(name = "getProviders")]
    async fn get_providers(&self) -> RpcResult<Vec<RpcProvider>>;

    /// Return a single provider by base-58 account ID.
    #[method(name = "getProvider")]
    async fn get_provider(&self, provider_id: String) -> RpcResult<Option<RpcProvider>>;

    /// Return all registered certificate schemas.
    #[method(name = "getSchemas")]
    async fn get_schemas(&self) -> RpcResult<Vec<RpcSchema>>;

    /// Return the claim state for a lock (by TxId hex).
    #[method(name = "getClaimState")]
    async fn get_claim_state(&self, lock_id: String) -> RpcResult<Option<RpcClaimState>>;

    /// Return the current oracle snapshot for a trading pair (e.g. "KX/USD").
    #[method(name = "getOracleSnapshot")]
    async fn get_oracle_snapshot(&self, pair: String) -> RpcResult<Option<RpcOracleSnapshot>>;

    // ── V3 New methods ────────────────────────────────────────────────────────

    /// Return a single time-lock contract by its TxId hex.
    #[method(name = "getLockById")]
    async fn get_lock_by_id(&self, lock_id: String) -> RpcResult<Option<RpcTimeLock>>;

    /// Return all **Pending** time-lock contracts where `account_id` is the recipient.
    /// Results are sorted by `unlock_at` ascending.
    #[method(name = "getPendingIncoming")]
    async fn get_pending_incoming(&self, account_id: String) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return paginated time-lock contracts for an account (sender or recipient).
    /// `offset` is the number of records to skip; `limit` is the page size (max 200).
    #[method(name = "getLocksPaged")]
    async fn get_locks_paged(
        &self,
        account_id: String,
        offset: u32,
        limit: u32,
    ) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return aggregate on-chain statistics.
    #[method(name = "getChainStats")]
    async fn get_chain_stats(&self) -> RpcResult<RpcChainStats>;

    /// Return the most recent `limit` transactions (max 200) as lightweight summaries.
    #[method(name = "getRecentTransactions")]
    async fn get_recent_transactions(&self, limit: u32) -> RpcResult<Vec<RpcRecentTx>>;

    /// Return all time-lock contracts whose `unlock_at` falls in [`from_unix`, `to_unix`].
    #[method(name = "getLocksByUnlockDate")]
    async fn get_locks_by_unlock_date(
        &self,
        from_unix: i64,
        to_unix: i64,
    ) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return node and protocol version information.
    #[method(name = "getVersion")]
    async fn get_version(&self) -> RpcResult<RpcVersionInfo>;

    /// Submit a signed `CancelTimeLock` transaction. `tx_hex` is hex-encoded bincode(Transaction).
    /// Returns the TxId hex on success. The transaction must contain exactly one
    /// `Action::CancelTimeLock` action.
    #[method(name = "cancelLock")]
    async fn cancel_lock(&self, tx_hex: String) -> RpcResult<String>;

    /// Search time-lock contracts for `account_id` with optional filters.
    #[method(name = "searchLocks")]
    async fn search_locks(&self, query: RpcSearchQuery) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return aggregate statistics across all active (Pending) timelocks.
    /// Lightweight alternative to fetching all contracts — designed for the public stats bar.
    #[method(name = "getLockStats")]
    async fn get_lock_stats(&self) -> RpcResult<RpcGlobalLockStats>;

    /// Return all time-lock contracts whose `email_recipient_hash` matches `email_hash_hex`.
    /// `email_hash_hex` is the 64-character hex encoding of the 32-byte BLAKE3 hash of the
    /// recipient's email address (lowercase, trimmed, no trailing newline).
    /// Returns only Pending locks sorted newest-first.
    #[method(name = "getEmailLocks")]
    async fn get_email_locks(&self, email_hash_hex: String) -> RpcResult<Vec<RpcTimeLock>>;

    /// Return all incoming transactions for an account: direct transfers received,
    /// claimed email locks, and claimed timelocks. Sorted newest-first.
    /// Max 500 results.
    #[method(name = "getIncomingTransfers")]
    async fn get_incoming_transfers(&self, account_id: String) -> RpcResult<Vec<RpcIncomingTransfer>>;


    /// Return all outgoing transactions for an account: direct transfers sent,
    /// email timelocks, and promise sends. Sorted newest-first.
    /// Max 500 results.
    #[method(name = "getOutgoingTransfers")]
    async fn get_outgoing_transfers(&self, account_id: String) -> RpcResult<Vec<RpcOutgoingTransfer>>;

    // ── V4 Cascade Send ────────────────────────────────────────────────────

    /// Create a cascade of email time-locks in a single transaction.
    /// All locks share one claim_secret_hash. The sender's wallet signs it.
    /// `tx_hex` is hex-encoded bincode(Transaction) containing multiple
    /// TimeLockCreate actions with the same lock_marker (0xC5 + hash).
    /// Returns the TxId hex on success.
    #[method(name = "submitCascade")]
    async fn submit_cascade(&self, tx_hex: String) -> RpcResult<String>;

    /// Return details of a cascade by its claim_secret_hash (hex).
    /// Returns all locks sharing that hash, plus aggregate statistics.
    #[method(name = "getCascadeDetails")]
    async fn get_cascade_details(&self, claim_secret_hash: String) -> RpcResult<RpcCascadeDetails>;


    // ── Verified Delivery Protocol ────────────────────────────

    /// Return all Active verifiers in the on-chain registry.
    #[method(name = "getVerifierRegistry")]
    async fn get_verifier_registry(&self) -> RpcResult<Vec<RpcVerifierRecord>>;

    /// Return the Day 91 trigger status for a lock (by TxId hex).
    /// Returns null if the trigger has not yet fired.
    #[method(name = "getPromiseTriggerStatus")]
    async fn get_promise_trigger_status(&self, lock_id: String) -> RpcResult<Option<RpcPromiseTriggerStatus>>;

    /// Return protocol delivery constants from genesis metadata.
    #[method(name = "getGenesis7Constants")]
    async fn get_genesis7_constants(&self) -> RpcResult<serde_json::Value>;

    /// Return the current balance of the Humanity Stake Pool wallet.
    #[method(name = "getHumanityStakeBalance")]
    async fn get_humanity_stake_balance(&self) -> RpcResult<RpcHumanityStakeBalance>;

    /// Return Promise Axioms and Trading Axioms from genesis metadata.
    #[method(name = "getPromiseAxioms")]
    async fn get_promise_axioms(&self) -> RpcResult<RpcPromiseAxioms>;


    // ── AI Agent Architecture ──────────────────────────────

    /// Return all Active agents in the on-chain registry.
    #[method(name = "getAgentRegistry")]
    async fn get_agent_registry(&self) -> RpcResult<Vec<RpcAgentRecord>>;

    /// Return a single agent loan record by lock_id hex.
    #[method(name = "getAgentLoanRecord")]
    async fn get_agent_loan_record(&self, lock_id: String) -> RpcResult<Option<RpcAgentLoanRecord>>;

    /// Return a single agent custody record by lock_id hex.
    #[method(name = "getAgentCustodyRecord")]
    async fn get_agent_custody_record(&self, lock_id: String) -> RpcResult<Option<RpcAgentCustodyRecord>>;

    /// Return all custody records for an agent wallet.
    #[method(name = "getAgentHistory")]
    async fn get_agent_history(&self, agent_wallet: String) -> RpcResult<Vec<RpcAgentCustodyRecord>>;

    /// Return axiom consent record for a lock_id + party_type ("GRANTOR" or "AGENT").
    #[method(name = "getAxiomConsent")]
    async fn get_axiom_consent(&self, lock_id: String, party_type: String) -> RpcResult<Option<RpcAxiomConsentRecord>>;

    /// Return all investable promises (agent_managed=true, not yet assigned, within investment window).
    #[method(name = "getInvestablePromises")]
    async fn get_investable_promises(&self) -> RpcResult<Vec<RpcInvestablePromise>>;

    /// Return agent architecture constants from genesis metadata as JSON.
    #[method(name = "getGenesis8Constants")]
    async fn get_genesis8_constants(&self) -> RpcResult<serde_json::Value>;

    /// Return MISAI executor's X25519 public key (hex) for lock_metadata encryption.
    #[method(name = "getMisaiPubkey")]
    async fn get_misai_pubkey(&self) -> RpcResult<serde_json::Value>;

    /// Recent transactions with parsed action details (admin dashboard).
    #[method(name = "getRecentTransactionsDetailed")]
    async fn get_recent_transactions_detailed(&self, limit: u32) -> RpcResult<Vec<RpcDetailedTx>>;

    // ── Invoice/Credit/Deposit/Conditional/Ledger queries ───

    /// Return an invoice by its ID (hex).
    #[method(name = "getInvoice")]
    async fn get_invoice(&self, invoice_id_hex: String) -> RpcResult<Option<RpcInvoiceRecord>>;

    /// Return all open invoices where the wallet is issuer or payer.
    #[method(name = "getOpenInvoices")]
    async fn get_open_invoices(&self, wallet: String) -> RpcResult<Vec<RpcInvoiceRecord>>;

    /// Return a credit authorization by its ID (hex).
    #[method(name = "getCreditAuthorization")]
    async fn get_credit_authorization(&self, credit_id_hex: String) -> RpcResult<Option<RpcCreditRecord>>;

    /// Return all open credits where the wallet is grantor or beneficiary.
    #[method(name = "getOpenCredits")]
    async fn get_open_credits(&self, wallet: String) -> RpcResult<Vec<RpcCreditRecord>>;

    /// Return a deposit by its ID (hex).
    #[method(name = "getDeposit")]
    async fn get_deposit(&self, deposit_id_hex: String) -> RpcResult<Option<RpcDepositRecord>>;

    /// Return all active/matured deposits for a wallet.
    #[method(name = "getActiveDeposits")]
    async fn get_active_deposits(&self, wallet: String) -> RpcResult<Vec<RpcDepositRecord>>;

    /// Return a conditional payment by its type_v_id (hex).
    #[method(name = "getConditionalPayment")]
    async fn get_conditional_payment(&self, type_v_id_hex: String) -> RpcResult<Option<RpcConditionalRecord>>;

    /// Return all ledger entries for a promise (by promise_id hex).
    #[method(name = "getLedgerEntries")]
    async fn get_ledger_entries(&self, promise_id_hex: String) -> RpcResult<Vec<RpcLedgerEntryRecord>>;

    // ── Sign of Life and Promise Chain queries ──────────

    /// Return sign-of-life status for a lock.
    #[method(name = "getSignOfLifeStatus")]
    async fn get_sign_of_life_status(&self, lock_id: String) -> RpcResult<Option<RpcSignOfLifeRecord>>;

    /// Return promise chain metadata by promise_id (hex).
    #[method(name = "getPromiseChain")]
    async fn get_promise_chain(&self, promise_id_hex: String) -> RpcResult<Option<RpcPromiseChainRecord>>;

    /// Return promise chain anchor history by promise_id (hex).
    #[method(name = "getPromiseChainAnchors")]
    async fn get_promise_chain_anchors(&self, promise_id_hex: String) -> RpcResult<Option<RpcPromiseChainRecord>>;

    // ── Identity Verification queries ───────────────────────────────

    /// Return the latest verified identity for a wallet (or null if none).
    #[method(name = "getVerifiedIdentity")]
    async fn get_verified_identity(&self, wallet_b58: String) -> RpcResult<Option<RpcIdentityRecord>>;

    /// Return all identity-related TYPE L entries for a wallet.
    #[method(name = "getIdentityHistory")]
    async fn get_identity_history(&self, wallet_b58: String) -> RpcResult<Vec<RpcLedgerEntryRecord>>;

    // ── Wallet Group queries ─────────────────────────

    /// Return a wallet group by its group_id (hex).
    #[method(name = "getGroup")]
    async fn get_group(&self, group_id_hex: String) -> RpcResult<Option<serde_json::Value>>;

    /// Check if a public key is a member of a group.
    #[method(name = "isGroupMember")]
    async fn is_group_member(&self, group_id_hex: String, pubkey_hex: String) -> RpcResult<serde_json::Value>;

    /// Submit a signed `RejectInvoice` transaction. `tx_hex` is hex-encoded bincode(Transaction).
    /// Returns the TxId hex on success. The transaction must contain exactly one
    /// `Action::RejectInvoice` action.
    #[method(name = "rejectInvoice")]
    async fn reject_invoice(&self, tx_hex: String) -> RpcResult<String>;

    // ── Genesis 10a — Loan queries ──────────────────────────────────────

    /// Return a single loan record by loan_id (hex).
    #[method(name = "getLoan")]
    async fn get_loan(&self, loan_id_hex: String) -> RpcResult<Option<serde_json::Value>>;

    /// Return all loans where the given wallet is lender or borrower.
    #[method(name = "getLoansByWallet")]
    async fn get_loans_by_wallet(&self, wallet_address: String) -> RpcResult<Vec<serde_json::Value>>;

    /// Return payment stage status for a loan.
    #[method(name = "getLoanPaymentHistory")]
    async fn get_loan_payment_history(&self, loan_id_hex: String) -> RpcResult<Vec<RpcLoanPaymentStage>>;

    /// Return the default record for a loan, if one exists.
    #[method(name = "getLoanDefaultRecord")]
    async fn get_loan_default_record(&self, loan_id_hex: String) -> RpcResult<Option<RpcLoanDefaultRecord>>;

    /// Return oracle price for a trading pair.
    #[method(name = "getOraclePrice")]
    async fn get_oracle_price_record(&self, pair: String) -> RpcResult<Option<RpcOraclePrice>>;

    /// Return counts of loans by status.
    #[method(name = "getActiveLoanCount")]
    async fn get_active_loan_count(&self) -> RpcResult<RpcLoanCounts>;

    // ── Genesis 10b — LenderMemo + Governance queries ────────────────────

    /// Return all lender memos for a given loan_id (hex).
    #[method(name = "getLenderMemos")]
    async fn get_lender_memos(&self, loan_id_hex: String) -> RpcResult<Vec<serde_json::Value>>;

    /// Return current governance parameters.
    #[method(name = "getGovernanceParams")]
    async fn get_governance_params(&self) -> RpcResult<serde_json::Value>;

    // -- RE-GENESIS 10: Escrow + MicroLoan queries --

    /// Return escrow account details by escrow_id hex.
    #[method(name = "getEscrow")]
    async fn get_escrow(&self, escrow_id_hex: String) -> RpcResult<Option<serde_json::Value>>;

    /// Return escrow deposit history by escrow_id hex.
    #[method(name = "getEscrowHistory")]
    async fn get_escrow_history(&self, escrow_id_hex: String) -> RpcResult<Vec<serde_json::Value>>;

    /// Return micro-loan record by loan_id hex.
    #[method(name = "getMicroLoan")]
    async fn get_micro_loan(&self, loan_id_hex: String) -> RpcResult<Option<serde_json::Value>>;

    /// Return pending loan offers for a borrower wallet.
    #[method(name = "getLoanOffers")]
    async fn get_loan_offers(&self, wallet_b58: String) -> RpcResult<Vec<serde_json::Value>>;

    /// Return loans by status for a wallet.
    #[method(name = "getLoansByStatus")]
    async fn get_loans_by_status(&self, wallet_b58: String, status: String) -> RpcResult<Vec<serde_json::Value>>;

    /// Return channel info by channel_id hex.
    #[method(name = "getChannelInfo")]
    async fn get_channel_info(&self, channel_id_hex: String) -> RpcResult<serde_json::Value>;




    // ── TYPE A — Authority Grant queries ────────────────────────────────────

    /// Return all authority grants where the wallet is grantor or grantee.
    #[method(name = "getAuthorityGrants")]
    async fn get_authority_grants(&self, wallet_b58: String) -> RpcResult<serde_json::Value>;

    /// Return KXGC bond wallet capacity and reserve status.
    #[method(name = "getKXGCCapacity")]
    async fn get_kxgc_capacity(&self) -> RpcResult<serde_json::Value>;


    // -- Genesis Zero -- Obligation Transfer RPC queries ----------------------

    /// Return the current owner of an obligation.
    #[method(name = "getObligationOwner")]
    async fn get_obligation_owner(&self, obligation_id: String) -> RpcResult<serde_json::Value>;

    /// Return the transfer history of an obligation.
    #[method(name = "getTransferHistory")]
    async fn get_transfer_history(&self, obligation_id: String) -> RpcResult<serde_json::Value>;

    /// Return all obligations owned by a wallet.
    #[method(name = "getObligationsByOwner")]
    async fn get_obligations_by_owner(&self, wallet: String) -> RpcResult<serde_json::Value>;

    /// Return all tranches of a parent obligation.
    #[method(name = "getTranches")]
    async fn get_tranches(&self, parent_obligation_id: String) -> RpcResult<serde_json::Value>;

    /// Return yield inputs for an obligation (respects terms_visibility).
    #[method(name = "getYieldInputs")]
    async fn get_yield_inputs(&self, obligation_id: String) -> RpcResult<serde_json::Value>;

    /// Return obligation status summary.
    #[method(name = "getObligationStatus")]
    async fn get_obligation_status(&self, obligation_id: String) -> RpcResult<serde_json::Value>;


    // -- Escalation/failure/hedge scaffold RPC methods ------------------------

    /// Get escalation status for a conditional lock.
    #[method(name = "getEscalationStatus")]
    async fn get_escalation_status(&self, conditional_id: String) -> RpcResult<serde_json::Value>;

    /// Get all declared attestor failures.
    #[method(name = "getAttestorFailures")]
    async fn get_attestor_failures(&self) -> RpcResult<serde_json::Value>;

    /// Get all locks affected by a group failure.
    #[method(name = "getAffectedPolicies")]
    async fn get_affected_policies(&self, group_id: String) -> RpcResult<serde_json::Value>;

    /// Get hedge instruments linked to a pool.
    #[method(name = "getHedgeInstruments")]
    async fn get_hedge_instruments(&self, pool_id: String) -> RpcResult<serde_json::Value>;

    /// Get linked spring instrument status.
    #[method(name = "getLinkedSpringStatus")]
    async fn get_linked_spring_status(&self, instrument_id: String) -> RpcResult<serde_json::Value>;

    /// Get pool health score (cached, null until MISAI populates).
    #[method(name = "getPoolHealthScore")]
    async fn get_pool_health_score(&self, pool_id: String) -> RpcResult<serde_json::Value>;


    /// Return partial release history for a conditional lock.
    #[method(name = "getPartialReleaseHistory")]
    async fn get_partial_release_history(&self, lock_id: String) -> RpcResult<serde_json::Value>;


    /// Return oracle trigger status for a conditional lock.
    #[method(name = "getOracleTriggerStatus")]
    async fn get_oracle_trigger_status(&self, lock_id: String) -> RpcResult<serde_json::Value>;

    /// Return all pending draw requests.
    #[method(name = "getPendingDrawRequests")]
    async fn get_pending_draw_requests(&self) -> RpcResult<serde_json::Value>;

}
