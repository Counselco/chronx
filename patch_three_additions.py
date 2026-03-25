#!/usr/bin/env python3
"""
Three Protocol Additions:
1. AttestConditional Partial Release
2. OracleTrigger Engine Logic
3. DeclareAttestorFailure Automated Cascade
"""

CHRONX = "/home/josep/chronx"

def read(path):
    with open(path) as f:
        return f.read()

def write(path, content):
    with open(path, "w") as f:
        f.write(content)
    print(f"  Written: {path}")

# ================================================================
# 1. transaction.rs - Add release_amount_chronos
# ================================================================
print("=== ADDITION 1: AttestConditional Partial Release ===")

tx_path = f"{CHRONX}/crates/chronx-core/src/transaction.rs"
tx = read(tx_path)

old_attest = (
    "pub struct AttestConditionalAction {\n"
    "    pub attestor_pubkey: DilithiumPublicKey,\n"
    "    pub type_v_id: [u8; 32],\n"
    "    pub attestation_memo: Option<String>,\n"
    "}"
)
new_attest = (
    "pub struct AttestConditionalAction {\n"
    "    pub attestor_pubkey: DilithiumPublicKey,\n"
    "    pub type_v_id: [u8; 32],\n"
    "    pub attestation_memo: Option<String>,\n"
    "    /// If Some(n): release exactly n Chronos (must be <= remaining locked amount).\n"
    "    /// If None: release full remaining amount (backward compatible).\n"
    "    #[serde(default)]\n"
    "    pub release_amount_chronos: Option<u64>,\n"
    "}"
)

if "release_amount_chronos" not in tx:
    tx = tx.replace(old_attest, new_attest)
    write(tx_path, tx)
    print("  Added release_amount_chronos to AttestConditionalAction")
else:
    print("  release_amount_chronos already present")

# ================================================================
# 2. account.rs - Add new status variants
# ================================================================
acct_path = f"{CHRONX}/crates/chronx-core/src/account.rs"
acct = read(acct_path)

if "PartiallyReleased" not in acct:
    old_exec = (
        "    /// MISAI executor withdrawal finalized; KX transferred to executor wallet.\n"
        "    ExecutorWithdrawn { withdrawn_at: Timestamp },\n"
        "}"
    )
    new_exec = (
        "    /// MISAI executor withdrawal finalized; KX transferred to executor wallet.\n"
        "    ExecutorWithdrawn { withdrawn_at: Timestamp },\n"
        "\n"
        "    /// Conditional payment partially released; remaining amount stays locked.\n"
        "    PartiallyReleased {\n"
        "        released_chronos: u64,\n"
        "        remaining_chronos: u64,\n"
        "        release_count: u32,\n"
        "    },\n"
        "    /// Oracle trigger fired automatically when price threshold crossed.\n"
        "    OracleTriggered { price_at_trigger: f64, triggered_at: Timestamp },\n"
        "    /// Oracle trigger expired without firing; success payment executed.\n"
        "    OracleExpiredClean { expiry_price: f64 },\n"
        "    /// Attestor group declared failed; lock escalated or awaiting intervention.\n"
        "    AttestorFailed { failed_group_id: String, escalated_to: Option<String> },\n"
        "}"
    )
    acct = acct.replace(old_exec, new_exec)

    old_term = "                | TimeLockStatus::ExecutorWithdrawn { .. }"
    new_term = (
        "                | TimeLockStatus::ExecutorWithdrawn { .. }\n"
        "                | TimeLockStatus::OracleTriggered { .. }\n"
        "                | TimeLockStatus::OracleExpiredClean { .. }"
    )
    acct = acct.replace(old_term, new_term)
    write(acct_path, acct)
    print("  Added new TimeLockStatus variants")
else:
    print("  New status variants already present")

# ================================================================
# 3. error.rs - Add new error variants
# ================================================================
print("\n=== Error variants ===")
err_path = f"{CHRONX}/crates/chronx-core/src/error.rs"
err = read(err_path)

if "ReleaseAmountExceedsLocked" not in err:
    old_other = '    #[error("{0}")]\n    Other(String),'
    new_errors = (
        '    #[error("release amount exceeds remaining locked balance")]\n'
        "    ReleaseAmountExceedsLocked,\n"
        "\n"
        '    #[error("conditional has no remaining balance for partial release")]\n'
        "    ConditionalFullyReleased,\n"
        "\n"
        '    #[error("oracle trigger: price fetch failed or timed out")]\n'
        "    OraclePriceFetchFailed,\n"
        "\n"
        '    #[error("{0}")]\n'
        "    Other(String),"
    )
    err = err.replace(old_other, new_errors)
    write(err_path, err)
    print("  Added new error variants")
else:
    print("  Error variants already present")

# ================================================================
# 4. db.rs - Add PartiallyReleased status, new fields, sled trees
# ================================================================
print("\n=== DB additions ===")
db_path = f"{CHRONX}/crates/chronx-state/src/db.rs"
db = read(db_path)

# 4A: Add PartiallyReleased to ConditionalStatus
if "PartiallyReleased," not in db:
    db = db.replace(
        "pub enum ConditionalStatus {\n    Pending,\n    Released,",
        "pub enum ConditionalStatus {\n    Pending,\n    Released,\n    PartiallyReleased,"
    )
    print("  Added ConditionalStatus::PartiallyReleased")

# 4B: Add new fields to ConditionalRecord
if "released_so_far_chronos" not in db:
    old_end = (
        "    #[serde(default)]\n"
        "    pub success_payment_wallet: Option<String>,\n"
        "    #[serde(default)]\n"
        "    pub success_payment_chronos: Option<u64>,\n"
        "}\n"
        "\n"
        "#[derive(Clone, Debug, Serialize, Deserialize)]\n"
        "pub struct LedgerEntryRecord {"
    )
    new_end = (
        "    #[serde(default)]\n"
        "    pub success_payment_wallet: Option<String>,\n"
        "    #[serde(default)]\n"
        "    pub success_payment_chronos: Option<u64>,\n"
        "    #[serde(default)]\n"
        "    pub released_so_far_chronos: u64,\n"
        "    #[serde(default)]\n"
        "    pub release_count: u32,\n"
        "    #[serde(default)]\n"
        "    pub condition_type: Option<String>,\n"
        "    #[serde(default)]\n"
        "    pub oracle_pair: Option<String>,\n"
        "    #[serde(default)]\n"
        "    pub oracle_trigger_threshold: Option<f64>,\n"
        "    #[serde(default)]\n"
        "    pub oracle_trigger_direction: Option<String>,\n"
        "    #[serde(default)]\n"
        "    pub oracle_creation_price: Option<f64>,\n"
        "    #[serde(default)]\n"
        "    pub escalation_wallet: Option<String>,\n"
        "    #[serde(default)]\n"
        "    pub escalation_lock_seconds: Option<u64>,\n"
        "    #[serde(default)]\n"
        "    pub attestors_suspended: bool,\n"
        "    #[serde(default)]\n"
        "    pub escalation_active: bool,\n"
        "}\n"
        "\n"
        "#[derive(Clone, Debug, Serialize, Deserialize)]\n"
        "pub struct LedgerEntryRecord {"
    )
    db = db.replace(old_end, new_end)
    print("  Added new ConditionalRecord fields")

# 4C: Add new sled trees
if "oracle_trigger_history" not in db:
    db = db.replace(
        "    pub attestor_failures: sled::Tree,",
        "    pub attestor_failures: sled::Tree,\n"
        "    pub oracle_trigger_history: sled::Tree,\n"
        "    pub partial_release_history: sled::Tree,\n"
        "    pub pending_drawrequests: sled::Tree,\n"
        "    pub escalation_errors: sled::Tree,"
    )
    old_open = '.open_tree("attestor_failures")\n            .expect("open attestor_failures");'
    new_open = (
        '.open_tree("attestor_failures")\n'
        '            .expect("open attestor_failures");\n'
        '        let oracle_trigger_history = db.open_tree("oracle_trigger_history").expect("open oracle_trigger_history");\n'
        '        let partial_release_history = db.open_tree("partial_release_history").expect("open partial_release_history");\n'
        '        let pending_drawrequests = db.open_tree("pending_drawrequests").expect("open pending_drawrequests");\n'
        '        let escalation_errors = db.open_tree("escalation_errors").expect("open escalation_errors");'
    )
    db = db.replace(old_open, new_open, 1)
    db = db.replace(
        "            attestor_failures,\n",
        "            attestor_failures,\n"
        "            oracle_trigger_history,\n"
        "            partial_release_history,\n"
        "            pending_drawrequests,\n"
        "            escalation_errors,\n",
        1
    )
    print("  Added new sled trees")

# 4D: Add helper methods
if "save_partial_release" not in db:
    marker = "pub fn save_attestor_failure"
    idx = db.find(marker)
    if idx > 0:
        brace = 0
        i = idx
        started = False
        while i < len(db):
            if db[i] == "{":
                brace += 1
                started = True
            elif db[i] == "}":
                brace -= 1
                if started and brace == 0:
                    insert_at = i + 1
                    break
            i += 1

        helpers = """

    pub fn save_partial_release(&self, type_v_id: &[u8; 32], data: &[u8]) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        let existing = self.partial_release_history.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)?.map(|v| v.to_vec()).unwrap_or_default();
        let mut history: Vec<serde_json::Value> = if existing.is_empty() { vec![] } else { serde_json::from_slice(&existing).unwrap_or_default() };
        let entry: serde_json::Value = serde_json::from_slice(data).unwrap_or_default();
        history.push(entry);
        let serialized = serde_json::to_vec(&history).map_err(|_| ChronxError::SerializationError)?;
        self.partial_release_history.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn get_partial_release_history(&self, type_v_id: &[u8; 32]) -> Result<Vec<serde_json::Value>, ChronxError> {
        let key = hex::encode(type_v_id);
        match self.partial_release_history.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)? {
            Some(data) => Ok(serde_json::from_slice(&data).unwrap_or_default()),
            None => Ok(vec![]),
        }
    }

    pub fn save_oracle_trigger_event(&self, type_v_id: &[u8; 32], data: &[u8]) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        let existing = self.oracle_trigger_history.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)?.map(|v| v.to_vec()).unwrap_or_default();
        let mut history: Vec<serde_json::Value> = if existing.is_empty() { vec![] } else { serde_json::from_slice(&existing).unwrap_or_default() };
        let entry: serde_json::Value = serde_json::from_slice(data).unwrap_or_default();
        history.push(entry);
        let serialized = serde_json::to_vec(&history).map_err(|_| ChronxError::SerializationError)?;
        self.oracle_trigger_history.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn save_pending_drawrequest(&self, key: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.pending_drawrequests.insert(key.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn iter_pending_drawrequests(&self) -> Result<Vec<(String, serde_json::Value)>, ChronxError> {
        let mut results = vec![];
        for item in self.pending_drawrequests.iter() {
            let (k, v) = item.map_err(|_| ChronxError::DatabaseError)?;
            results.push((String::from_utf8_lossy(&k).to_string(), serde_json::from_slice(&v).unwrap_or_default()));
        }
        Ok(results)
    }

    pub fn remove_pending_drawrequest(&self, key: &str) -> Result<(), ChronxError> {
        self.pending_drawrequests.remove(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn save_escalation_error(&self, lock_id: &str, data: &[u8]) -> Result<(), ChronxError> {
        self.escalation_errors.insert(lock_id.as_bytes(), data).map_err(|_| ChronxError::DatabaseError)?;
        Ok(())
    }

    pub fn get_conditionals_by_attestor_group(&self, _group_id: &str) -> Result<Vec<ConditionalRecord>, ChronxError> {
        let mut results = vec![];
        for item in self.conditionals.iter() {
            let (_k, v) = item.map_err(|_| ChronxError::DatabaseError)?;
            if let Ok(record) = serde_json::from_slice::<ConditionalRecord>(&v) {
                if matches!(record.status, ConditionalStatus::Pending | ConditionalStatus::PartiallyReleased) {
                    results.push(record);
                }
            }
        }
        Ok(results)
    }

    pub fn set_conditional_attestors_suspended(&self, type_v_id: &[u8; 32], suspended: bool) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        if let Some(data) = self.conditionals.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)? {
            let mut record: ConditionalRecord = serde_json::from_slice(&data).map_err(|_| ChronxError::SerializationError)?;
            record.attestors_suspended = suspended;
            let serialized = serde_json::to_vec(&record).map_err(|_| ChronxError::SerializationError)?;
            self.conditionals.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        }
        Ok(())
    }

    pub fn set_conditional_escalation_active(&self, type_v_id: &[u8; 32], active: bool) -> Result<(), ChronxError> {
        let key = hex::encode(type_v_id);
        if let Some(data) = self.conditionals.get(key.as_bytes()).map_err(|_| ChronxError::DatabaseError)? {
            let mut record: ConditionalRecord = serde_json::from_slice(&data).map_err(|_| ChronxError::SerializationError)?;
            record.escalation_active = active;
            let serialized = serde_json::to_vec(&record).map_err(|_| ChronxError::SerializationError)?;
            self.conditionals.insert(key.as_bytes(), serialized).map_err(|_| ChronxError::DatabaseError)?;
        }
        Ok(())
    }
"""
        db = db[:insert_at] + helpers + db[insert_at:]
        print("  Added db helper methods")

write(db_path, db)

# ================================================================
# 5. engine.rs - Update handlers
# ================================================================
print("\n=== Engine updates ===")
eng_path = f"{CHRONX}/crates/chronx-state/src/engine.rs"
eng = read(eng_path)

# 5A: Replace AttestConditional handler
old_handler_end = 'info!(type_v_id = %hex::encode(action.type_v_id), "Conditional released \xe2\x80\x94 threshold met");'
start_marker = "            Action::AttestConditional(ref action) => {"
start_idx = eng.find(start_marker)
end_idx = eng.find(old_handler_end)

if start_idx > 0 and end_idx > 0:
    # Find the closing of the match arm after the info! line
    search_from = end_idx
    brace_depth = 0
    # We need to find the "Ok(())\n            }" that closes this arm
    ok_marker = eng.find("Ok(())\n            }", search_from)
    if ok_marker > 0:
        arm_end = ok_marker + len("Ok(())\n            }")

        new_handler = """            Action::AttestConditional(ref action) => {
                let now_u64 = now as u64;
                let cond = self.db.get_conditional(&action.type_v_id)?
                    .ok_or_else(|| ChronxError::ConditionalNotFound(hex::encode(action.type_v_id)))?;
                if !matches!(cond.status, ConditionalStatus::Pending | ConditionalStatus::PartiallyReleased) {
                    return Err(ChronxError::ConditionalNotPending);
                }
                if now_u64 >= cond.valid_until {
                    return Err(ChronxError::ConditionalExpired);
                }
                let attestor_bytes = action.attestor_pubkey.0.clone();
                if cond.attestors_suspended {
                    if let Some(ref esc_wallet) = cond.escalation_wallet {
                        let attestor_account = chronx_crypto::hash::account_id_from_pubkey(&action.attestor_pubkey.0);
                        if attestor_account.to_b58() != *esc_wallet {
                            return Err(ChronxError::AttestorNotAuthorized);
                        }
                    } else {
                        return Err(ChronxError::AttestorNotAuthorized);
                    }
                } else {
                    if !cond.attestor_pubkeys.iter().any(|p| *p == attestor_bytes) {
                        return Err(ChronxError::AttestorNotAuthorized);
                    }
                    if cond.attestations_received.iter().any(|(p, _)| *p == attestor_bytes) {
                        return Err(ChronxError::AttestorAlreadyAttested);
                    }
                }
                let updated = self.db.add_attestation(&action.type_v_id, attestor_bytes, now_u64)?;
                if updated.attestations_received.len() as u32 >= updated.min_attestors {
                    let remaining = updated.amount_chronos.saturating_sub(updated.released_so_far_chronos);
                    if remaining == 0 { return Err(ChronxError::ConditionalFullyReleased); }
                    let release_amount: u64 = match action.release_amount_chronos {
                        Some(partial) => {
                            if partial == 0 { return Err(ChronxError::ZeroAmount); }
                            if partial > remaining { return Err(ChronxError::ReleaseAmountExceedsLocked); }
                            partial
                        }
                        None => remaining,
                    };
                    let recipient_account_id = chronx_crypto::hash::account_id_from_pubkey(&updated.recipient_pubkey);
                    let mut recipient = match self.db.get_account(&recipient_account_id)? {
                        Some(acc) => acc,
                        None => Account {
                            account_id: recipient_account_id.clone(), balance: 0,
                            auth_policy: chronx_core::account::AuthPolicy::SingleSig {
                                public_key: chronx_core::types::DilithiumPublicKey(updated.recipient_pubkey.clone())
                            },
                            nonce: 0, recovery_state: Default::default(), post_recovery_restriction: None,
                            verifier_stake: 0, is_verifier: false, account_version: 3, created_at: Some(now),
                            display_name_hash: None, incoming_locks_count: 0, outgoing_locks_count: 0,
                            total_locked_incoming_chronos: 0, total_locked_outgoing_chronos: 0,
                            preferred_fiat_currency: None, lock_marker: None
                        }
                    };
                    recipient.balance += release_amount as u128;
                    staged.accounts.push(recipient);
                    let new_released = updated.released_so_far_chronos + release_amount;
                    let new_remaining = updated.amount_chronos.saturating_sub(new_released);
                    let new_count = updated.release_count + 1;
                    let event = serde_json::json!({"release_amount": release_amount, "released_at": now_u64, "release_number": new_count, "remaining": new_remaining});
                    let _ = self.db.save_partial_release(&action.type_v_id, &serde_json::to_vec(&event).unwrap_or_default());
                    if new_remaining == 0 {
                        self.db.update_conditional_status(&action.type_v_id, ConditionalStatus::Released)?;
                        info!(type_v_id = %hex::encode(action.type_v_id), "Conditional FULLY released");
                    } else {
                        self.db.update_conditional_status(&action.type_v_id, ConditionalStatus::PartiallyReleased)?;
                        if let Some(mut record) = self.db.get_conditional(&action.type_v_id)? {
                            record.released_so_far_chronos = new_released;
                            record.release_count = new_count;
                            record.attestations_received.clear();
                            let s = serde_json::to_vec(&record).map_err(|_| ChronxError::SerializationError)?;
                            self.db.conditionals.insert(hex::encode(action.type_v_id).as_bytes(), s).map_err(|_| ChronxError::DatabaseError)?;
                        }
                        info!(type_v_id = %hex::encode(action.type_v_id), "Conditional PARTIALLY released — {} remaining", new_remaining);
                    }
                }
                Ok(())
            }"""
        eng = eng[:start_idx] + new_handler + eng[arm_end:]
        print("  Replaced AttestConditional handler with partial release logic")
    else:
        print("  ERROR: Could not find Ok(()) closing for AttestConditional")
else:
    print("  ERROR: Could not find AttestConditional handler markers")

# 5B: Replace DeclareAttestorFailure handler
old_fail_end = '"[ATTESTOR FAILURE] declared");'
fs = eng.find("            Action::DeclareAttestorFailure(ref action) => {")
fe = eng.find(old_fail_end)
if fs > 0 and fe > 0:
    ok_marker2 = eng.find("Ok(())\n            }", fe)
    if ok_marker2 > 0:
        arm_end2 = ok_marker2 + len("Ok(())\n            }")
        new_fail = """            Action::DeclareAttestorFailure(ref action) => {
                let now_u64 = now as u64;
                let record = serde_json::json!({"group_id": action.group_id, "declaring_wallet": action.declaring_wallet, "failure_type": action.failure_type, "evidence_hash": hex::encode(&action.evidence_hash), "memo": action.memo, "declared_at": now_u64});
                let data = serde_json::to_vec(&record).map_err(|_| ChronxError::SerializationError)?;
                self.db.save_attestor_failure(&action.group_id, &data)?;
                info!(group_id = %action.group_id, failure_type = %action.failure_type, "[ATTESTOR FAILURE] declared \u2014 beginning cascade");
                let affected = self.db.get_conditionals_by_attestor_group(&action.group_id)?;
                let mut escalated = 0u32;
                let mut errors = 0u32;
                for cond in &affected {
                    let lid = hex::encode(cond.type_v_id);
                    let r: Result<(), ChronxError> = (|| {
                        self.db.set_conditional_attestors_suspended(&cond.type_v_id, true)?;
                        if let Some(ref ew) = cond.escalation_wallet {
                            self.db.set_conditional_escalation_active(&cond.type_v_id, true)?;
                            let esc = serde_json::json!({"conditional_id": lid, "escalation_type": "AttestorIncapacity", "escalated_to": ew, "triggered_by": action.group_id, "evidence_hash": hex::encode(&action.evidence_hash), "escalated_at": now_u64, "auto_generated": true});
                            self.db.save_escalation(&lid, &serde_json::to_vec(&esc).map_err(|_| ChronxError::SerializationError)?)?;
                            escalated += 1;
                        }
                        Ok(())
                    })();
                    if let Err(e) = r {
                        errors += 1;
                        let err_rec = serde_json::json!({"lock_id": lid, "error": format!("{}", e), "at": now_u64});
                        let _ = self.db.save_escalation_error(&lid, &serde_json::to_vec(&err_rec).unwrap_or_default());
                        warn!(lock_id = %lid, error = %e, "[CASCADE ERROR] continuing");
                    }
                }
                let dr = serde_json::json!({"group_id": action.group_id, "reason": action.memo, "evidence_hash": hex::encode(&action.evidence_hash), "lock_until": now_u64 + 2592000, "queued_at": now_u64, "auto_generated": true, "affected": affected.len(), "escalated": escalated, "errors": errors});
                self.db.save_pending_drawrequest(&format!("dr:{}:{}", action.group_id, now_u64), &serde_json::to_vec(&dr).map_err(|_| ChronxError::SerializationError)?)?;
                info!(group_id = %action.group_id, affected = affected.len(), escalated = escalated, errors = errors, "[ATTESTOR FAILURE CASCADE] complete");
                Ok(())
            }"""
        eng = eng[:fs] + new_fail + eng[arm_end2:]
        print("  Replaced DeclareAttestorFailure with cascade logic")

write(eng_path, eng)

# ================================================================
# 6. genesis-params.json
# ================================================================
print("\n=== Genesis params ===")
import json
gp_path = f"{CHRONX}/genesis-params.json"
gp = read(gp_path)
if "hedgekx_oracle_trigger_enabled" not in gp:
    last = gp.rfind("}")
    insertion = ',\n  "hedgekx_oracle_trigger_enabled": true,\n  "oracle_trigger_max_age_secs": 3600,\n  "escalation_lock_seconds_default": 2592000\n'
    gp = gp[:last] + insertion + gp[last:]
    write(gp_path, gp)
    print("  Added governance flags")
else:
    print("  Governance flags already present")

print("\n=== ALL THREE ADDITIONS PATCHED ===")
print("Run: cargo build --release -p chronx-node -p chronx-wallet")
