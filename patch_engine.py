#!/usr/bin/env python3
"""patch_engine.py — Apply Genesis 8 changes to chronx-state/src/engine.rs.

Changes:
  1. Add Genesis 8 constants to the imports
  2. Add encrypt_package() standalone function before impl StateEngine
  3. Add 6 new fields to TimeLockCreate destructuring
  4. Add agent-managed validation + axiom consent storage in TimeLockCreate
  5. Replace plaintext PromisePackageRecord with encrypted version
  6. Add AgentRegister action handler
  7. Add AgentCodeUpdate action handler
  8. Add AgentLoanRequest action handler
  9. Add sweep_agent_loan_returns() in new impl block
"""

TARGET = "/home/josep/chronx/crates/chronx-state/src/engine.rs"

# ── Helper ─────────────────────────────────────────────────────────────────────

def find_matching_brace(content, start_idx):
    """Find the index of the closing brace matching the opening brace at start_idx."""
    brace_count = 0
    i = start_idx
    while i < len(content):
        if content[i] == '{':
            brace_count += 1
        elif content[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                return i
        i += 1
    return -1


# ── Blocks to insert ──────────────────────────────────────────────────────────

ENCRYPT_PACKAGE_FN = '''
// ── POST-QUANTUM HYBRID ENCRYPTION ────────────────────────────────────────
// Kyber1024 (NIST PQC standard) for key encapsulation
// ChaCha20-Poly1305 for authenticated symmetric encryption
// Only the holder of the corresponding Kyber private key can decrypt
// This scheme is designed to resist attacks from quantum computers
// protecting 100-year promise commitments

fn encrypt_package(
    json: &str,
    kyber_pubkey_hex: &str,
    lock_id_hex: &str,
    now: u64,
) -> Result<crate::db::PromisePackageRecord, chronx_core::error::ChronxError> {
    use pqcrypto_kyber::kyber1024;
    use pqcrypto_traits::kem::{PublicKey, SharedSecret, Ciphertext};
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};

    // Decode Kyber public key from hex
    let pk_bytes = hex::decode(kyber_pubkey_hex)
        .map_err(|e| chronx_core::error::ChronxError::EncryptionFailed(format!("bad kyber pubkey hex: {}", e)))?;
    let pk = kyber1024::PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| chronx_core::error::ChronxError::EncryptionFailed(format!("bad kyber pubkey: {:?}", e)))?;

    // Kyber1024 key encapsulation
    let (shared_secret, ciphertext) = kyber1024::encapsulate(&pk);

    // Use first 32 bytes of shared secret as ChaCha20-Poly1305 key
    let ss_bytes = shared_secret.as_bytes();
    let key_bytes: [u8; 32] = ss_bytes[..32].try_into()
        .map_err(|_| chronx_core::error::ChronxError::EncryptionFailed("shared secret too short".into()))?;

    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|e| chronx_core::error::ChronxError::EncryptionFailed(format!("cipher init: {}", e)))?;
    let encrypted = cipher.encrypt(nonce, json.as_bytes())
        .map_err(|e| chronx_core::error::ChronxError::EncryptionFailed(format!("encryption: {}", e)))?;

    Ok(crate::db::PromisePackageRecord {
        lock_id: lock_id_hex.to_string(),
        encryption_scheme: chronx_core::constants::GENESIS_8_ENCRYPTION_SCHEME.to_string(),
        kyber_ciphertext_hex: hex::encode(ciphertext.as_bytes()),
        chacha20_ciphertext_hex: hex::encode(&encrypted),
        chacha20_nonce_hex: hex::encode(&nonce_bytes),
        verifas_kyber_pubkey_hint: kyber_pubkey_hex.to_string(),
        created_at: now,
    })
}
'''

AGENT_MANAGED_VALIDATION = '''
                // ── Genesis 8: Agent-managed timelock validation ─────────────
                if agent_managed.unwrap_or(false) {
                    // Step 1: Validate axiom consent hash
                    if let Some(ref consent_hash) = grantor_axiom_consent_hash {
                        let expected = self.db.get_combined_axiom_hash()?;
                        if *consent_hash != expected {
                            return Err(ChronxError::AxiomConsentMismatch);
                        }
                    } else {
                        return Err(ChronxError::AxiomConsentRequired);
                    }

                    // Step 2: Validate recipient is registered Active agent
                    let recipient_b58 = account_id_from_pubkey(&recipient.0).to_b58();
                    match self.db.get_agent(&recipient_b58)? {
                        None => return Err(ChronxError::AgentNotRegistered),
                        Some(ref a) if a.status != "Active" => return Err(ChronxError::AgentNotActive),
                        Some(_) => {}
                    }

                    // Step 3: Validate investable fraction
                    if let Some(frac) = investable_fraction {
                        if *frac < 0.0 || *frac > MISAI_INVESTABLE_FRACTION_MAX {
                            return Err(ChronxError::InvalidInvestableFraction { max: MISAI_INVESTABLE_FRACTION_MAX });
                        }
                    }

                    // Step 4: Validate grantor intent length
                    if let Some(ref intent) = grantor_intent {
                        if intent.len() > MISAI_LOAN_PACKAGE_MAX_INTENT_CHARS {
                            return Err(ChronxError::GrantorIntentTooLong { max: MISAI_LOAN_PACKAGE_MAX_INTENT_CHARS });
                        }
                    }

                    // Step 5: Store grantor axiom consent record
                    {
                        use crate::db::AxiomConsentRecord;
                        let lock_id_hex = if action_idx == 0 {
                            tx_id.to_hex()
                        } else {
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(&tx_id.0);
                            hasher.update(&(action_idx as u32).to_le_bytes());
                            let h = hasher.finalize();
                            chronx_core::types::TxId(*h.as_bytes()).to_hex()
                        };
                        let consent = AxiomConsentRecord {
                            lock_id: lock_id_hex.clone(),
                            party_type: "GRANTOR".to_string(),
                            party_wallet: sender.account_id.to_b58(),
                            axiom_hash: grantor_axiom_consent_hash.clone().unwrap_or_default(),
                            consented_at: now as u64,
                        };
                        if let Err(e) = self.db.put_axiom_consent(&lock_id_hex, "GRANTOR", &consent) {
                            warn!(error = %e, "Genesis 8: failed to store grantor axiom consent");
                        }
                    }
                }
'''

AGENT_REGISTER_HANDLER = '''
            // ── Genesis 8: AgentRegister ──────────────────────────────────
            Action::AgentRegister {
                agent_name, agent_wallet, agent_code_hash,
                kyber_public_key_hex, operator_wallet, jurisdiction,
            } => {
                use crate::db::AgentRecord;

                // Governance-only
                let governance_wallet_id = self.db.get_meta("genesis_7_governance_wallet")?
                    .map(|b| String::from_utf8_lossy(&b).to_string());
                if let Some(ref gov_id) = governance_wallet_id {
                    if sender.account_id.to_b58() != *gov_id {
                        return Err(ChronxError::GovernanceOnly);
                    }
                } else {
                    return Err(ChronxError::GovernanceOnly);
                }

                // Check agent not already registered
                if self.db.get_agent(agent_wallet)?.is_some() {
                    return Err(ChronxError::AgentAlreadyRegistered);
                }

                // Validate Kyber key length (Kyber1024 PK = 1568 bytes = 3136 hex chars)
                let kyber_bytes = hex::decode(kyber_public_key_hex)
                    .map_err(|_| ChronxError::InvalidKyberKeyLength)?;
                if kyber_bytes.len() != 1568 {
                    return Err(ChronxError::InvalidKyberKeyLength);
                }

                let record = AgentRecord {
                    agent_name: agent_name.clone(),
                    agent_wallet: agent_wallet.clone(),
                    agent_code_hash: agent_code_hash.clone(),
                    kyber_public_key_hex: kyber_public_key_hex.clone(),
                    operator_wallet: operator_wallet.clone(),
                    jurisdiction: jurisdiction.clone(),
                    status: "Active".to_string(),
                    registered_at: now as u64,
                    governance_tx_id: tx_id.to_hex(),
                };
                self.db.put_agent(agent_wallet, &record)?;

                info!(
                    name = %agent_name, wallet = %agent_wallet,
                    operator = %operator_wallet,
                    "Genesis 8: agent registered"
                );
                Ok(())
            }
'''

AGENT_CODE_UPDATE_HANDLER = '''
            // ── Genesis 8: AgentCodeUpdate ────────────────────────────────
            Action::AgentCodeUpdate {
                agent_wallet, new_code_hash, new_kyber_public_key_hex,
            } => {
                let mut agent = self.db.get_agent(agent_wallet)?
                    .ok_or(ChronxError::AgentNotRegistered)?;
                if agent.status != "Active" {
                    return Err(ChronxError::AgentNotActive);
                }
                // Only operator may update
                if sender.account_id.to_b58() != agent.operator_wallet {
                    return Err(ChronxError::AgentCodeUpdateNotByOperator);
                }

                agent.agent_code_hash = new_code_hash.clone();
                agent.kyber_public_key_hex = new_kyber_public_key_hex.clone();
                self.db.put_agent(agent_wallet, &agent)?;

                info!(wallet = %agent_wallet, new_hash = %new_code_hash, "Genesis 8: agent code updated");
                Ok(())
            }
'''

AGENT_LOAN_REQUEST_HANDLER = '''
            // ── Genesis 8: AgentLoanRequest ───────────────────────────────
            Action::AgentLoanRequest {
                lock_id, agent_wallet, investable_fraction,
                proposed_return_date, agent_axiom_consent_hash,
            } => {
                use crate::db::{AgentRecord, AgentLoanRecord, AgentCustodyRecord, AxiomConsentRecord};
                use chronx_core::constants::CHRONOS_PER_KX;

                // Validate agent
                let agent = self.db.get_agent(agent_wallet)?
                    .ok_or(ChronxError::AgentNotRegistered)?;
                if agent.status != "Active" {
                    return Err(ChronxError::AgentNotActive);
                }

                // Validate agent axiom consent
                let expected_hash = self.db.get_combined_axiom_hash()?;
                if *agent_axiom_consent_hash != expected_hash {
                    return Err(ChronxError::AxiomConsentMismatch);
                }

                // Parse lock_id
                let lock_id_bytes = hex::decode(lock_id)
                    .map_err(|_| ChronxError::TimeLockNotFound(lock_id.clone()))?;
                if lock_id_bytes.len() != 32 { return Err(ChronxError::TimeLockNotFound(lock_id.clone())); }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&lock_id_bytes);
                let tid = chronx_core::types::TxId::from_bytes(arr);

                // Get lock
                let mut lock = self.db.get_timelock(&tid)?
                    .ok_or_else(|| ChronxError::TimeLockNotFound(lock_id.clone()))?;
                if lock.status != chronx_core::account::TimeLockStatus::Pending {
                    return Err(ChronxError::TimeLockAlreadyClaimed);
                }

                // Validate lock is agent-managed (lock_type = "M")
                if lock.lock_type.as_deref() != Some("M") {
                    return Err(ChronxError::LockNotAgentManaged);
                }

                // Validate return date
                let min_return = now + (MISAI_MIN_INVESTMENT_WINDOW_DAYS as i64 * 86400);
                if (*proposed_return_date as i64) < min_return {
                    return Err(ChronxError::ReturnDateTooSoon { min_days: MISAI_MIN_INVESTMENT_WINDOW_DAYS });
                }
                if (*proposed_return_date as i64) >= lock.unlock_at {
                    return Err(ChronxError::ReturnDateAfterMaturity);
                }

                // Calculate loan amount
                let loan_amount = (lock.amount as f64 * investable_fraction) as u128;
                if loan_amount == 0 || loan_amount > lock.amount {
                    return Err(ChronxError::InvalidInvestableFraction { max: MISAI_INVESTABLE_FRACTION_MAX });
                }

                // Store agent axiom consent
                let agent_consent = AxiomConsentRecord {
                    lock_id: lock_id.clone(),
                    party_type: "AGENT".to_string(),
                    party_wallet: agent_wallet.clone(),
                    axiom_hash: agent_axiom_consent_hash.clone(),
                    consented_at: now as u64,
                };
                self.db.put_axiom_consent(lock_id, "AGENT", &agent_consent)?;

                // Build loan package JSON
                let loan_package_json = serde_json::json!({
                    "return_wallet": lock.sender.to_b58(),
                    "return_date": proposed_return_date,
                    "loan_amount_chronos": loan_amount as u64,
                    "original_promise_value": lock.amount as u64,
                    "investable_fraction": investable_fraction,
                    "investment_style": lock.lock_metadata.as_deref().unwrap_or(""),
                    "grantor_intent": "",
                    "axiom_version_hash": agent_axiom_consent_hash,
                    "lock_id": lock_id,
                }).to_string();

                // Encrypt loan package with agent's Kyber key
                let (kyber_ct, chacha_ct, chacha_nonce, encrypted) = match encrypt_package(
                    &loan_package_json, &agent.kyber_public_key_hex, lock_id, now as u64
                ) {
                    Ok(r) => (r.kyber_ciphertext_hex, r.chacha20_ciphertext_hex, r.chacha20_nonce_hex, true),
                    Err(e) => {
                        warn!(error = %e, "Genesis 8: loan package encryption failed");
                        (String::new(), String::new(), String::new(), false)
                    }
                };

                // Transfer loan amount to agent wallet
                let agent_account_id = chronx_core::types::AccountId::from_b58(agent_wallet)
                    .map_err(|_| ChronxError::UnknownAccount(agent_wallet.clone()))?;
                let mut agent_account = self.db.get_account(&agent_account_id)?
                    .ok_or_else(|| ChronxError::UnknownAccount(agent_wallet.clone()))?;
                agent_account.balance += loan_amount;
                staged.accounts.push(agent_account);

                // Reduce lock amount
                lock.amount -= loan_amount;
                lock.lock_type = Some("M_DISBURSED".to_string());
                staged.timelocks.push(lock.clone());

                // Get grantor consent timestamp
                let grantor_consent_at = self.db.get_axiom_consent(lock_id, "GRANTOR")?
                    .map(|c| c.consented_at)
                    .unwrap_or(0);

                // Write loan record
                let loan_record = AgentLoanRecord {
                    lock_id: lock_id.clone(),
                    agent_wallet: agent_wallet.clone(),
                    agent_name: agent.agent_name.clone(),
                    loan_amount_chronos: loan_amount as u64,
                    original_promise_value: lock.amount as u64,
                    investable_fraction: *investable_fraction,
                    return_wallet: lock.sender.to_b58(),
                    return_date: *proposed_return_date,
                    investment_style: String::new(),
                    investment_exclusions: String::new(),
                    grantor_intent: String::new(),
                    loan_package_encrypted: encrypted,
                    kyber_ciphertext_hex: kyber_ct,
                    chacha20_ciphertext_hex: chacha_ct,
                    chacha20_nonce_hex: chacha_nonce,
                    disbursed_at: now as u64,
                    returned_at: 0,
                    returned_chronos: 0,
                    status: "Active".to_string(),
                };
                self.db.put_agent_loan(lock_id, &loan_record)?;

                // Write custody record
                let custody_record = AgentCustodyRecord {
                    lock_id: lock_id.clone(),
                    agent_name: agent.agent_name.clone(),
                    agent_wallet: agent_wallet.clone(),
                    agent_code_hash: agent.agent_code_hash.clone(),
                    operator_wallet: agent.operator_wallet.clone(),
                    axiom_version_hash: agent_axiom_consent_hash.clone(),
                    grantor_consent_at,
                    agent_consent_at: now as u64,
                    released_at: now as u64,
                    amount_chronos: loan_amount as u64,
                    statement: "ChronX Protocol has fulfilled its obligation under the grantor\\u2019s intent. These funds are released into agent custody. ChronX bears no further responsibility for their disposition.".to_string(),
                };
                self.db.put_agent_custody(lock_id, &custody_record)?;

                info!(
                    lock = %lock_id, agent = %agent.agent_name,
                    amount_kx = loan_amount / CHRONOS_PER_KX,
                    return_date = %proposed_return_date,
                    "Genesis 8: agent loan disbursed"
                );
                Ok(())
            }
'''

SWEEP_AGENT_LOANS_BLOCK = '''
// ── Genesis 8 — Agent loan return sweep ───────────────────────────────────

impl StateEngine {
    /// Scan all Active agent loans and return funds to the beneficiary
    /// when the return date has been reached.
    ///
    /// BEST_EFFORT: transfers whatever the agent wallet currently holds.
    /// No minimum. No guarantee. This is by design.
    pub fn sweep_agent_loan_returns(&self, now: i64) -> Result<u32, ChronxError> {
        use chronx_core::constants::CHRONOS_PER_KX;

        let all_loans = self.db.iter_all_agent_loans()?;
        let mut return_count = 0u32;

        for loan in all_loans {
            if loan.status != "Active" { continue; }
            if now < loan.return_date as i64 { continue; }

            // Get agent wallet balance
            let agent_account_id = match chronx_core::types::AccountId::from_b58(&loan.agent_wallet) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let mut agent_account = match self.db.get_account(&agent_account_id)? {
                Some(a) => a,
                None => continue,
            };

            // Transfer entire balance to return wallet
            let return_amount = agent_account.balance;
            if return_amount == 0 {
                // Agent has nothing — still mark as returned
                let mut updated_loan = loan.clone();
                updated_loan.returned_at = now as u64;
                updated_loan.returned_chronos = 0;
                updated_loan.status = "Returned".to_string();
                self.db.put_agent_loan(&loan.lock_id, &updated_loan)?;
                return_count += 1;
                continue;
            }

            let return_account_id = match chronx_core::types::AccountId::from_b58(&loan.return_wallet) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let mut return_account = match self.db.get_account(&return_account_id)? {
                Some(a) => a,
                None => continue,
            };

            agent_account.balance = 0;
            return_account.balance += return_amount;
            self.db.put_account(&agent_account)?;
            self.db.put_account(&return_account)?;

            let mut updated_loan = loan.clone();
            updated_loan.returned_at = now as u64;
            updated_loan.returned_chronos = return_amount as u64;
            updated_loan.status = "Returned".to_string();
            self.db.put_agent_loan(&loan.lock_id, &updated_loan)?;

            info!(
                lock = %loan.lock_id, agent = %loan.agent_name,
                original_kx = loan.loan_amount_chronos as u128 / CHRONOS_PER_KX,
                returned_kx = return_amount / CHRONOS_PER_KX,
                to = %loan.return_wallet,
                "Genesis 8: agent loan return"
            );
            return_count += 1;
        }

        if return_count > 0 {
            self.db.flush()?;
        }
        Ok(return_count)
    }
}
'''


def main():
    with open(TARGET, "r") as f:
        content = f.read()

    changed = False

    # ── 1. Add Genesis 8 constants to imports ──────────────────────────────
    if "GENESIS_8_ENCRYPTION_SCHEME" not in content:
        # Find the existing constants import block
        import_anchor = "use chronx_core::constants::{"
        if import_anchor in content:
            # Find the closing `};` of this import
            import_start = content.index(import_anchor)
            import_end = content.index("};", import_start) + 2

            old_import = content[import_start:import_end]

            # Extract just the constants between { and };
            brace_start = old_import.index("{")
            brace_end = old_import.rindex("}")
            existing_constants = old_import[brace_start + 1:brace_end].strip()

            # Remove trailing comma if present and add our new constants
            if existing_constants.endswith(","):
                existing_constants = existing_constants[:-1]

            new_constants = (
                "GENESIS_8_ENCRYPTION_SCHEME, MISAI_INVESTABLE_FRACTION_MAX, "
                "MISAI_LOAN_PACKAGE_MAX_INTENT_CHARS, MISAI_MIN_INVESTMENT_WINDOW_DAYS,"
            )

            new_import = (
                "use chronx_core::constants::{\n"
                "    " + existing_constants + ",\n"
                "    " + new_constants + "\n"
                "};"
            )
            content = content.replace(old_import, new_import)
            print("  [1] Added Genesis 8 constants to imports.")
            changed = True
        else:
            print("ERROR [1]: Could not find constants import block.")
    else:
        print("  [1] Genesis 8 constants already imported — skipping.")

    # ── 2. Add encrypt_package() function before impl StateEngine ──────────
    if "fn encrypt_package(" not in content:
        anchor = "pub struct StateEngine {"
        if anchor in content:
            idx = content.index(anchor)
            content = content[:idx] + ENCRYPT_PACKAGE_FN + "\n" + content[idx:]
            print("  [2] Added encrypt_package() function before impl StateEngine.")
            changed = True
        else:
            print("ERROR [2]: Could not find 'pub struct StateEngine {' anchor.")
    else:
        print("  [2] encrypt_package() already present — skipping.")

    # ── 3. Add 6 new fields to TimeLockCreate destructuring ────────────────
    if "agent_managed," not in content.split("Action::TimeLockCreate")[1].split("=> {")[0] if "Action::TimeLockCreate" in content else "":
        # Find the TimeLockCreate destructure pattern in apply_action
        # The last field before `} => {` is `unclaimed_action,`
        # After patch_transaction.py runs, the 6 new fields will exist in the
        # Action enum variant but NOT yet in the engine's destructure pattern.
        #
        # We need to add them to the destructure. The anchor is `unclaimed_action,`
        # within the TimeLockCreate destructure block.

        # Find `Action::TimeLockCreate {` in apply_action (not in tests)
        tlc_pattern = "Action::TimeLockCreate {"
        # Find it in the apply_action method — the first occurrence in the match block
        match_idx = content.index("match action {")
        tlc_idx = content.index(tlc_pattern, match_idx)

        # Find the `} => {` that closes this destructure
        destructure_close = content.index("} => {", tlc_idx)

        # Find `unclaimed_action,` within this range
        destructure_block = content[tlc_idx:destructure_close]

        if "unclaimed_action," in destructure_block:
            anchor = "                unclaimed_action,\n"
            anchor_pos = content.index(anchor, tlc_idx)
            if anchor_pos < destructure_close:
                new_fields = (
                    "                agent_managed,\n"
                    "                grantor_axiom_consent_hash,\n"
                    "                investable_fraction,\n"
                    "                investment_style,\n"
                    "                investment_exclusions,\n"
                    "                grantor_intent,\n"
                )
                content = content[:anchor_pos + len(anchor)] + new_fields + content[anchor_pos + len(anchor):]
                print("  [3] Added 6 Genesis 8 fields to TimeLockCreate destructuring.")
                changed = True
            else:
                print("ERROR [3]: unclaimed_action found but outside destructure block.")
        else:
            print("ERROR [3]: Could not find 'unclaimed_action,' in TimeLockCreate destructure.")
    else:
        print("  [3] TimeLockCreate destructure already has agent_managed — skipping.")

    # ── 4. Add agent-managed validation in TimeLockCreate handler ──────────
    if "Agent-managed timelock validation" not in content:
        # Insert after the existing validation block and before the balance check.
        # The anchor is the line `if sender.spendable_balance() < *amount {`
        # within the TimeLockCreate handler.
        #
        # We need to find it WITHIN the TimeLockCreate handler specifically.
        # Strategy: find TimeLockCreate in apply_action, then find the first
        # `sender.spendable_balance()` after it.

        match_idx = content.index("match action {")
        tlc_idx = content.index("Action::TimeLockCreate {", match_idx)

        balance_anchor = "                if sender.spendable_balance() < *amount {"
        balance_idx = content.index(balance_anchor, tlc_idx)

        # Insert the validation block before the balance check
        content = content[:balance_idx] + AGENT_MANAGED_VALIDATION + "\n" + content[balance_idx:]
        print("  [4] Added agent-managed validation block in TimeLockCreate handler.")
        changed = True
    else:
        print("  [4] Agent-managed validation already present — skipping.")

    # ── 5. Replace plaintext PromisePackageRecord with encrypted version ───
    if "encrypt_package(&package_json" not in content:
        # Look for the old plaintext PromisePackageRecord construction
        old_record_anchor = "let record = PromisePackageRecord {"
        # Also look for the patched version from patch_db.py
        old_record_alt = "let record = crate::db::PromisePackageRecord {"

        # We need to find this within the TimeLockCreate handler
        # It's in the promise package generation block (Genesis 7)
        if old_record_anchor in content or old_record_alt in content:
            anchor_text = old_record_anchor if old_record_anchor in content else old_record_alt
            record_idx = content.index(anchor_text)

            # Find the closing `};` of this struct literal
            brace_start = content.index("{", record_idx + len("let record = "))
            brace_end = find_matching_brace(content, brace_start)
            if brace_end > 0:
                # Include the semicolon after the closing brace
                semi_idx = content.index(";", brace_end)
                old_block = content[record_idx:semi_idx + 1]

                new_block = '''// Genesis 8: encrypt package with Verifas Kyber1024 public key
                        let verifas_kyber_pubkey = self.db.get_meta("verifas_kyber_pubkey_hex")
                            .unwrap_or(None)
                            .map(|b| String::from_utf8_lossy(&b).to_string())
                            .unwrap_or_default();

                        let record = if !verifas_kyber_pubkey.is_empty() {
                            match encrypt_package(&package_json, &verifas_kyber_pubkey, &lock_id.to_hex(), now as u64) {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!(error = %e, "Genesis 8: encryption failed, storing plaintext fallback");
                                    crate::db::PromisePackageRecord {
                                        lock_id: lock_id.to_hex(),
                                        encryption_scheme: "PLAINTEXT".to_string(),
                                        kyber_ciphertext_hex: String::new(),
                                        chacha20_ciphertext_hex: package_json.clone(),
                                        chacha20_nonce_hex: String::new(),
                                        verifas_kyber_pubkey_hint: String::new(),
                                        created_at: now as u64,
                                    }
                                }
                            }
                        } else {
                            // No Kyber key registered yet — store as plaintext
                            crate::db::PromisePackageRecord {
                                lock_id: lock_id.to_hex(),
                                encryption_scheme: "PLAINTEXT".to_string(),
                                kyber_ciphertext_hex: String::new(),
                                chacha20_ciphertext_hex: package_json.clone(),
                                chacha20_nonce_hex: String::new(),
                                verifas_kyber_pubkey_hint: String::new(),
                                created_at: now as u64,
                            }
                        };'''

                content = content.replace(old_block, new_block)
                print("  [5] Replaced plaintext PromisePackageRecord with encrypted version.")
                changed = True
            else:
                print("ERROR [5]: Could not find closing brace of PromisePackageRecord.")
        else:
            print("  [5] No PromisePackageRecord construction found — skipping (may not have Genesis 7 package code).")
    else:
        print("  [5] Encrypted package generation already present — skipping.")

    # ── 6-8. Add 3 new Action handlers ─────────────────────────────────────
    if "Action::AgentRegister" not in content:
        # Find the closing of the last match arm in apply_action.
        # The last handler is ReclaimExpiredLock. After its `Ok(())` and `}`
        # (closing the match arm), we insert the new handlers.
        #
        # Strategy: find `Action::ReclaimExpiredLock` then find its closing `}`
        # that ends the match arm. The pattern is:
        #     }   <-- closes the => { block
        # followed by the closing `}` of the match and `}` of apply_action.

        reclaim_anchor = "Action::ReclaimExpiredLock"
        if reclaim_anchor in content:
            reclaim_idx = content.index(reclaim_anchor)
            # Find `=> {` after it
            arm_start = content.index("=> {", reclaim_idx)
            arm_brace = content.index("{", arm_start + 2)
            arm_end = find_matching_brace(content, arm_brace)

            if arm_end > 0:
                # Insert the 3 new handlers after this arm's closing }
                insert_pos = arm_end + 1
                handlers = AGENT_REGISTER_HANDLER + AGENT_CODE_UPDATE_HANDLER + AGENT_LOAN_REQUEST_HANDLER
                content = content[:insert_pos] + "\n" + handlers + content[insert_pos:]
                print("  [6-8] Added AgentRegister, AgentCodeUpdate, AgentLoanRequest handlers.")
                changed = True
            else:
                print("ERROR [6-8]: Could not find closing brace of ReclaimExpiredLock handler.")
        else:
            print("ERROR [6-8]: Could not find Action::ReclaimExpiredLock anchor.")
    else:
        print("  [6-8] Agent action handlers already present — skipping.")

    # ── 9. Add sweep_agent_loan_returns() impl block ───────────────────────
    if "sweep_agent_loan_returns" not in content:
        # Insert after the closing `}` of the main `impl StateEngine` block
        # that contains apply_action, but before #[cfg(test)].
        test_anchor = "#[cfg(test)]"
        if test_anchor in content:
            test_idx = content.index(test_anchor)
            content = content[:test_idx] + SWEEP_AGENT_LOANS_BLOCK + "\n" + content[test_idx:]
            print("  [9] Added sweep_agent_loan_returns() impl block.")
            changed = True
        else:
            # Fallback: append before the last line
            content = content.rstrip() + "\n" + SWEEP_AGENT_LOANS_BLOCK
            print("  [9] Added sweep_agent_loan_returns() impl block (appended).")
            changed = True
    else:
        print("  [9] sweep_agent_loan_returns() already present — skipping.")

    # ── 10. Add 6 Genesis 8 fields to tlc_action() in tests ───────────────
    if "fn tlc_action(" in content and "agent_managed:" not in content:
        # Find the tlc_action helper in tests and add the 6 new fields
        tlc_action_idx = content.index("fn tlc_action(")
        # Find `unclaimed_action: None,` within this function
        unclaimed_in_test = "            unclaimed_action: None,\n"
        unclaimed_test_idx = content.index(unclaimed_in_test, tlc_action_idx)

        test_fields = (
            "            agent_managed: None,\n"
            "            grantor_axiom_consent_hash: None,\n"
            "            investable_fraction: None,\n"
            "            investment_style: None,\n"
            "            investment_exclusions: None,\n"
            "            grantor_intent: None,\n"
        )
        content = content[:unclaimed_test_idx + len(unclaimed_in_test)] + test_fields + content[unclaimed_test_idx + len(unclaimed_in_test):]
        print("  [10] Added 6 Genesis 8 fields to tlc_action() test helper.")
        changed = True
    elif "agent_managed:" in content:
        print("  [10] tlc_action() test helper already has Genesis 8 fields — skipping.")
    else:
        print("  [10] No tlc_action() found in tests — skipping.")

    if changed:
        with open(TARGET, "w") as f:
            f.write(content)
        print("DONE: Patched engine.rs with Genesis 8 changes.")
    else:
        print("No changes made to engine.rs.")


if __name__ == "__main__":
    main()
