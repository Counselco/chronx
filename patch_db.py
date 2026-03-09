#!/usr/bin/env python3
"""patch_db.py — Add Genesis 8 structs, trees, and accessors to StateDb."""

TARGET = "/home/josep/chronx/crates/chronx-state/src/db.rs"

# ── New structs to add after VerifierRecord ──────────────────────────────

NEW_STRUCTS = '''
// ── Genesis 8 — AI Agent Architecture data structures ────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentRecord {
    pub agent_name: String,
    pub agent_wallet: String,
    pub agent_code_hash: String,
    pub kyber_public_key_hex: String,
    pub operator_wallet: String,
    pub jurisdiction: String,
    pub status: String,
    pub registered_at: u64,
    pub governance_tx_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentLoanRecord {
    pub lock_id: String,
    pub agent_wallet: String,
    pub agent_name: String,
    pub loan_amount_chronos: u64,
    pub original_promise_value: u64,
    pub investable_fraction: f64,
    pub return_wallet: String,
    pub return_date: u64,
    pub investment_style: String,
    pub investment_exclusions: String,
    pub grantor_intent: String,
    pub loan_package_encrypted: bool,
    pub kyber_ciphertext_hex: String,
    pub chacha20_ciphertext_hex: String,
    pub chacha20_nonce_hex: String,
    pub disbursed_at: u64,
    pub returned_at: u64,
    pub returned_chronos: u64,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentCustodyRecord {
    pub lock_id: String,
    pub agent_name: String,
    pub agent_wallet: String,
    pub agent_code_hash: String,
    pub operator_wallet: String,
    pub axiom_version_hash: String,
    pub grantor_consent_at: u64,
    pub agent_consent_at: u64,
    pub released_at: u64,
    pub amount_chronos: u64,
    pub statement: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AxiomConsentRecord {
    pub lock_id: String,
    pub party_type: String,
    pub party_wallet: String,
    pub axiom_hash: String,
    pub consented_at: u64,
}
'''

# ── New tree fields for StateDb struct ───────────────────────────────────

TREE_FIELDS = '''
    // Genesis 8 — AI Agent Architecture trees
    agent_registry: sled::Tree,
    agent_loans: sled::Tree,
    agent_custody_records: sled::Tree,
    axiom_consents: sled::Tree,
'''

# ── Tree opening code for StateDb::open() ────────────────────────────────

TREE_OPEN = '''
        let agent_registry = db
            .open_tree("agent_registry")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let agent_loans = db
            .open_tree("agent_loans")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let agent_custody_records = db
            .open_tree("agent_custody_records")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
        let axiom_consents = db
            .open_tree("axiom_consents")
            .map_err(|e| ChronxError::Storage(e.to_string()))?;
'''

# ── Struct field initializers for Ok(Self { ... }) ───────────────────────

SELF_FIELDS = '''            agent_registry,
            agent_loans,
            agent_custody_records,
            axiom_consents,'''

# ── Accessor methods ─────────────────────────────────────────────────────

ACCESSOR_METHODS = '''
    // ── Genesis 8 — Agent registry ────────────────────────────────────────

    pub fn put_agent(&self, wallet: &str, record: &AgentRecord) -> Result<(), ChronxError> {
        let b = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.agent_registry.insert(wallet.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_agent(&self, wallet: &str) -> Result<Option<AgentRecord>, ChronxError> {
        match self.agent_registry.get(wallet.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn get_all_active_agents(&self) -> Result<Vec<AgentRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.agent_registry.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: AgentRecord = bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.status == "Active" { out.push(record); }
        }
        Ok(out)
    }

    // ── Genesis 8 — Agent loans ───────────────────────────────────────────

    pub fn put_agent_loan(&self, lock_id: &str, record: &AgentLoanRecord) -> Result<(), ChronxError> {
        let b = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.agent_loans.insert(lock_id.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_agent_loan(&self, lock_id: &str) -> Result<Option<AgentLoanRecord>, ChronxError> {
        match self.agent_loans.get(lock_id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn iter_all_agent_loans(&self) -> Result<Vec<AgentLoanRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.agent_loans.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            out.push(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?);
        }
        Ok(out)
    }

    // ── Genesis 8 — Agent custody records ─────────────────────────────────

    pub fn put_agent_custody(&self, lock_id: &str, record: &AgentCustodyRecord) -> Result<(), ChronxError> {
        let b = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.agent_custody_records.insert(lock_id.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_agent_custody(&self, lock_id: &str) -> Result<Option<AgentCustodyRecord>, ChronxError> {
        match self.agent_custody_records.get(lock_id.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn iter_agent_custody_for_wallet(&self, agent_wallet: &str) -> Result<Vec<AgentCustodyRecord>, ChronxError> {
        let mut out = Vec::new();
        for item in self.agent_custody_records.iter() {
            let (_, b) = item.map_err(|e| ChronxError::Storage(e.to_string()))?;
            let record: AgentCustodyRecord = bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?;
            if record.agent_wallet == agent_wallet { out.push(record); }
        }
        Ok(out)
    }

    // ── Genesis 8 — Axiom consents ────────────────────────────────────────

    pub fn put_axiom_consent(&self, lock_id: &str, party_type: &str, record: &AxiomConsentRecord) -> Result<(), ChronxError> {
        let key = format!("{}:{}", lock_id, party_type);
        let b = bincode::serialize(record).map_err(|e| ChronxError::Serialization(e.to_string()))?;
        self.axiom_consents.insert(key.as_bytes(), b).map_err(|e| ChronxError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_axiom_consent(&self, lock_id: &str, party_type: &str) -> Result<Option<AxiomConsentRecord>, ChronxError> {
        let key = format!("{}:{}", lock_id, party_type);
        match self.axiom_consents.get(key.as_bytes()).map_err(|e| ChronxError::Storage(e.to_string()))? {
            Some(b) => Ok(Some(bincode::deserialize(&b).map_err(|e| ChronxError::Serialization(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn has_both_consents(&self, lock_id: &str) -> bool {
        let grantor_key = format!("{}:GRANTOR", lock_id);
        let agent_key = format!("{}:AGENT", lock_id);
        let has_grantor = self.axiom_consents.contains_key(grantor_key.as_bytes()).unwrap_or(false);
        let has_agent = self.axiom_consents.contains_key(agent_key.as_bytes()).unwrap_or(false);
        has_grantor && has_agent
    }

    /// Compute the combined axiom hash: BLAKE3(promise_axioms + trading_axioms)
    pub fn get_combined_axiom_hash(&self) -> Result<String, ChronxError> {
        let promise = self.get_meta("promise_axioms")?.unwrap_or_default();
        let trading = self.get_meta("trading_axioms")?.unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&promise);
        hasher.update(&trading);
        Ok(hasher.finalize().to_hex().to_string())
    }
'''

# ── New PromisePackageRecord ─────────────────────────────────────────────

OLD_PROMISE_PACKAGE = '''#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PromisePackageRecord {
    pub lock_id: String,
    pub encryption_scheme: String,
    pub package_json: String,
    pub verifas_pubkey_hint: String,
    pub created_at: u64,
}'''

NEW_PROMISE_PACKAGE = '''#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PromisePackageRecord {
    pub lock_id: String,
    pub encryption_scheme: String,
    pub kyber_ciphertext_hex: String,
    pub chacha20_ciphertext_hex: String,
    pub chacha20_nonce_hex: String,
    pub verifas_kyber_pubkey_hint: String,
    pub created_at: u64,
}'''


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


def main():
    with open(TARGET, "r") as f:
        content = f.read()

    changed = False

    # ── 1. Replace PromisePackageRecord ───────────────────────────────────
    if "package_json: String," in content and "kyber_ciphertext_hex" not in content:
        content = content.replace(OLD_PROMISE_PACKAGE, NEW_PROMISE_PACKAGE)
        print("  Replaced PromisePackageRecord with Kyber/ChaCha20 fields.")
        changed = True
    elif "kyber_ciphertext_hex" in content:
        print("  PromisePackageRecord already updated — skipping.")
    else:
        print("WARNING: Could not find old PromisePackageRecord struct to replace.")

    # ── 2. Add new structs after VerifierRecord ──────────────────────────
    if "AgentRecord" not in content:
        # Find the end of VerifierRecord struct
        if "pub struct VerifierRecord" in content:
            vr_idx = content.index("pub struct VerifierRecord")
            brace_start = content.index("{", vr_idx)
            brace_end = find_matching_brace(content, brace_start)
            if brace_end > 0:
                insert_pos = brace_end + 1
                content = content[:insert_pos] + "\n" + NEW_STRUCTS + content[insert_pos:]
                print("  Added AgentRecord, AgentLoanRecord, AgentCustodyRecord, AxiomConsentRecord structs.")
                changed = True
        else:
            print("ERROR: Could not find VerifierRecord struct.")
    else:
        print("  Genesis 8 structs already present — skipping.")

    # ── 3. Add tree fields to StateDb struct ─────────────────────────────
    if "agent_registry: sled::Tree," not in content:
        anchor = "verifier_registry: sled::Tree,"
        if anchor in content:
            content = content.replace(anchor, anchor + "\n" + TREE_FIELDS)
            print("  Added 4 sled tree fields to StateDb struct.")
            changed = True
        else:
            print("ERROR: Could not find verifier_registry field in StateDb struct.")
    else:
        print("  Tree fields already present — skipping.")

    # ── 4. Open trees in StateDb::open() ─────────────────────────────────
    if 'open_tree("agent_registry")' not in content:
        # Find the verifier_registry open_tree block and insert after it
        anchor = 'open_tree("verifier_registry")'
        if anchor in content:
            # Find the semicolon that ends the verifier_registry let statement
            vr_open_idx = content.index(anchor)
            # Find the next semicolon after this
            semi_idx = content.index(";", vr_open_idx)
            # Find the end of line
            eol_idx = content.index("\n", semi_idx)
            insert_pos = eol_idx + 1
            content = content[:insert_pos] + TREE_OPEN + content[insert_pos:]
            print("  Added 4 tree open_tree() calls in StateDb::open().")
            changed = True
        else:
            print("ERROR: Could not find verifier_registry open_tree in StateDb::open().")
    else:
        print("  Tree opens already present — skipping.")

    # ── 5. Add fields to Ok(Self { ... }) ────────────────────────────────
    if "agent_registry,\n" not in content or "Ok(Self" not in content:
        # Only add if they aren't in the Self block already
        # Check more carefully: look within the Ok(Self { ... }) block
        if "Ok(Self" in content and "agent_registry,\n" not in content:
            # Find "verifier_registry," within Ok(Self { ... })
            ok_self_idx = content.index("Ok(Self")
            remaining = content[ok_self_idx:]
            if "verifier_registry," in remaining:
                # Find the verifier_registry, line within Ok(Self)
                vr_in_self_idx = ok_self_idx + remaining.index("verifier_registry,")
                eol = content.index("\n", vr_in_self_idx)
                insert_pos = eol + 1
                content = content[:insert_pos] + SELF_FIELDS + "\n" + content[insert_pos:]
                print("  Added 4 tree fields to Ok(Self { ... }).")
                changed = True
            else:
                print("ERROR: Could not find verifier_registry in Ok(Self { ... }).")
    else:
        print("  Self fields already present — skipping.")

    # ── 6. Add accessor methods ──────────────────────────────────────────
    if "pub fn put_agent(" not in content:
        # Find the last method: get_verifas_vault_address
        anchor = "get_verifas_vault_address"
        if anchor in content:
            # Find the end of get_verifas_vault_address method
            # It's a pub fn, find its closing }
            fn_idx = content.rindex(anchor)  # use rindex in case there are multiple references
            # Find the fn's opening {
            fn_brace = content.index("{", fn_idx)
            fn_end = find_matching_brace(content, fn_brace)
            if fn_end > 0:
                insert_pos = fn_end + 1
                content = content[:insert_pos] + ACCESSOR_METHODS + content[insert_pos:]
                print("  Added Genesis 8 accessor methods (agent, loan, custody, axiom consent).")
                changed = True
            else:
                print("ERROR: Could not find end of get_verifas_vault_address method.")
        else:
            print("WARNING: get_verifas_vault_address not found. Trying to insert before last } of impl StateDb.")
            # Fallback: find the very last } in the file (closing impl StateDb)
            last_brace = content.rindex("}")
            content = content[:last_brace] + ACCESSOR_METHODS + "\n" + content[last_brace:]
            print("  Added Genesis 8 accessor methods (before final }).")
            changed = True
    else:
        print("  Accessor methods already present — skipping.")

    if changed:
        with open(TARGET, "w") as f:
            f.write(content)
        print("DONE: Patched db.rs with Genesis 8 changes.")
    else:
        print("No changes made to db.rs.")

if __name__ == "__main__":
    main()
