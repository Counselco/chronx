#!/usr/bin/env python3
"""patch_rpc.py — Add Genesis 8 RPC methods to types.rs, api.rs, server.rs.

New methods:
  1. chronx_getAgentRegistry
  2. chronx_getAgentLoanRecord(lock_id)
  3. chronx_getAgentCustodyRecord(lock_id)
  4. chronx_getAgentHistory(agent_wallet)
  5. chronx_getAxiomConsent(lock_id, party_type)
  6. chronx_getInvestablePromises
  7. chronx_getGenesis8Constants
  8. Update chronx_getPromiseAxioms (add combined_axiom_hash)
"""

BASE = "/home/josep/chronx/crates/chronx-rpc/src"

def patch_types():
    path = f"{BASE}/types.rs"
    with open(path, "r") as f:
        content = f.read()

    changed = False

    # 1. Add combined_axiom_hash to RpcPromiseAxioms
    if "combined_axiom_hash" not in content:
        old = """pub struct RpcPromiseAxioms {
    pub promise_axioms: String,
    pub trading_axioms: String,
}"""
        new = """pub struct RpcPromiseAxioms {
    pub promise_axioms: String,
    pub trading_axioms: String,
    /// BLAKE3 hash of (promise_axioms || trading_axioms) — wallets use this
    /// to compute axiom consent hashes without recalculating.
    pub combined_axiom_hash: String,
}"""
        if old in content:
            content = content.replace(old, new)
            print("  [types] Added combined_axiom_hash to RpcPromiseAxioms.")
            changed = True
        else:
            print("ERROR [types]: Could not find RpcPromiseAxioms struct.")
    else:
        print("  [types] combined_axiom_hash already present — skipping.")

    # 2. Add Genesis 8 RPC types
    if "RpcAgentRecord" not in content:
        new_types = '''

// ── Genesis 8 — AI Agent Architecture RPC types ──────────────────────────────

/// Agent registry entry returned by `chronx_getAgentRegistry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAgentRecord {
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

/// Agent loan record returned by `chronx_getAgentLoanRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAgentLoanRecord {
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
    pub disbursed_at: u64,
    pub returned_at: u64,
    pub returned_chronos: u64,
    pub status: String,
}

/// Agent custody record returned by `chronx_getAgentCustodyRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAgentCustodyRecord {
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

/// Axiom consent record returned by `chronx_getAxiomConsent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAxiomConsentRecord {
    pub lock_id: String,
    pub party_type: String,
    pub party_wallet: String,
    pub axiom_hash: String,
    pub consented_at: u64,
}

/// Investable promise summary returned by `chronx_getInvestablePromises`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcInvestablePromise {
    pub lock_id: String,
    pub sender: String,
    pub amount_chronos: String,
    pub amount_kx: String,
    pub unlock_at: i64,
    pub lock_type: Option<String>,
    pub lock_metadata: Option<String>,
}
'''
        content = content.rstrip() + new_types
        print("  [types] Added 6 Genesis 8 RPC types.")
        changed = True
    else:
        print("  [types] Genesis 8 RPC types already present — skipping.")

    if changed:
        with open(path, "w") as f:
            f.write(content)
        print("  DONE: types.rs patched.")
    else:
        print("  No changes to types.rs.")


def patch_api():
    path = f"{BASE}/api.rs"
    with open(path, "r") as f:
        content = f.read()

    changed = False

    # 1. Add new type imports
    if "RpcAgentRecord" not in content:
        old_import = "use crate::types::{"
        if old_import in content:
            import_start = content.index(old_import)
            import_end = content.index("};", import_start) + 2

            old_import_block = content[import_start:import_end]
            # Extract existing types
            brace_start = old_import_block.index("{")
            brace_end = old_import_block.rindex("}")
            existing = old_import_block[brace_start + 1:brace_end].strip()
            if existing.endswith(","):
                existing = existing[:-1]

            new_types = (
                "RpcAgentRecord, RpcAgentLoanRecord, RpcAgentCustodyRecord, "
                "RpcAxiomConsentRecord, RpcInvestablePromise,"
            )

            new_import_block = (
                "use crate::types::{\n"
                "    " + existing + ",\n"
                "    " + new_types + "\n"
                "};"
            )
            content = content.replace(old_import_block, new_import_block)
            print("  [api] Added Genesis 8 type imports.")
            changed = True
        else:
            print("ERROR [api]: Could not find type imports.")
    else:
        print("  [api] Genesis 8 type imports already present — skipping.")

    # 2. Add new API methods before the closing `}`
    if "getAgentRegistry" not in content:
        new_methods = '''

    // ── Genesis 8 — AI Agent Architecture ──────────────────────────────

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

    /// Return Genesis 8 constants from genesis metadata as JSON.
    #[method(name = "getGenesis8Constants")]
    async fn get_genesis8_constants(&self) -> RpcResult<serde_json::Value>;
'''
        # Insert before the closing `}` of the trait
        # Find `async fn get_promise_axioms` and then find the end of that method + the closing `}`
        anchor = "async fn get_promise_axioms(&self) -> RpcResult<RpcPromiseAxioms>;"
        if anchor in content:
            anchor_idx = content.index(anchor)
            # Find the `}` that closes the trait — it's after this line
            # The closing `}` is on its own line after the last method
            closing_brace = content.rindex("}")
            content = content[:closing_brace] + new_methods + "}\n"
            print("  [api] Added 7 Genesis 8 API method declarations.")
            changed = True
        else:
            print("ERROR [api]: Could not find get_promise_axioms method.")
    else:
        print("  [api] Genesis 8 API methods already present — skipping.")

    if changed:
        with open(path, "w") as f:
            f.write(content)
        print("  DONE: api.rs patched.")
    else:
        print("  No changes to api.rs.")


def patch_server():
    path = f"{BASE}/server.rs"
    with open(path, "r") as f:
        content = f.read()

    changed = False

    # 1. Add new type imports
    if "RpcAgentRecord" not in content:
        old_import = "use crate::types::{"
        if old_import in content:
            import_start = content.index(old_import)
            import_end = content.index("};", import_start) + 2

            old_import_block = content[import_start:import_end]
            brace_start = old_import_block.index("{")
            brace_end = old_import_block.rindex("}")
            existing = old_import_block[brace_start + 1:brace_end].strip()
            if existing.endswith(","):
                existing = existing[:-1]

            new_types = (
                "RpcAgentRecord, RpcAgentLoanRecord, RpcAgentCustodyRecord, "
                "RpcAxiomConsentRecord, RpcInvestablePromise,"
            )

            new_import_block = (
                "use crate::types::{\n"
                "    " + existing + ",\n"
                "    " + new_types + "\n"
                "};"
            )
            content = content.replace(old_import_block, new_import_block)
            print("  [server] Added Genesis 8 type imports.")
            changed = True
        else:
            print("ERROR [server]: Could not find type imports.")
    else:
        print("  [server] Genesis 8 type imports already present — skipping.")

    # 2. Update get_promise_axioms to include combined_axiom_hash
    if "combined_axiom_hash" not in content:
        old_return = """Ok(RpcPromiseAxioms {
            promise_axioms: promise,
            trading_axioms: trading,
        })"""
        new_return = """// Genesis 8: compute combined axiom hash
        let combined_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(promise.as_bytes());
            hasher.update(trading.as_bytes());
            hasher.finalize().to_hex().to_string()
        };
        Ok(RpcPromiseAxioms {
            promise_axioms: promise,
            trading_axioms: trading,
            combined_axiom_hash: combined_hash,
        })"""
        if old_return in content:
            content = content.replace(old_return, new_return)
            print("  [server] Updated get_promise_axioms with combined_axiom_hash.")
            changed = True
        else:
            print("ERROR [server]: Could not find RpcPromiseAxioms return block.")
    else:
        print("  [server] combined_axiom_hash already present — skipping.")

    # 3. Add 7 new method implementations
    if "get_agent_registry" not in content:
        new_impls = '''

    // ── Genesis 8 — AI Agent Architecture ────────────────────────────

    /// `chronx_getAgentRegistry` — return all Active agents.
    async fn get_agent_registry(&self) -> RpcResult<Vec<RpcAgentRecord>> {
        let agents = self.state.db.get_all_active_agents()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(agents.into_iter().map(|a| RpcAgentRecord {
            agent_name: a.agent_name,
            agent_wallet: a.agent_wallet,
            agent_code_hash: a.agent_code_hash,
            kyber_public_key_hex: a.kyber_public_key_hex,
            operator_wallet: a.operator_wallet,
            jurisdiction: a.jurisdiction,
            status: a.status,
            registered_at: a.registered_at,
            governance_tx_id: a.governance_tx_id,
        }).collect())
    }

    /// `chronx_getAgentLoanRecord` — return a single loan record by lock_id.
    async fn get_agent_loan_record(&self, lock_id: String) -> RpcResult<Option<RpcAgentLoanRecord>> {
        let record = self.state.db.get_agent_loan(&lock_id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcAgentLoanRecord {
            lock_id: r.lock_id,
            agent_wallet: r.agent_wallet,
            agent_name: r.agent_name,
            loan_amount_chronos: r.loan_amount_chronos,
            original_promise_value: r.original_promise_value,
            investable_fraction: r.investable_fraction,
            return_wallet: r.return_wallet,
            return_date: r.return_date,
            investment_style: r.investment_style,
            investment_exclusions: r.investment_exclusions,
            grantor_intent: r.grantor_intent,
            loan_package_encrypted: r.loan_package_encrypted,
            disbursed_at: r.disbursed_at,
            returned_at: r.returned_at,
            returned_chronos: r.returned_chronos,
            status: r.status,
        }))
    }

    /// `chronx_getAgentCustodyRecord` — return a single custody record by lock_id.
    async fn get_agent_custody_record(&self, lock_id: String) -> RpcResult<Option<RpcAgentCustodyRecord>> {
        let record = self.state.db.get_agent_custody(&lock_id)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcAgentCustodyRecord {
            lock_id: r.lock_id,
            agent_name: r.agent_name,
            agent_wallet: r.agent_wallet,
            agent_code_hash: r.agent_code_hash,
            operator_wallet: r.operator_wallet,
            axiom_version_hash: r.axiom_version_hash,
            grantor_consent_at: r.grantor_consent_at,
            agent_consent_at: r.agent_consent_at,
            released_at: r.released_at,
            amount_chronos: r.amount_chronos,
            statement: r.statement,
        }))
    }

    /// `chronx_getAgentHistory` — all custody records for an agent wallet.
    async fn get_agent_history(&self, agent_wallet: String) -> RpcResult<Vec<RpcAgentCustodyRecord>> {
        let records = self.state.db.iter_agent_custody_for_wallet(&agent_wallet)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(records.into_iter().map(|r| RpcAgentCustodyRecord {
            lock_id: r.lock_id,
            agent_name: r.agent_name,
            agent_wallet: r.agent_wallet,
            agent_code_hash: r.agent_code_hash,
            operator_wallet: r.operator_wallet,
            axiom_version_hash: r.axiom_version_hash,
            grantor_consent_at: r.grantor_consent_at,
            agent_consent_at: r.agent_consent_at,
            released_at: r.released_at,
            amount_chronos: r.amount_chronos,
            statement: r.statement,
        }).collect())
    }

    /// `chronx_getAxiomConsent` — return axiom consent record.
    async fn get_axiom_consent(&self, lock_id: String, party_type: String) -> RpcResult<Option<RpcAxiomConsentRecord>> {
        let record = self.state.db.get_axiom_consent(&lock_id, &party_type)
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        Ok(record.map(|r| RpcAxiomConsentRecord {
            lock_id: r.lock_id,
            party_type: r.party_type,
            party_wallet: r.party_wallet,
            axiom_hash: r.axiom_hash,
            consented_at: r.consented_at,
        }))
    }

    /// `chronx_getInvestablePromises` — all agent-managed, unassigned promises within investment window.
    async fn get_investable_promises(&self) -> RpcResult<Vec<RpcInvestablePromise>> {
        use chronx_core::constants::MISAI_MIN_INVESTMENT_WINDOW_DAYS;

        let now = chrono::Utc::now().timestamp();
        let min_unlock = now + (MISAI_MIN_INVESTMENT_WINDOW_DAYS as i64 * 86400);

        let all_locks = self.state.db.iter_all_timelocks()
            .map_err(|e| rpc_err(-32603, e.to_string()))?;

        let results: Vec<RpcInvestablePromise> = all_locks.into_iter()
            .filter(|tlc| {
                tlc.status == TimeLockStatus::Pending
                    && tlc.lock_type.as_deref() == Some("M")
                    && tlc.unlock_at > min_unlock
            })
            .map(|tlc| RpcInvestablePromise {
                lock_id: tlc.id.to_hex(),
                sender: tlc.sender.to_b58(),
                amount_chronos: tlc.amount.to_string(),
                amount_kx: (tlc.amount / CHRONOS_PER_KX).to_string(),
                unlock_at: tlc.unlock_at,
                lock_type: tlc.lock_type,
                lock_metadata: tlc.lock_metadata,
            })
            .collect();

        Ok(results)
    }

    /// `chronx_getGenesis8Constants` — return Genesis 8 constants from metadata.
    async fn get_genesis8_constants(&self) -> RpcResult<serde_json::Value> {
        let meta: Option<Vec<u8>> = self.state.db.get_meta("genesis_8_constants")
            .map_err(|e| rpc_err(-32603, e.to_string()))?;
        match meta {
            Some(bytes) => {
                let s = String::from_utf8_lossy(&bytes);
                serde_json::from_str(&s)
                    .map_err(|e| rpc_err(-32603, format!("failed to parse genesis_8_constants: {}", e)))
            }
            None => Ok(serde_json::json!(null)),
        }
    }
'''
        # Insert before the closing `}` of the impl block (last `}` in file)
        closing_brace = content.rindex("}")
        content = content[:closing_brace] + new_impls + "}\n"
        print("  [server] Added 7 Genesis 8 method implementations.")
        changed = True
    else:
        print("  [server] Genesis 8 method implementations already present — skipping.")

    if changed:
        with open(path, "w") as f:
            f.write(content)
        print("  DONE: server.rs patched.")
    else:
        print("  No changes to server.rs.")


def main():
    print("Patching types.rs...")
    patch_types()
    print()
    print("Patching api.rs...")
    patch_api()
    print()
    print("Patching server.rs...")
    patch_server()
    print()
    print("=== Genesis 8 RPC patch complete ===")


if __name__ == "__main__":
    main()
