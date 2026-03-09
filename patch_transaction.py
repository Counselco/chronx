#!/usr/bin/env python3
"""patch_transaction.py — Add Genesis 8 Action variants and TimeLockCreate fields."""

TARGET = "/home/josep/chronx/crates/chronx-core/src/transaction.rs"

TIMELOCK_FIELDS = '''
        // ── Genesis 8 — AI Agent management fields ─────────────────────────
        /// If true, this lock's investable fraction is managed by a registered AI agent.
        #[serde(default)]
        agent_managed: Option<bool>,
        /// BLAKE3 of combined promise_axioms+trading_axioms. Required if agent_managed.
        #[serde(default)]
        grantor_axiom_consent_hash: Option<String>,
        /// Fraction of promise value offered for AI investment (0.0 to 1.0).
        #[serde(default)]
        investable_fraction: Option<f64>,
        /// Investment style mandate.
        #[serde(default)]
        investment_style: Option<String>,
        /// Comma-separated exclusion list.
        #[serde(default)]
        investment_exclusions: Option<String>,
        /// Free text grantor intent (max MISAI_LOAN_PACKAGE_MAX_INTENT_CHARS chars).
        #[serde(default)]
        grantor_intent: Option<String>,
'''

ACTION_VARIANTS = '''
    // ── Genesis 8 — AI Agent Architecture ─────────────────────────────────
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
'''

def main():
    with open(TARGET, "r") as f:
        content = f.read()

    changed = False

    # ── 1. Add TimeLockCreate fields after lock_metadata ──────────────────
    if "agent_managed:" not in content:
        # Find `lock_metadata` field in TimeLockCreate
        # The field line should look like: lock_metadata: Option<...>,
        # We need to find it within the TimeLockCreate variant
        anchor = None
        # Try common patterns for the lock_metadata field
        for candidate in [
            "lock_metadata: Option<String>,",
            "lock_metadata: Option<Vec<u8>>,",
            "lock_metadata: Option<HashMap<String, String>>,",
        ]:
            if candidate in content:
                anchor = candidate
                break

        if anchor is None:
            # Try a more flexible search
            import re
            m = re.search(r'(        lock_metadata: [^\n]+,)', content)
            if m:
                anchor = m.group(1).strip()

        if anchor:
            # Insert after the lock_metadata line
            content = content.replace(anchor, anchor + "\n" + TIMELOCK_FIELDS)
            print("  Added 6 Genesis 8 fields to TimeLockCreate (after lock_metadata).")
            changed = True
        else:
            print("ERROR: Could not find lock_metadata field in TimeLockCreate.")
    else:
        print("  TimeLockCreate fields already present — skipping.")

    # ── 2. Add Action variants before closing } of Action enum ────────────
    if "AgentRegister" not in content:
        # Find the VerifierRegister variant — our new variants go after it
        # Strategy: find the last variant in the Action enum and add after it
        # Look for "VerifierRegister" as the anchor
        if "VerifierRegister" in content:
            # Find the end of the VerifierRegister variant block
            # It's a struct variant with { ... }, so find its closing },
            vr_idx = content.index("VerifierRegister")
            # Find the closing }, for this variant
            brace_count = 0
            i = content.index("{", vr_idx)
            while i < len(content):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        # Found the closing }
                        # Now find the comma after it
                        comma_idx = content.index(",", i)
                        insert_pos = comma_idx + 1
                        content = content[:insert_pos] + "\n" + ACTION_VARIANTS + content[insert_pos:]
                        print("  Added 3 Genesis 8 Action variants (after VerifierRegister).")
                        changed = True
                        break
                i += 1
        else:
            # Fallback: find the closing } of enum Action
            # Find "enum Action" then its closing }
            enum_idx = content.index("enum Action")
            brace_count = 0
            i = content.index("{", enum_idx)
            while i < len(content):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        # Insert before closing }
                        content = content[:i] + ACTION_VARIANTS + "\n" + content[i:]
                        print("  Added 3 Genesis 8 Action variants (before enum closing }).")
                        changed = True
                        break
                i += 1
    else:
        print("  Action variants already present — skipping.")

    if changed:
        with open(TARGET, "w") as f:
            f.write(content)
        print("DONE: Patched transaction.rs with Genesis 8 changes.")
    else:
        print("No changes made to transaction.rs.")

if __name__ == "__main__":
    main()
