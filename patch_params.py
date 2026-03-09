#!/usr/bin/env python3
"""patch_params.py — Add Genesis 8 fields to GenesisParams and test_params()."""

TARGET = "/home/josep/chronx/crates/chronx-genesis/src/params.rs"

# Fields to add after governance_wallet_b58 in the struct
STRUCT_FIELDS = '''
    // ── Genesis 8 — AI Agent Architecture ────────────────────────────────

    /// MISAI trading wallet Dilithium2 public key — zero balance at genesis.
    /// Same pattern as Genesis 7 protocol wallets.
    #[serde(default = "default_genesis7_key")]
    pub misai_agent_wallet_pubkey: DilithiumPublicKey,

    /// Assignment mechanism for agent-managed promises.
    /// "SOLE_AGENT" at genesis — stored for governance reference.
    #[serde(default)]
    pub genesis_8_assignment_mechanism: Option<String>,
'''

def main():
    with open(TARGET, "r") as f:
        content = f.read()

    if "misai_agent_wallet_pubkey" in content:
        print("Genesis 8 params already present — skipping.")
        return

    # ── 1. Add struct fields after governance_wallet_b58 ──────────────────
    # Find the governance_wallet_b58 field declaration and insert after it
    anchor = "pub governance_wallet_b58: Option<String>,"
    if anchor not in content:
        print("ERROR: Could not find governance_wallet_b58 field in struct.")
        return

    content = content.replace(anchor, anchor + "\n" + STRUCT_FIELDS)
    print("  Added misai_agent_wallet_pubkey + genesis_8_assignment_mechanism fields to struct.")

    # ── 2. Add to test_params() ───────────────────────────────────────────
    # First, check if governance_wallet_b58 is already in test_params
    if "governance_wallet_b58:" not in content.split("fn test_params")[1] if "fn test_params" in content else "":
        # Need to add governance_wallet_b58 to test_params too
        # Find the last field before the closing brace of the GenesisParams construction in test_params
        pass

    # Find the test_params function and add the new keypair + fields
    if "fn test_params" in content:
        # Add `let ma = ...` keypair generation after the last `let` keypair line in test_params
        # Look for the pattern of existing keypair generations
        # Find the last keypair let binding before the GenesisParams { block
        # We'll insert after the last `let` line that generates a keypair

        # Strategy: find "fn test_params" then find the GenesisParams { construction
        test_fn_start = content.index("fn test_params")
        test_fn_content = content[test_fn_start:]

        # Find the last `let XX = DilithiumKeyPair::generate();` or similar before GenesisParams {
        # We need to add: let ma = DilithiumKeyPair::generate();
        # Find "GenesisParams {" in the test function
        gp_idx = test_fn_content.index("GenesisParams {")

        # Find the last `let ` line before GenesisParams {
        pre_gp = test_fn_content[:gp_idx]
        lines = pre_gp.split("\n")

        # Find last line starting with `let `
        last_let_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith("let "):
                last_let_idx = i

        if last_let_idx >= 0:
            # Insert after this line
            lines.insert(last_let_idx + 1, "        let ma = KeyPair::generate();")
            pre_gp = "\n".join(lines)
            test_fn_content = pre_gp + test_fn_content[gp_idx:]
            content = content[:test_fn_start] + test_fn_content
            print("  Added `let ma = DilithiumKeyPair::generate();` to test_params.")

        # Now add the fields to the GenesisParams { ... } construction
        # Find governance_wallet_b58 in the test_params context
        test_fn_start = content.index("fn test_params")
        test_fn_content = content[test_fn_start:]

        # Check if governance_wallet_b58 is in the test function's GenesisParams block
        gp_block_start = test_fn_content.index("GenesisParams {")
        # Find the closing } of GenesisParams - scan for matching braces
        brace_count = 0
        gp_block_abs_start = test_fn_start + gp_block_start
        gp_inner_start = content.index("{", gp_block_abs_start)
        i = gp_inner_start
        while i < len(content):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    gp_block_end = i
                    break
            i += 1

        gp_block = content[gp_inner_start:gp_block_end + 1]

        # Check if governance_wallet_b58 is in the block
        new_fields = ""
        if "governance_wallet_b58" not in gp_block:
            new_fields += "            governance_wallet_b58: None,\n"
            print("  Added governance_wallet_b58: None to test_params.")

        new_fields += "            misai_agent_wallet_pubkey: ma.public_key.clone(),\n"
        new_fields += "            genesis_8_assignment_mechanism: Some(\"SOLE_AGENT\".to_string()),\n"

        # Insert before the closing }
        # Find the last real field line (non-empty, non-comment) before the closing }
        # Just insert before the closing }
        insert_pos = gp_block_end
        content = content[:insert_pos] + "            " + new_fields.strip() + "\n        " + content[insert_pos:]
        print("  Added misai_agent_wallet_pubkey + genesis_8_assignment_mechanism to test_params.")
    else:
        print("WARNING: fn test_params not found — skipped test update.")

    with open(TARGET, "w") as f:
        f.write(content)

    print("DONE: Patched params.rs with Genesis 8 fields.")

if __name__ == "__main__":
    main()
