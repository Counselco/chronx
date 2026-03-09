#!/usr/bin/env python3
"""patch_genesis_lib.py — Apply Genesis 8 changes to chronx-genesis/src/lib.rs.

Changes:
  1. Add misai_agent_wallet field to GenesisAccounts struct
  2. Create zero-balance MISAI agent wallet in apply_genesis()
  3. Replace promise_axioms with Genesis 8 text
  4. Replace trading_axioms with Genesis 8 text
  5. Store Genesis 8 constants as metadata
  6. Store assignment mechanism as governable metadata
  7. Add misai_agent_wallet to build_accounts()
"""

TARGET = "/home/josep/chronx/crates/chronx-genesis/src/lib.rs"


def main():
    with open(TARGET, "r") as f:
        content = f.read()

    changed = False

    # ── 1. Add misai_agent_wallet to GenesisAccounts struct ────────────────
    if "misai_agent_wallet" not in content:
        anchor = "pub humanity_stake_pool: AccountId,"
        if anchor in content:
            new_field = (
                anchor + "\n"
                "    /// MISAI agent trading wallet — zero balance at genesis.\n"
                "    pub misai_agent_wallet: AccountId,"
            )
            content = content.replace(anchor, new_field)
            print("  [1] Added misai_agent_wallet field to GenesisAccounts (after humanity_stake_pool).")
            changed = True
        else:
            print("ERROR [1]: Could not find 'pub humanity_stake_pool: AccountId,' anchor.")
    else:
        print("  [1] misai_agent_wallet already in GenesisAccounts — skipping.")

    # ── 2. Create zero-balance MISAI agent wallet in apply_genesis() ───────
    if "misai_agent_wallet (0 KX)" not in content and "MISAI agent wallet (0 KX)" not in content:
        anchor = 'info!(account = %accounts.humanity_stake_pool, "genesis: Humanity Stake Pool account (0 KX)");'
        if anchor in content:
            insert_block = '''

    // ── Genesis 8 — Create zero-balance MISAI agent wallet ───────────────
    let misai_agent_account = Account::new(
        accounts.misai_agent_wallet.clone(),
        AuthPolicy::SingleSig {
            public_key: params.misai_agent_wallet_pubkey.clone(),
        },
    );
    db.put_account(&misai_agent_account)?;
    info!(account = %accounts.misai_agent_wallet, "genesis: MISAI agent wallet (0 KX)");'''
            content = content.replace(anchor, anchor + insert_block)
            print("  [2] Added MISAI agent wallet creation block.")
            changed = True
        else:
            print("ERROR [2]: Could not find Humanity Stake Pool info!() anchor.")
    else:
        print("  [2] MISAI agent wallet creation already present — skipping.")

    # ── 3. Replace promise_axioms with Genesis 8 text ──────────────────────
    if 'let promise_axioms = "ChronX Promise Axioms' in content:
        # Find the full promise_axioms string — from `let promise_axioms = "` to the closing `";`
        start_marker = 'let promise_axioms = "'
        start_idx = content.index(start_marker)
        # Find the closing ";  — look for the pattern `";` after the start
        # The string may span multiple lines with \n escapes, so find `";` scanning forward
        search_from = start_idx + len(start_marker)
        end_idx = content.index('";', search_from) + 2  # include the ";

        old_text = content[start_idx:end_idx]

        new_axioms = r'''let promise_axioms = "ChronX Promise Axioms\nEncoded at Genesis. Immutable. Cannot be changed by any person, governance body, or software update.\n\nI.\nThe grantor\u2019s intent is the master. Once a promise is made and the cancellation window closes, it is irrevocable. No person, institution, or governance body can recall it.\n\nII.\nPromised funds are never abandoned. A promise unclaimed by its intended beneficiary within 90 days of maturity is held by the Verified Delivery Protocol, recoverable by any person who can establish a lawful claim. Where no lawful claim is established within the maximum period permitted by applicable law, remaining funds are transferred to the Humanity Stake, governed for the benefit of all.\n\nIII.\nThe protocol enforces delivery. No custodian, no lawyer, no intermediary is required for a promise between a sender and a reachable recipient. Where delivery requires human verification, the Verified Delivery Protocol holds funds under post-quantum encryption until a bonded finder completes delivery. The blockchain is the contract.\n\nIV.\nAll promises and their fulfillment remain subject to the laws of applicable jurisdictions.";'''

        content = content.replace(old_text, new_axioms)
        print("  [3] Replaced promise_axioms with Genesis 8 text.")
        changed = True
    else:
        if "promise_axioms" in content:
            print("  [3] promise_axioms present but pattern not matched — CHECK MANUALLY.")
        else:
            print("  [3] No promise_axioms found — skipping.")

    # ── 4. Replace trading_axioms with Genesis 8 text ──────────────────────
    if 'let trading_axioms = "ChronX AI Trading Axioms' in content:
        start_marker = 'let trading_axioms = "'
        start_idx = content.index(start_marker)
        search_from = start_idx + len(start_marker)
        end_idx = content.index('";', search_from) + 2

        old_text = content[start_idx:end_idx]

        new_axioms = r'''let trading_axioms = "ChronX AI Trading Axioms\nEncoded at Genesis. Immutable. Consent required from the grantor when enabling AI investment management, and from the AI agent when accepting any mandate. ChronX does not guarantee the performance of any registered agent.\n\nI.\nThe grantor\u2019s intent, once encoded, is carried forward by autonomous software. Algorithms may evolve. The intent does not. An autonomous agent has no authority beyond that mandate.\n\nII.\nEvery trade is recorded on the blockchain at the time it occurs.\n\nIII.\nThe grantor acknowledges, and the AI agent affirms, that AI management of any investment tranche may result in gains or losses up to and including total loss.\n\nIV.\nAll trades, mandates, and their fulfillment remain subject to the laws of applicable jurisdictions.";'''

        content = content.replace(old_text, new_axioms)
        print("  [4] Replaced trading_axioms with Genesis 8 text.")
        changed = True
    else:
        if "trading_axioms" in content:
            print("  [4] trading_axioms present but pattern not matched — CHECK MANUALLY.")
        else:
            print("  [4] No trading_axioms found — skipping.")

    # ── 5. Store Genesis 8 constants as metadata ───────────────────────────
    if "genesis_8_constants" not in content:
        anchor = 'info!("genesis: Genesis 7 constants stored as metadata");'
        if anchor in content:
            genesis_8_block = '''

    // ── Genesis 8 — Store protocol constants as auditable metadata ───────
    {
        use chronx_core::constants::*;
        let genesis_8_json = format!(
            r#"{{"encryption_scheme":"{}","misai_investable_fraction_max":{},"agent_loan_return_obligation":"{}","agent_assignment_mechanism":"{}","axiom_consent_required":{},"misai_loan_package_max_intent_chars":{},"misai_min_investment_window_days":{}}}"#,
            GENESIS_8_ENCRYPTION_SCHEME, MISAI_INVESTABLE_FRACTION_MAX,
            AGENT_LOAN_RETURN_OBLIGATION, AGENT_ASSIGNMENT_MECHANISM,
            AXIOM_CONSENT_REQUIRED, MISAI_LOAN_PACKAGE_MAX_INTENT_CHARS,
            MISAI_MIN_INVESTMENT_WINDOW_DAYS,
        );
        db.put_meta("genesis_8_constants", genesis_8_json.as_bytes())?;
        info!("genesis: Genesis 8 constants stored as metadata");
    }

    // ── Genesis 8 — Store assignment mechanism as governable metadata ─────
    if let Some(ref mechanism) = params.genesis_8_assignment_mechanism {
        db.put_meta("genesis_8_assignment_mechanism", mechanism.as_bytes())?;
        info!(mechanism = %mechanism, "genesis: assignment mechanism stored");
    }'''
            content = content.replace(anchor, anchor + genesis_8_block)
            print("  [5] Added Genesis 8 constants metadata storage block.")
            changed = True
        else:
            print("ERROR [5]: Could not find 'genesis: Genesis 7 constants stored as metadata' anchor.")
    else:
        print("  [5] genesis_8_constants already present — skipping.")

    # ── 6. Add misai_agent_wallet to build_accounts() ──────────────────────
    if "misai_agent_wallet:" not in content:
        anchor = "humanity_stake_pool: account_id_from_pubkey(&params.humanity_stake_pool_pubkey.0),"
        if anchor in content:
            new_line = (
                anchor + "\n"
                "        misai_agent_wallet: account_id_from_pubkey(&params.misai_agent_wallet_pubkey.0),"
            )
            content = content.replace(anchor, new_line)
            print("  [6] Added misai_agent_wallet to build_accounts().")
            changed = True
        else:
            # Try alternate anchor without the full line — might have different formatting
            alt_anchor = "humanity_stake_pool: account_id_from_pubkey("
            if alt_anchor in content:
                idx = content.index(alt_anchor)
                # Find end of line
                eol = content.index("\n", idx)
                line = content[idx:eol]
                new_line = (
                    line + "\n"
                    "        misai_agent_wallet: account_id_from_pubkey(&params.misai_agent_wallet_pubkey.0),"
                )
                content = content.replace(line, new_line, 1)
                print("  [6] Added misai_agent_wallet to build_accounts() (alt anchor).")
                changed = True
            else:
                print("ERROR [6]: Could not find humanity_stake_pool in build_accounts().")
    else:
        print("  [6] misai_agent_wallet already in build_accounts() — skipping.")

    # ── 7. Update test_params — add misai_agent_wallet_pubkey if needed ────
    if "fn test_params" in content and "misai_agent_wallet_pubkey" not in content:
        # The test_params function should already have the `ma` keypair from patch_params.py.
        # But if GenesisAccounts now has misai_agent_wallet, we might need to update.
        # This is handled by patch_params.py — skip here.
        print("  [7] test_params update deferred to patch_params.py.")
    elif "misai_agent_wallet_pubkey" in content:
        print("  [7] test_params already has misai_agent_wallet_pubkey — OK.")

    if changed:
        with open(TARGET, "w") as f:
            f.write(content)
        print("DONE: Patched genesis/lib.rs with Genesis 8 changes.")
    else:
        print("No changes made to genesis/lib.rs.")


if __name__ == "__main__":
    main()
