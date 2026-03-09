#!/usr/bin/env python3
"""patch_constants.py — Append Genesis 8 constants after Genesis 7 section."""

TARGET = "/home/josep/chronx/crates/chronx-core/src/constants.rs"

GENESIS_8_BLOCK = '''
// ── GENESIS 8 — POST-QUANTUM ENCRYPTION + AI AGENT ARCHITECTURE ─────────
//
// Genesis 8 adds CRYSTALS-Kyber1024 package encryption, AI agent registry,
// axiom consent gates, and MISAI loan architecture.

/// Post-quantum hybrid encryption scheme identifier.
/// Kyber1024 for key encapsulation, ChaCha20-Poly1305 for data encryption.
pub const GENESIS_8_ENCRYPTION_SCHEME: &str = "KYBER1024_CHACHA20POLY1305";

/// Grantor may offer up to 100% of promise value for AI investment.
/// Grantor's intent is the master — no protocol ceiling imposed.
pub const MISAI_INVESTABLE_FRACTION_MAX: f64 = 1.0;

/// MISAI returns whatever it holds on the return date.
/// No guarantee of principal or yield — ever.
/// This constant must never be changed to any guarantee variant.
pub const AGENT_LOAN_RETURN_OBLIGATION: &str = "BEST_EFFORT";

/// All agent-managed promises assigned to sole registered agent.
/// Governable to ROUND_ROBIN or WEIGHTED_PERFORMANCE when multiple agents exist.
pub const AGENT_ASSIGNMENT_MECHANISM: &str = "SOLE_AGENT";

/// Agent-managed timelocks require grantor axiom consent hash.
/// Agent loan requests require agent axiom consent hash.
/// Both must be present before disbursement fires.
pub const AXIOM_CONSENT_REQUIRED: bool = true;

/// Maximum characters for grantor_intent free text field.
pub const MISAI_LOAN_PACKAGE_MAX_INTENT_CHARS: usize = 1000;

/// MISAI will not accept loans with less than 30 days until return date.
/// Prevents MISAI from receiving funds it cannot meaningfully invest.
pub const MISAI_MIN_INVESTMENT_WINDOW_DAYS: u64 = 30;
'''

def main():
    with open(TARGET, "r") as f:
        content = f.read()

    if "GENESIS_8_ENCRYPTION_SCHEME" in content:
        print("Genesis 8 constants already present — skipping.")
        return

    if "GENESIS_7_SHORT_LOCK_THRESHOLD_SECS" not in content:
        print("ERROR: Could not find GENESIS_7_SHORT_LOCK_THRESHOLD_SECS anchor.")
        return

    # Append the Genesis 8 block at the end of the file
    content = content.rstrip() + "\n" + GENESIS_8_BLOCK

    with open(TARGET, "w") as f:
        f.write(content)

    print("DONE: Appended Genesis 8 constants block to constants.rs")

if __name__ == "__main__":
    main()
