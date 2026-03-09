#!/usr/bin/env python3
"""patch_error.py — Add Genesis 8 error variants to ChronxError enum."""

TARGET = "/home/josep/chronx/crates/chronx-core/src/error.rs"

GENESIS_8_ERRORS = '''
    // Genesis 8 — AI Agent Architecture errors
    #[error("agent-managed timelock requires axiom consent hash")]
    AxiomConsentRequired,

    #[error("axiom consent hash does not match current genesis axioms")]
    AxiomConsentMismatch,

    #[error("recipient wallet is not a registered ChronX-approved AI agent")]
    AgentNotRegistered,

    #[error("agent is not currently Active in the registry")]
    AgentNotActive,

    #[error("agent already registered in the registry")]
    AgentAlreadyRegistered,

    #[error("invalid investable fraction: must be between 0.0 and {max}")]
    InvalidInvestableFraction { max: f64 },

    #[error("lock is not agent-managed")]
    LockNotAgentManaged,

    #[error("proposed return date is too soon — minimum {min_days} day investment window")]
    ReturnDateTooSoon { min_days: u64 },

    #[error("return date must be before promise maturity")]
    ReturnDateAfterMaturity,

    #[error("requested fraction does not match grantor's specified investable fraction")]
    FractionMismatch,

    #[error("grantor intent exceeds maximum of {max} characters")]
    GrantorIntentTooLong { max: usize },

    #[error("only the operator wallet may update agent code")]
    AgentCodeUpdateNotByOperator,

    #[error("invalid Kyber1024 public key length")]
    InvalidKyberKeyLength,

    #[error("package encryption failed: {0}")]
    EncryptionFailed(String),

'''

def main():
    with open(TARGET, "r") as f:
        content = f.read()

    if "AxiomConsentRequired" in content:
        print("Genesis 8 error variants already present — skipping.")
        return

    # Find the Other(String) variant and insert before it
    anchor = '    #[error("{0}")]\n    Other(String),'
    if anchor not in content:
        # Try alternate formatting
        anchor = '#[error("{0}")]\n    Other(String),'
        if anchor not in content:
            print("ERROR: Could not find Other(String) variant.")
            return

    content = content.replace(anchor, GENESIS_8_ERRORS + "    " + anchor)

    with open(TARGET, "w") as f:
        f.write(content)

    print("DONE: Added 14 Genesis 8 error variants to error.rs")

if __name__ == "__main__":
    main()
