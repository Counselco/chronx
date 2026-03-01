# ChronX Claims Resolution Framework — V2 Specification

## Overview

V2 extends the time-lock subsystem with a full on-chain claims resolution
framework that handles disputes about lock recipients without requiring a
future hard fork.  All new storage trees and transaction types are additive;
existing V0 locks (lock_version = 0) continue to use the direct-claim path.

---

## Storage Layout

All state is stored in [sled](https://github.com/spacejam/sled) trees.
Keys and values are [bincode](https://github.com/bincode-org/bincode)-serialised.

| Tree name             | Key type         | Value type           |
|-----------------------|------------------|----------------------|
| `timelocks`           | `TxId` (32 B)    | `TimeLockContract`   |
| `claims`              | `TxId` (32 B)    | `ClaimState`         |
| `providers`           | `AccountId` (32 B)| `ProviderRecord`    |
| `schemas`             | `SchemaId` (u64 LE)| `CertificateSchema`|
| `oracle_snapshots`    | pair string UTF-8 | `OracleSnapshot`   |
| `oracle_submissions`  | pair + timestamp | `OracleSubmission`   |

### TimeLockContract new fields (all `#[serde(default)]` for V0 compat)

```
lock_version: u16                      — 0 = V0 direct-claim; 1 = V2 framework
claim_policy: Option<PolicyId>         — references a ClaimPolicy registry entry
beneficiary_anchor_commitment: Option<[u8;32]>  — blake3 of expected beneficiary data
org_identifier: Option<String>         — unique human-readable identifier for ambiguity detection
```

---

## Claim Lifecycle State Machine

```
LOCKED (TimeLockStatus::Pending)
    │ unlock_at <= now
    ▼
CLAIM_OPEN      ← Action::OpenClaim
    │
    ▼
CLAIM_COMMITTED ← Action::SubmitClaimCommit  (agent posts bond + commit hash)
    │
    ▼
CLAIM_REVEALED  ← Action::RevealClaim        (agent reveals payload + salt)
    │                └─ hash mismatch / timeout → CLAIM_SLASHED
    ├── no challenge within window
    │       ▼
    │   CLAIM_FINALIZED ← Action::FinalizeClaim  (agent wins; lock paid out)
    │
    └── challenge submitted within window
            ▼
        CLAIM_CHALLENGED ← Action::ChallengeClaimReveal
                ▼
            CLAIM_SLASHED  ← Action::FinalizeClaim  (challenger wins; agent bond forfeited)
              or
            CLAIM_FINALIZED ← Action::FinalizeClaim  (agent wins; challenge bond forfeited)
```

Additionally:
- V1 locks where both `org_identifier` and `beneficiary_anchor_commitment` are `None`
  enter `AMBIGUOUS` state on `OpenClaim` instead of `CLAIM_OPEN`.

---

## Lane Selection

Lane is determined at `open_claim` time from the fiat-equivalent value of the
lock using the oracle snapshot for the `KX/USD` pair.

| Lane     | USD value at claim-open | Agent bond    | Reveal window | Challenge window |
|----------|------------------------|---------------|---------------|-----------------|
| Trivial  | < $1,000               | 10 KX         | 7 days        | 7 days          |
| Standard | $1,000 – $50,000       | 100 KX        | 14 days       | 14 days         |
| Elevated | ≥ $50,000              | 500 KX        | 30 days       | 21 days         |

All thresholds and bond sizes are stored in `ClaimPolicy` records and are
governance-updatable without a code change (just submit a `RegisterClaimPolicy`
transaction with new values).

---

## Oracle

- Oracle providers must be registered with `provider_class = "oracle"`.
- Price submissions: `Action::SubmitOraclePrice { pair, price_cents }`.
- Snapshot is recomputed as the **median** of all submissions for a pair within
  the past hour (`ORACLE_MAX_AGE_SECS = 3600`).
- Minimum 3 submissions are required (`ORACLE_MIN_SUBMISSIONS = 3`);
  `open_claim` fails with `OracleSnapshotUnavailable` if fewer are present.

---

## Slashing

| Scenario                           | Slashed party | Slash reason              |
|------------------------------------|---------------|---------------------------|
| Agent reveals wrong payload        | Agent         | `RevealHashMismatch`      |
| Agent fails to reveal within window| Agent         | `RevealTimeout`           |
| Successful challenger proves fraud | Agent         | `SuccessfulChallenge`     |
| Required compliance cert missing   | Agent         | `InvalidComplianceCert`   |
| Ambiguous lock times out           | (lock frozen) | `AmbiguityTimeout`        |

Slashed bonds are currently removed from circulation (burned).  A future
governance proposal can redirect them to a treasury or challenger reward pool
without a protocol change.

---

## Extensibility (No Hard Fork Required)

| Extension point          | Mechanism                                        |
|--------------------------|--------------------------------------------------|
| New certificate type     | `Action::RegisterSchema` — no code change        |
| New provider class       | `Action::RegisterProvider` with new class string |
| New lane thresholds      | `ClaimPolicy` governance record update           |
| New oracle pair          | `Action::SubmitOraclePrice` with new pair string |
| New compliance rule      | Update `ClaimPolicy.requires_compliance_cert`    |

All registry records are keyed by opaque u64 IDs (`PolicyId`, `SchemaId`) so
that future on-chain governance can update them atomically.

---

## V0 Backward Compatibility

- `lock_version = 0` and `claim_policy = None` → `Action::TimeLockClaim`
  works exactly as before (no PoW, no bond, no certificates).
- `lock_version = 1` with `claim_policy` set → must use `Action::OpenClaim`;
  calling `TimeLockClaim` on a V1 lock returns
  `Err(LockRequiresClaimsFramework)`.
- All new `TimeLockStatus` variants are serde-compatible with V0 nodes because
  they are additive enum variants with `#[serde(default)]`-guarded container
  fields.

---

## Protocol Constants

```
CHRONOS_PER_KX          = 1_000_000
PROVIDER_BOND_CHRONOS   = 10_000 KX   (registration bond for oracle/compliance providers)
SCHEMA_BOND_CHRONOS     =  1_000 KX   (bond to register a new certificate schema)
ORACLE_MAX_AGE_SECS     = 3_600       (1 hour; older submissions excluded from median)
ORACLE_MIN_SUBMISSIONS  = 3           (minimum distinct oracle submissions required)
UNLOCK_GRACE_SECS       = 604_800     (7-day grace period before OpenClaim is required)
```

---

## RPC Methods (V2 additions)

| Method                          | Returns               |
|---------------------------------|-----------------------|
| `chronx_getProviders`           | `Vec<RpcProvider>`    |
| `chronx_getProvider(id)`        | `Option<RpcProvider>` |
| `chronx_getSchemas`             | `Vec<RpcSchema>`      |
| `chronx_getClaimState(lock_id)` | `Option<RpcClaimState>` |
| `chronx_getOracleSnapshot(pair)`| `Option<RpcOracleSnapshot>` |
