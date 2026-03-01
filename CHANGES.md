# ChronX Changelog

This changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
Each entry documents what changed at the protocol level, which crates were affected, and which tests cover the change.
Unreleased sections accumulate changes until a versioned release is tagged.

---

## [Unreleased] — Protocol V3.2

### Summary
Protocol V3.2 adds eight dormant, forward-compatible fields and three new enums
to `TimeLockContract` for conditional payment support. No consensus logic is
attached — these fields are scaffolding for the oracle-verified payment feature
planned in a future protocol version. All fields use `#[serde(default)]` for
full backward compatibility with V0/V2/V3/V3.1 stored locks.

### New Enums
- `OraclePolicy` — `AnyBondedAgent | SpecificAgent(AccountId) | MultiSig { agents, threshold } | ExternalFeed { feed_id }`
  — specifies who is authorised to verify a conditional payment.
- `ConditionPrecision` — `Exact | Interpretive | Expert`
  — how strictly the oracle must interpret the condition text.
- `ConditionStatus` — `Pending | Verified { attestation_id } | Disputed { challenger } | Expired | Reverted`
  — lifecycle state of condition verification.

### New TimeLockContract Fields — Conditional Payments (dormant)
| Field | Type | Default | Purpose |
|---|---|---|---|
| `condition_description` | `Option<String>` | `None` | Plain-English condition (max 1 024 bytes); if set, `condition_expiry` must also be set |
| `condition_expiry` | `Option<u64>` | `None` | UTC Unix timestamp — condition must verify before this date or funds revert |
| `condition_oracle` | `Option<OraclePolicy>` | `None` | Who is authorised to attest the condition |
| `condition_precision` | `Option<ConditionPrecision>` | `None` | Interpretation strictness |
| `condition_status` | `Option<ConditionStatus>` | `None` | Current verification lifecycle state |
| `condition_attestation_id` | `Option<TxId>` | `None` | TxId of the attestation vertex once verified |
| `condition_disputed` | `bool` | `false` | Whether a dispute has been raised against the attestation |
| `condition_dispute_window_secs` | `Option<u64>` | `None` | Seconds after attestation before funds release (dispute window) |

### Affected Crates
- `chronx-core` — new enums + fields in `account.rs`
- `chronx-state` — 4 `TimeLockContract` initializers in `engine.rs` updated
- `chronx-genesis` — `genesis_lock()` initializer in `lib.rs` updated

### Tests
All 45 existing lib tests pass unmodified. No new consensus tests (fields are dormant).

---

## [Unreleased] — Protocol V3.1

### Summary
Protocol V3.1 adds two groups of dormant, forward-compatible fields to
`TimeLockContract`. No consensus logic is attached to these fields — they are
scaffolding for features planned in future protocol versions. All fields use
`#[serde(default)]` so existing stored data (V0/V2/V3 locks) deserialises
correctly without any migration.

### New Enum
- `UnclaimedAction` — `RevertToSender | Burn | ForwardTo(AccountId)` — governs
  what happens to email-lock funds when the claim window expires unclaimed.

### New TimeLockContract Fields — Transferability (dormant)
| Field | Type | Default | Purpose |
|---|---|---|---|
| `transferable` | `bool` | `false` | Sender-set flag: claim right may be assigned |
| `transfer_policy` | `Option<PolicyId>` | `None` | Governance rule-set for secondary market |
| `current_beneficiary` | `Option<AccountId>` | `None` | Current holder of claim right (None = original recipient) |
| `transfer_history` | `Vec<TxId>` | `[]` | Append-only audit trail of transfers |
| `earliest_transfer_date` | `Option<u64>` | `None` | Deferred transferability timestamp |

### New TimeLockContract Fields — Email-lock (dormant)
| Field | Type | Default | Purpose |
|---|---|---|---|
| `recipient_email_hash` | `Option<[u8; 32]>` | `None` | BLAKE3 of recipient email — never plaintext |
| `claim_window_secs` | `Option<u64>` | `None` | Seconds to claim before `unclaimed_action` fires |
| `unclaimed_action` | `Option<UnclaimedAction>` | `None` | Action on claim-window expiry |
| `notification_sent` | `bool` | `false` | Off-chain flag: claim email dispatched |

---

## [Unreleased] — Protocol V3

### Summary
Protocol V3 adds maximum optionality to every major on-chain structure before the
final re-genesis. All new fields use `#[serde(default)]` so existing stored data
remains fully forward-compatible. No fields have been removed. Total supply is now
confirmed at **8,270,000,000 KX**.

---

### Breaking Changes
- `PUBLIC_SALE_KX` reduced from **7,269,000,000** to **7,268,000,000** to make room
  for the two new genesis time-locks below. Re-genesis required.

---

### New Genesis Locks
| Lock | Amount | Unlock |
|------|--------|--------|
| Milestone 2076 | 500,000 KX | 2076-01-01 |
| Protocol Reserve | 500,000 KX | 2036-01-01 |

Total supply breakdown:
- Public sale: 7,268,000,000 KX
- Treasury (100-year schedule): 1,000,000,000 KX
- Humanity stake: 1,000,000 KX
- Milestone 2076: 500,000 KX
- Protocol reserve: 500,000 KX
- **Total: 8,270,000,000 KX**

---

### chronx-core

#### `account.rs`
- Added `account_version: u16` field to `Account` (default 1)
- Added `created_at: Option<i64>` — Unix timestamp when the account was first written
- Added `display_name_hash: Option<[u8; 32]>` — optional off-chain display name commitment
- Added `incoming_locks_count: u32` — cached count of incoming pending locks
- Added `outgoing_locks_count: u32` — cached count of outgoing pending locks
- Added `total_locked_incoming_chronos: u128` — cached sum of incoming pending locks
- Added `total_locked_outgoing_chronos: u128` — cached sum of outgoing pending locks
- Added `preferred_fiat_currency: Option<String>` — ISO 4217 currency hint
- Added `extension_data: Option<Vec<u8>>` — up to 1 KiB arbitrary metadata
- Added new enums to `account.rs`:
  - `ExpiryPolicy { ReturnToSender, Burn, RedirectTo(AccountId) }`
  - `RecurringPolicy { None, Weekly, Monthly, Annual }` (each with a `count: u32`)
  - `SplitPolicy { recipients: Vec<(AccountId, u16)> }` (basis points, must sum to 10,000)
- Added `Cancelled { cancelled_at: Timestamp }` variant to `TimeLockStatus`
- Updated `is_terminal()` to include `Cancelled`
- Added 13 new optional fields to `TimeLockContract` (all `#[serde(default)]`):
  - `cancellation_window_secs: Option<u64>`
  - `notify_recipient: bool` (default `true`)
  - `tags: Option<Vec<String>>`
  - `private: bool` (default `false`)
  - `expiry_policy: Option<ExpiryPolicy>`
  - `split_policy: Option<SplitPolicy>`
  - `claim_attempts_max: Option<u32>`
  - `recurring: Option<RecurringPolicy>`
  - `extension_data: Option<Vec<u8>>`
  - `oracle_hint: Option<String>`
  - `jurisdiction_hint: Option<String>`
  - `governance_proposal_id: Option<u64>`
  - `client_ref: Option<[u8; 16]>`

#### `transaction.rs`
- Added `tx_version: u16` to `Transaction` (default 1)
- Added `client_ref: Option<[u8; 16]>` to `Transaction` — opaque client correlation ID
- Added `fee_chronos: u128` to `Transaction` — reserved for future fee market
- Added `expires_at: Option<i64>` to `Transaction` — transaction TTL
- Extended `Action::TimeLockCreate` with 13 matching optional fields
- Added `Action::CancelTimeLock { lock_id: TimeLockId }` — sender-initiated cancellation

#### `constants.rs`
- Added `MIN_LOCK_AMOUNT_CHRONOS = 1_000_000` (1 KX minimum per lock)
- Added `MAX_MEMO_BYTES = 256`
- Added `MAX_TAGS_PER_LOCK = 5`
- Added `MAX_TAG_LENGTH = 32`
- Added `MAX_LOCKS_PER_QUERY = 100`
- Added `DEFAULT_CANCELLATION_WINDOW_SECS = 0`
- Added `MAX_LOCK_DURATION_YEARS = 200`
- Added `MIN_LOCK_DURATION_SECS = 3_600` (1 hour)
- Added `MAX_EXTENSION_DATA_BYTES = 1_024`
- Added `MAX_RECURRING_COUNT = 1_200`
- Added `CANCELLATION_WINDOW_MAX_SECS = 86_400` (24 hours)
- Added `MILESTONE_2076_UNLOCK_TIMESTAMP` and `PROTOCOL_RESERVE_UNLOCK_TIMESTAMP`
- Added `MILESTONE_2076_KX = 500_000` and `PROTOCOL_RESERVE_KX = 500_000`

#### `error.rs`
- Added 13 new error variants for consensus validation:
  `LockAmountTooSmall`, `LockDurationTooShort`, `LockDurationTooLong`,
  `MemoTooLong`, `TooManyTags`, `TagTooLong`, `ExtensionDataTooLarge`,
  `CancellationWindowTooLong`, `SplitPolicyBasisPointsMismatch`,
  `RecurringCountTooLarge`, `CancellationWindowExpired`, `CancelNotBySender`,
  `TransactionExpired`

---

### chronx-state

#### `engine.rs`
- Added 10 consensus validation rules for `TimeLockCreate`:
  amount ≥ MIN, duration in bounds, memo ≤ 256 bytes, ≤ 5 tags, each tag ≤ 32 chars,
  extension_data ≤ 1 KiB, cancellation window ≤ 24 h, split policy sums to 10,000 bps,
  recurring count ≤ 1,200
- Added full `CancelTimeLock` handler: validates sender, Pending status, window not
  expired, returns chronos to sender, sets `Cancelled` status
- Added `expires_at` check: transactions with `expires_at < now` are rejected

#### `db.rs`
- Added `iter_all_timelocks()` — full timelock scan (no filter)
- Added `iter_all_vertices()` — full vertex scan
- Added `count_accounts()`, `count_timelocks()`, `count_vertices()` — O(1) row counts

---

### chronx-genesis
- Added `genesis_lock()` helper for constructing genesis-time `TimeLockContract`s
- Added Milestone 2076 lock (500,000 KX, unlocks 2076-01-01)
- Added Protocol Reserve lock (500,000 KX, unlocks 2036-01-01)
- Added deterministic IDs: `milestone_2076_lock_id()`, `protocol_reserve_lock_id()`
- `verify_genesis_supply` updated to include both new locks in the supply audit

---

### chronx-timelock
- `TimeLockQuery::describe()` handles new `Cancelled` status variant

---

### chronx-rpc

#### CORS
- All RPC responses now include permissive CORS headers (`Access-Control-Allow-*: *`)
  via `tower-http` middleware. Required for browser-based clients.

#### New methods (V3)
| Method | Description |
|--------|-------------|
| `chronx_getTimeLockById(lock_id)` | Fetch a single lock by TxId hex |
| `chronx_getPendingIncoming(account_id)` | Pending locks where account is recipient |
| `chronx_getTimeLockContractsPaged(account_id, offset, limit)` | Paginated lock list (max 200/page) |
| `chronx_getChainStats()` | Aggregate stats: accounts, timelocks, vertices, DAG depth |
| `chronx_getRecentTransactions(limit)` | Most recent N transactions (max 200) |
| `chronx_getLocksByUnlockDate(from_unix, to_unix)` | Locks maturing in a date range |
| `chronx_getVersion()` | Node/protocol/API version string |
| `chronx_cancelLock(tx_hex)` | Submit a CancelTimeLock transaction (validates action type) |
| `chronx_searchLocks(query)` | Filter by account + status + tags + date range + pagination |

#### Updated methods
- `chronx_getAccount` now returns `account_version`, `created_at`,
  `incoming_locks_count`, `outgoing_locks_count`, `incoming_locked_chronos`,
  `outgoing_locked_chronos`
- `chronx_getTimeLockContracts` response items now include `tags`, `private`,
  `lock_version` fields

---

### chronx-wallet (CLI)
- `Transaction` construction updated with `tx_version`, `client_ref`, `fee_chronos`, `expires_at`
- `TimeLockCreate` action updated with all 13 new `None` optional fields

---

### Wallet GUI (wallet-gui-temp)
- **Spendable balance**: `AccountInfo` now includes `spendable_kx` / `spendable_chronos`;
  the Account tab shows both total and spendable balance
- **Incoming locks**: Account tab now queries `chronx_getPendingIncoming` on load and
  displays up to 20 pending incoming locks in faded gold with unlock dates
- **Transaction fix**: `build_sign_mine_submit` now constructs `Transaction` with all
  V3 fields (`tx_version`, `client_ref`, `fee_chronos`, `expires_at`)
- **TimeLockCreate fix**: `create_timelock` now passes all 13 new optional fields as `None`
- **Config fix**: `set_node_url` now reads the existing config before writing, preventing
  accidental erasure of other config fields
- Added `get_pending_incoming` Tauri command

---

### Tests
- All 29 library unit tests pass (`cargo test --lib`)
- Genesis supply verification confirms 8,270,000,000 KX total
- Treasury lock ID uniqueness: 100 unique deterministic IDs confirmed
- Engine: `honest_claim_full_flow` and `fraudulent_claim_hash_mismatch_slashed` both pass
