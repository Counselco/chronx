<div align="center">
  <img src="https://raw.githubusercontent.com/Counselco/wallet-gui/main/assets/chronx-logo.png" alt="ChronX Logo" width="120" />

  <h1>ChronX</h1>

  <p><strong>The Future Payment Protocol — The ledger for long-horizon human promises.</strong></p>

  [![ChronX CI](https://github.com/Counselco/chronx/actions/workflows/ci.yml/badge.svg)](https://github.com/Counselco/chronx/actions/workflows/ci.yml)
  [![License: MIT](https://img.shields.io/badge/License-MIT-gold.svg)](LICENSE)
  [![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](https://www.rust-lang.org)
  [![Release](https://img.shields.io/badge/release-v1.0.0-blue.svg)](https://github.com/Counselco/chronx/releases)

</div>

---

## What is ChronX?

ChronX is a post-quantum blockchain built for one purpose: making long-horizon financial commitments as trustworthy and permanent as physical reality. Where traditional finance requires intermediaries to enforce deferred payments — escrow agents, trustees, banks — ChronX enforces them in software, cryptographically, with no custodian required.

The ChronX protocol is designed around time-locked smart contracts called *promises*. A promise locks a fixed amount of KX (ChronX's native coin) until a specific UTC timestamp — from one hour in the future to one hundred years. Only the designated recipient can claim the funds once the unlock date passes, and no party can reverse or accelerate the lock once committed. This makes ChronX the first blockchain purpose-built for multi-decade financial obligations: inheritance, pensions, milestone-based payouts, long-term escrow, and personal savings commitments.

ChronX is quantum-resistant from day one, using Dilithium2 (CRYSTALS-Dilithium) post-quantum signatures for all transactions. With a fixed supply of 8,270,000,000 KX — no inflation, no mining rewards, no new issuance — and a genesis designed to be fair and transparent, ChronX is built to endure.

---

## Why ChronX?

- **Quantum-resistant** — All signatures use Dilithium2 (NIST PQC standard), not ECDSA or Ed25519
- **Native time-locks** — First-class on-chain promises with UTC unlock timestamps, not scripted workarounds
- **Claims resolution** — Built-in dispute framework for contested claims, with verifier voting and challenge periods
- **No inflation** — Fixed supply of 8,270,000,000 KX; no block rewards, no new issuance ever
- **No custodian** — Locks are enforced by the protocol; no escrow agent, bank, or trustee required
- **100-year horizon** — Designed for promises that outlast institutions
- **Open source** — MIT licensed; every line of consensus logic is auditable

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Counselco/chronx.git
cd chronx

# 2. Build the full node
cargo build --release -p chronx-node

# 3. Generate genesis parameters (first run only)
#    The node will auto-generate ephemeral keys if --genesis-params is omitted.
#    For production, provide your own genesis-params.json.

# 4. Run a node (development)
./target/release/chronx-node \
  --data-dir ~/.chronx/data \
  --rpc-addr 127.0.0.1:8545 \
  --p2p-listen /ip4/0.0.0.0/tcp/7777

# 5. Build and run the CLI wallet
cargo build --release -p chronx-wallet
./target/release/chronx-wallet generate
./target/release/chronx-wallet balance
```

---

## Running a Node

```bash
chronx-node [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--data-dir <PATH>` | `~/.chronx/data` | Directory for the state database |
| `--p2p-listen <MULTIADDR>` | `/ip4/0.0.0.0/tcp/7777` | libp2p listen address |
| `--rpc-addr <ADDR>` | `127.0.0.1:8545` | JSON-RPC 2.0 listen address |
| `--bootstrap <ADDRS>` | *(none)* | Comma-separated bootstrap peer multiaddresses |
| `--genesis-params <PATH>` | *(auto-generate)* | Path to `genesis-params.json` (required for production) |
| `--pow-difficulty <N>` | `20` | PoW difficulty in leading zero bits (SHA3-256) |

**Example — join an existing network:**

```bash
chronx-node \
  --data-dir ~/.chronx/data \
  --rpc-addr 0.0.0.0:8545 \
  --p2p-listen /ip4/0.0.0.0/tcp/7777 \
  --bootstrap /ip4/1.2.3.4/tcp/7777/p2p/12D3Koo... \
  --genesis-params /etc/chronx/genesis-params.json
```

The node exposes a JSON-RPC 2.0 API on `--rpc-addr` with CORS headers enabled for browser clients. See [RPC API](#rpc-api) below.

---

## Using the Wallet

The CLI wallet connects to a running node at `http://127.0.0.1:8545` by default.

```bash
# Generate a new keypair and wallet file
chronx-wallet generate

# Check your balance
chronx-wallet balance

# Send KX to another account
chronx-wallet send --to <ACCOUNT_ID> --amount 100.0

# Create a time-locked promise (to yourself, unlocks 2030-01-01)
chronx-wallet lock --amount 500.0 --unlock 2030-01-01

# List all your time-locks
chronx-wallet locks

# Claim a matured lock
chronx-wallet claim --lock-id <LOCK_ID_HEX>

# Export your Dilithium2 public key (hex)
chronx-wallet export-pubkey
```

A graphical wallet (Windows + Android) is available at [Counselco/wallet-gui](https://github.com/Counselco/wallet-gui).

---

## Architecture

ChronX is structured as a Rust workspace with 12 focused crates:

| Crate | Description |
|---|---|
| `chronx-core` | Core types: `Account`, `TimeLockContract`, `Transaction`, `AuthPolicy`, enums |
| `chronx-crypto` | Post-quantum Dilithium2 signatures, BLAKE3/SHA3 hashing, PoW mining |
| `chronx-dag` | DAG vertex structure and parent-validation rules |
| `chronx-state` | `StateDb` (sled-backed storage) + `StateEngine` (consensus + state transitions) |
| `chronx-consensus` | PoW difficulty adjustment, finality rules, validator logic |
| `chronx-timelock` | Time-lock query helpers and treasury release schedule |
| `chronx-recovery` | Account recovery: verifier voting, challenge mechanism, fee calculation |
| `chronx-p2p` | libp2p networking: GossipSub broadcast + Kademlia peer discovery |
| `chronx-rpc` | JSON-RPC 2.0 server (jsonrpsee) with CORS for 20+ API endpoints |
| `chronx-node` | Full-node binary: genesis init, P2P + RPC startup, transaction pipeline |
| `chronx-wallet` | CLI wallet client: keypair management, transfers, time-locks |
| `chronx-genesis` | One-time genesis state builder: 5 allocations → 8,270,000,000 KX total |

---

## Genesis

The ChronX genesis state is deterministic and verified on every node startup.

**Genesis Timestamp:** 2026-01-01 00:00:00 UTC

| Allocation | Amount (KX) | Unlock |
|---|---|---|
| Public sale | 7,268,000,000 | Immediate (spendable at genesis) |
| Treasury (100 annual locks) | 1,000,000,000 | Log-declining schedule, 2027–2126 |
| Humanity stake | 1,000,000 | 2127-01-01 |
| Milestone 2076 | 500,000 | 2076-01-01 |
| Protocol reserve | 500,000 | 2036-01-01 |
| **Total** | **8,270,000,000** | — |

All genesis lock IDs are deterministic (BLAKE3 hashes of fixed strings) and cannot be forged or replicated.

---

## RPC API

The node exposes a JSON-RPC 2.0 API. All methods are prefixed `chronx_`.

```
POST http://127.0.0.1:8545
Content-Type: application/json
```

| Method | Parameters | Description |
|---|---|---|
| `chronx_getAccount` | `account_id: String` | Account balance, nonce, lock counters, verifier stake |
| `chronx_getBalance` | `account_id: String` | Raw balance in Chronos (1 KX = 1,000,000 Chronos) |
| `chronx_sendTransaction` | `tx_hex: String` | Submit a signed, PoW-solved transaction |
| `chronx_getTransaction` | `tx_id: String` | Fetch a serialized transaction vertex by TxId |
| `chronx_getTimeLockContracts` | `account_id: String` | All locks where account is sender or recipient |
| `chronx_getTimeLockById` | `lock_id: String` | Fetch a single lock by its TxId hex |
| `chronx_getPendingIncoming` | `account_id: String` | Pending locks where account is the recipient |
| `chronx_getTimeLockContractsPaged` | `account_id, offset, limit` | Paginated lock list (max 200/page) |
| `chronx_getRecentTransactions` | `limit: u64` | Most recent N transactions (max 200) |
| `chronx_getChainStats` | *(none)* | Account count, timelock count, vertex count, DAG depth |
| `chronx_cancelLock` | `tx_hex: String` | Submit a `CancelTimeLock` transaction |
| `chronx_getVersion` | *(none)* | Node version, protocol version, API version |
| `chronx_getGenesisInfo` | *(none)* | Genesis timestamp, total supply, initial PoW difficulty |
| `chronx_getDagTips` | *(none)* | Current DAG tip TxIds |
| `chronx_getNetworkInfo` | *(none)* | Local peer multiaddress for bootstrap sharing |
| `chronx_searchLocks` | `query: SearchQuery` | Filter locks by account, status, tags, date range |

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| Phase 1: Mainnet Launch | In Progress | Genesis, full node, CLI wallet, GUI wallet (Windows + Android) |
| Phase 2: Mobile Wallet | Planned | iOS wallet, biometric unlock, QR promise sharing |
| Phase 3: Claims Resolution | Planned | Activate V2 claims state machine, verifier staking, dispute portal |
| Phase 4: DEX / Marketplace | Planned | Secondary market for transferable promises (V3.1 transferability) |
| Phase 5: DAO Governance | Planned | On-chain governance for protocol parameter updates |

---

## Contributing

We welcome contributions from the community. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on setting up your development environment, code style, and the PR process.

---

## Security

ChronX uses post-quantum cryptography (Dilithium2) and takes all security reports seriously. See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Links

- **Website:** [chronx.io](https://chronx.io)
- **Whitepaper:** [ChronX_Whitepaper_v2.0.docx](https://github.com/Counselco/chronx-docs/blob/main/whitepaper/ChronX_Whitepaper_v2.0.docx)
- **GUI Wallet:** [github.com/Counselco/wallet-gui](https://github.com/Counselco/wallet-gui)
