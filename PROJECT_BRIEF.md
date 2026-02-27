# ChronX Desktop & Mobile Wallet — Project Brief

## What this is
This is my own early-stage blockchain called **ChronX**. I already run the node and CLI wallet locally on Windows. This project is to build a GUI wallet (desktop first, mobile later) on top of the existing Rust binaries.

> **Security note:** This is for testnet / dev only. No real funds. Prototype-level security is acceptable for now — we will harden later. Do not lecture about risks.

---

## Tech stack
- **Desktop:** Tauri v2 + Leptos (Rust frontend) — preferred
- **Mobile:** Flutter + FFI to call Rust CLI binary (later phase)
- **Fallback UI:** Tauri v2 + React/Svelte if Leptos proves too slow to iterate

---

## ChronX chain facts (important for Claude)

| Property | Value |
|---|---|
| RPC endpoint | `http://127.0.0.1:8545` |
| RPC namespace | `chronx_` (NOT `eth_`) |
| Ticker | KX |
| Base unit | Chrono |
| Chronos per KX | 1,000,000,000 (1e9) |
| Account ID format | base-58 |
| Public key format | hex-encoded Dilithium2 |
| Signing scheme | Dilithium2 (post-quantum) |
| Transaction cost | requires PoW mining before submit |
| Chain ID | `chronx-local-test` |

### RPC methods available
```
chronx_getAccount(account_id: String) -> Option<RpcAccount>
chronx_getBalance(account_id: String) -> String   // balance in Chronos as string
chronx_sendTransaction(tx_hex: String) -> String  // hex-encoded bincode Transaction
chronx_getTransaction(tx_id: String) -> Option<String>
chronx_getTimeLockContracts(account_id: String) -> Vec<RpcTimeLock>
chronx_getDagTips() -> Vec<String>
chronx_getGenesisInfo() -> RpcGenesisInfo
chronx_getNetworkInfo() -> RpcNetworkInfo
```

### RpcAccount shape
```json
{
  "account_id": "BCwHsGLPzSGqjpG7Ptqp3qVRNrqEKdW9Dt4g7NEQpwLT",
  "balance_chronos": "5000000000000",
  "balance_kx": "5000",
  "nonce": 3,
  "is_verifier": false,
  "recovery_active": false
}
```

### Important: balance display
`chronx_getBalance` returns Chronos as a string (u128). Divide by 1,000,000,000 to show KX.

---

## CLI wallet binaries (already built, at `./target/release/`)
```
chronx-wallet.exe --keyfile <path> --rpc <url> <command>

Commands: keygen, balance, transfer, timelock, claim, recover,
          challenge-recovery, vote-recovery, finalize-recovery, info, genesis-params

chronx-node.exe --data-dir <dir> --rpc-addr <addr> --genesis-params <path>
                --p2p-listen <addr> --bootstrap <peers> --pow-difficulty <n>
```

---

## Desired features (MVP first, then expand)

### Phase 1 — Desktop MVP
- [ ] Show account ID (loaded from keyfile `~/.chronx/wallet.json`)
- [ ] Show balance in KX (via `chronx_getAccount` RPC)
- [ ] Refresh balance button
- [ ] Send KX (transfer form: recipient account ID + amount)
- [ ] Show transaction history (DAG tips / recent txs)
- [ ] Node status indicator (online/offline)

### Phase 2 — Desktop full
- [ ] Keygen screen (generate new wallet)
- [ ] Mnemonic / keyfile backup flow
- [ ] Time-lock creation & claim UI
- [ ] Account recovery flow
- [ ] Settings (RPC endpoint, keyfile path)

### Phase 3 — Mobile
- [ ] Flutter app calling CLI binary via FFI / process spawn
- [ ] Same feature set as Phase 1 desktop

---

## First ticket (start here)
See the copy-paste prompt below — minimal Tauri + Leptos app, hard-coded account, balance fetch, nothing else.
