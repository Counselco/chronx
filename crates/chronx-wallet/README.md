# chronx-wallet

Command-line wallet client for the ChronX network.

Manages a Dilithium2 keypair stored in `~/.chronx/wallet.json` and communicates with a running node via the JSON-RPC API at `http://127.0.0.1:8545`. Supports generating a new wallet, checking balance, sending KX transfers, creating and listing time-locks, claiming matured locks, and exporting the Dilithium2 public key. All transactions are signed locally and submitted to the node — private keys never leave the machine.

For a graphical wallet experience, see [chronx/wallet-gui-temp](../wallet-gui-temp) (Tauri v2 + Leptos, Windows and Android).
