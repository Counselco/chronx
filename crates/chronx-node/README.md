# chronx-node

The ChronX full-node binary — the entry point for running a network participant.

On startup the node opens (or initialises) the sled-backed `StateDb`, applies the genesis state if the database is fresh, then brings up the libp2p P2P network (GossipSub broadcast + Kademlia peer discovery) and the JSON-RPC 2.0 server. The main loop receives incoming transactions from both the RPC API and P2P gossip, validates and applies them through `StateEngine`, then re-broadcasts accepted transactions to peers. PoW difficulty is adjusted automatically every 10,000 solves using a 100-block window.

**Run a node:**
```bash
cargo run --release -p chronx-node -- \
  --data-dir ~/.chronx/data \
  --rpc-addr 127.0.0.1:8545 \
  --p2p-listen /ip4/0.0.0.0/tcp/7777
```
