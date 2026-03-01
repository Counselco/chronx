# chronx-genesis

One-time genesis state builder for the ChronX blockchain.

`apply_genesis` writes accounts and time-lock contracts directly into a `StateDb` — bypassing the normal transaction engine (no PoW, no signatures, no parent links). This is the single point where all 8,270,000,000 KX are created. After genesis, no further minting is ever possible. The function panics if called on a non-empty database (it can only run once). All genesis lock IDs are deterministic: derived from BLAKE3 hashes of fixed strings so that any node can independently verify their correctness without trusting a genesis block hash.

The five allocations are: public sale (7,268,000,000 KX), treasury 100-year schedule (1,000,000,000 KX), humanity stake until 2127 (1,000,000 KX), milestone 2076 (500,000 KX), and protocol reserve until 2036 (500,000 KX).
