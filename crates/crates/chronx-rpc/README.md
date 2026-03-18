# chronx-rpc

JSON-RPC 2.0 server for the ChronX node, built on [jsonrpsee](https://github.com/paritytech/jsonrpsee).

Exposes 20+ `chronx_*` API endpoints covering account queries, transaction submission, time-lock management, claims state, chain statistics, and protocol version information. CORS headers are set to permissive (`Access-Control-Allow-*: *`) so that browser-based clients — including the Tauri GUI wallet — can connect directly without a reverse proxy. The `RpcServer` wraps a shared `Arc<StateDb>` and an optional `tokio::mpsc::Sender` to forward validated transactions into the node's main pipeline.
