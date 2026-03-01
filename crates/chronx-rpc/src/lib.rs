//! chronx-rpc
//!
//! JSON-RPC 2.0 server for ChronX nodes.
//!
//! Namespace: "chronx"
//! Methods:
//!   chronx_getAccount          — full account state
//!   chronx_getBalance          — balance in Chronos
//!   chronx_sendTransaction     — submit a signed transaction (hex-encoded bincode)
//!   chronx_getTransaction      — get a vertex/tx by TxId hex
//!   chronx_getTimeLockContracts — list time-locks for an account
//!   chronx_getDagTips           — current DAG tip TxIds
//!   chronx_getGenesisInfo       — protocol constants

pub mod api;
pub mod server;
pub mod types;

pub use server::RpcServer;
pub use server::RpcServerState;
pub use types::{
    RpcAccount, RpcClaimState, RpcGenesisInfo, RpcNetworkInfo, RpcOracleSnapshot, RpcProvider,
    RpcSchema, RpcTimeLock,
};
