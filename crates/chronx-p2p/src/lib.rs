//! chronx-p2p
//!
//! libp2p networking layer for ChronX nodes.
//!
//! GossipSub broadcasts new DAG vertices to all connected peers.
//! Kademlia DHT handles peer discovery and bootstrap.
//! Identify and Ping maintain connection metadata and liveness.

pub mod config;
pub mod message;
pub mod network;

pub use config::P2pConfig;
pub use message::P2pMessage;
pub use network::{P2pHandle, P2pNetwork};
