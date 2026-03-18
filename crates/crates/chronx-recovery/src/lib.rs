//! chronx-recovery
//!
//! High-level service layer for the protocol recovery system.
//! The core state machine transitions live in chronx-state's StateEngine.
//! This crate provides query helpers, bond fee distribution, and verifier
//! registry management utilities.

pub mod fee;
pub mod query;
pub mod verifier;

pub use fee::distribute_recovery_fees;
pub use query::RecoveryQuery;
pub use verifier::VerifierRegistry;
