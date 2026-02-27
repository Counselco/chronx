//! chronx-timelock
//!
//! High-level query and service layer for time-lock contracts.
//! The core create/claim/sell logic lives in chronx-state's StateEngine.
//! This crate provides queries, schedule computation, and the treasury
//! logarithmic release schedule.

pub mod query;
pub mod schedule;

pub use query::TimeLockQuery;
pub use schedule::{treasury_release_amount, treasury_release_schedule, TreasuryRelease};
