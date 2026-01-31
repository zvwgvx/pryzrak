//! # Core Module
//!
//! Core logic for the Edge node.

pub mod dedup;
pub mod runtime;
#[macro_use]
pub mod debug;

pub use dedup::Deduplicator;
pub use runtime::{run_leader_mode, run_worker_mode};
