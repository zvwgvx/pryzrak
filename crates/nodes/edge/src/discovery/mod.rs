//! # Discovery Module
//!
//! Handles node discovery and election.

pub mod election;
pub mod zero_noise;
pub mod eth_listener;

pub use election::{ElectionService, NodeRole};
pub use zero_noise::ZeroNoiseDiscovery;
