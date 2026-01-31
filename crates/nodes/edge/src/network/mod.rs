//! # Network Module
//!
//! Handles all network communication for the Edge node.

pub mod client;
pub mod bridge;
pub mod local_comm;
pub mod watchdog;
pub mod bootstrap;
pub mod multi_cloud;

pub use client::PolyMqttClient;
pub use bridge::BridgeService;
pub use local_comm::{LocalTransport, LipcMsgType};
pub use watchdog::{NetworkWatchdog, run_fallback_monitor};
