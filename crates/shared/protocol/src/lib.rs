pub mod types;
pub mod uplink;
pub mod p2p;
pub mod wire; // New module

// Re-export common types for convenience
pub use types::*;
pub use uplink::MqttPacket;
pub use p2p::{P2PMessage, P2PCommand};
// We also export constants from wire via p2p/uplink modules mainly, 
// but wire is accessible for C header generation.
