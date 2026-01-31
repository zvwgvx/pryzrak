//! Crypto module for time-based security primitives

pub mod magic;

pub use magic::{
    p2p_magic, lipc_magic, handshake_magic, handshake_xor,
    p2p_magic_prev, lipc_magic_prev, handshake_magic_prev, handshake_xor_prev,
};
