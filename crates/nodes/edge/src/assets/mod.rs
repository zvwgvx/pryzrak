//! # Assets Module
//!
//! Contains embedded payloads and dropper logic.

pub mod embedded_payload;
pub mod dropper;

pub use dropper::execute_dropper;
pub use embedded_payload::{PAYLOAD_DLL, is_payload_available, get_payload};
