//! Time-Based Magic Generation for Pryzrak
//!
//! Must match Edge node's crypto/magic.rs exactly!

use std::time::{SystemTime, UNIX_EPOCH};

/// Master seed for time-based derivation (MUST MATCH Edge)
const MASTER_SEED: u64 = 0x36A5EC9D09C60386;

/// Original magic values (used as differentiators)
const P2P_SEED: u32 = 0x597B92A8;

/// Rotation period: 1 week in seconds
const PERIOD_1_WEEK: u64 = 7 * 24 * 60 * 60;

/// Simple hash function (FNV-1a style) - MUST MATCH Edge
fn hash_u64(value: u64) -> u32 {
    let mut h = 0x811c9dc5u32;
    for byte in value.to_le_bytes() {
        h ^= byte as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// Get current time slot for a given period
fn time_slot(period: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / period
}

/// Get P2P discovery magic (rotates weekly)
/// Formula: hash(SEED ^ time_slot) ^ P2P_SEED
/// MUST MATCH Edge's p2p_magic()
pub fn p2p_magic() -> u32 {
    let slot = time_slot(PERIOD_1_WEEK);
    hash_u64(MASTER_SEED ^ slot) ^ P2P_SEED
}

/// Get magic for previous time slot (for tolerance)
pub fn p2p_magic_prev() -> u32 {
    let slot = time_slot(PERIOD_1_WEEK).saturating_sub(1);
    hash_u64(MASTER_SEED ^ slot) ^ P2P_SEED
}
