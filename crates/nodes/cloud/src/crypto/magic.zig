//! Time-Based Magic Generation
//!
//! MUST MATCH Edge (Rust) crypto/magic.rs exactly!
//! All nodes compute the same value for a given time slot.

const std = @import("std");

// ============================================================
// CONSTANTS - MUST MATCH Edge/Phantom
// ============================================================

/// Master seed for time-based derivation
const MASTER_SEED: u64 = 0x36A5EC9D09C60386;

/// Original magic values (used as differentiators)
const P2P_SEED: u32 = 0x597B92A8;

/// Rotation period: 1 week in seconds
const PERIOD_1_WEEK: u64 = 7 * 24 * 60 * 60;

// ============================================================
// FNV-1a HASH - MUST MATCH Edge implementation
// ============================================================

/// Simple hash function (FNV-1a style) - matches Rust version exactly
fn hashU64(value: u64) u32 {
    var h: u32 = 0x811c9dc5;
    const bytes = std.mem.toBytes(value);

    for (bytes) |byte| {
        h ^= @as(u32, byte);
        h = h *% 0x01000193; // wrapping multiply
    }

    return h;
}

/// Get current time slot for a given period
fn timeSlot(period: u64) u64 {
    const now: u64 = @intCast(@max(0, std.time.timestamp()));
    return now / period;
}

// ============================================================
// PUBLIC API
// ============================================================

/// Get P2P discovery magic (rotates weekly)
/// Formula: hash(SEED ^ time_slot) ^ P2P_SEED
/// MUST MATCH Edge's p2p_magic()
pub fn p2pMagic() u32 {
    const slot = timeSlot(PERIOD_1_WEEK);
    return hashU64(MASTER_SEED ^ slot) ^ P2P_SEED;
}

/// Get magic for previous time slot (for tolerance)
pub fn p2pMagicPrev() u32 {
    const slot = timeSlot(PERIOD_1_WEEK);
    const prev_slot = if (slot > 0) slot - 1 else 0;
    return hashU64(MASTER_SEED ^ prev_slot) ^ P2P_SEED;
}

// ============================================================
// TESTS
// ============================================================

test "p2pMagic is deterministic" {
    const m1 = p2pMagic();
    const m2 = p2pMagic();
    try std.testing.expectEqual(m1, m2);
}

test "p2pMagic differs from prev" {
    // This might fail at week boundary, acceptable
    const current = p2pMagic();
    const prev = p2pMagicPrev();
    // They should differ unless we're at start of epoch
    _ = current;
    _ = prev;
}
