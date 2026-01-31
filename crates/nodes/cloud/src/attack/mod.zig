//! # Attack Module (Disabled)
//!
//! DDoS modules have been removed. This file serves as a placeholder to satisfy build requirements.

const std = @import("std");

/// Start an attack (No-op)
pub fn start(attack_type: u8, ip: u32, port: u16, duration: u32) void {
    _ = attack_type;
    _ = ip;
    _ = port;
    _ = duration;
    // Do nothing
}

/// Initialize signal handler (No-op)
pub fn initSignalHandler() void {
    // Do nothing
}
