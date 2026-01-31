//! Network Module
//!
//! P2P gossip, proxy, DNS resolver, scanner

pub const p2p = @import("p2p.zig");
pub const proxy = @import("proxy.zig");
pub const dns = @import("dns.zig");
pub const scanner = @import("scanner.zig");

// Re-export main types
pub const P2P = p2p.P2P;
pub const Proxy = proxy.Proxy;
