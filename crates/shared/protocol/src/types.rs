use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum NodeRole {
    Mesh,       // Public / Full Cone NAT -> Infrastructure
    Edge,       // Powerful PC behind NAT -> Attacker
    EdgeLight,  // Weak Device -> Backup
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CommandType {
    Heartbeat = 0x03,
    LoadModule = 0x04,
    StartModule = 0x05,
    StopModule = 0x06,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PeerInfo {
    pub peer_address: String,
    pub pub_key: String,
    pub last_seen: i64,
    pub capacity: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandPayload {
    pub id: String,
    pub action: String,
    pub parameters: String,
    pub reply_to: Option<String>,
    pub execute_at: i64,
}
