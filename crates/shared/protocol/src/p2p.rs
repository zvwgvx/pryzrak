use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::{Signer, SigningKey};
use std::io::Write;

pub const P2P_MAGIC: u32 = 0x9A1D3F7C;
pub const P2P_TYPE_GOSSIP: u8 = 1;
pub const P2P_TYPE_CMD: u8 = 2;

#[derive(Debug, Clone)]
pub enum P2PMessage {
    Gossip(Vec<u8>),
    Command(P2PCommand),
}

#[derive(Debug, Clone)]
pub struct P2PCommand {
    pub nonce: u32,
    pub signature: [u8; 64],
    pub payload: Vec<u8>,
}

impl P2PCommand {
    pub fn new(nonce: u32, payload: Vec<u8>, key: &SigningKey) -> Self {
        let mut cmd = Self {
            nonce,
            signature: [0u8; 64],
            payload,
        };
        cmd.sign(key);
        cmd
    }

    pub fn sign(&mut self, key: &SigningKey) {
        let sig = key.sign(&self.payload);
        self.signature = sig.to_bytes();
    }
}

impl P2PMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(P2P_MAGIC).unwrap();
        
        match self {
            P2PMessage::Command(cmd) => {
                buf.write_u8(P2P_TYPE_CMD).unwrap();
                buf.write_u32::<BigEndian>(cmd.nonce).unwrap();
                buf.write_all(&cmd.signature).unwrap();
                buf.write_u16::<BigEndian>(cmd.payload.len() as u16).unwrap();
                buf.write_all(&cmd.payload).unwrap();
            }
            P2PMessage::Gossip(data) => {
                buf.write_u8(P2P_TYPE_GOSSIP).unwrap();
                buf.extend_from_slice(data);
            }
        }
        buf
    }
}

