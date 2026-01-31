use smol::net::{TcpListener, TcpStream};
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use log::info;
use std::net::SocketAddr;

use crate::c::{lipc_magic, lipc_magic_prev};

// LIPC Protocol Constants
pub const HEADER_SIZE: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LipcMsgType {
    Hello = 0x01,
    Data = 0x02,
    Heartbeat = 0x03,
}

impl LipcMsgType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(LipcMsgType::Hello),
            0x02 => Some(LipcMsgType::Data),
            0x03 => Some(LipcMsgType::Heartbeat),
            _ => None,
        }
    }
}

pub struct LipcHeader {
    pub magic: u32,
    pub length: u32,
    pub worker_id: u64,
    pub msg_type: LipcMsgType,
}

pub struct LocalTransport;

impl LocalTransport {
    pub async fn bind_server() -> Result<TcpListener, Box<dyn Error + Send + Sync>> {
        // Bind to all interfaces for LAN access
        let addr = "0.0.0.0:31339"; 
        let listener = TcpListener::bind(addr).await?;
        info!("[LocalComm] Bound TCP Server at {}", addr);
        Ok(listener)
    }

    pub async fn connect_client(leader_addr: SocketAddr) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
        // Connect to Leader's IP on Port 31339
        let mut target = leader_addr;
        target.set_port(31339);
        
        let stream = TcpStream::connect(target).await?;
        info!("[LocalComm] Connected to Leader at {}", target);
        Ok(stream)
    }

    /// Reads a full LIPC frame from the stream
    pub async fn read_frame(stream: &mut TcpStream) -> Result<(LipcHeader, Vec<u8>), Box<dyn Error + Send + Sync>> {
        let mut head_buf = [0u8; HEADER_SIZE];
        stream.read_exact(&mut head_buf).await?;

        let magic = u32::from_be_bytes(head_buf[0..4].try_into()?);
        if magic != lipc_magic() && magic != lipc_magic_prev() {
            return Err("Invalid LIPC Magic".into());
        }

        let length = u32::from_be_bytes(head_buf[4..8].try_into()?);
        
        // SECURITY FIX: Prevent OOM DoS via malicious length
        const MAX_PAYLOAD_SIZE: u32 = 1024 * 1024; // 1MB max
        if length > MAX_PAYLOAD_SIZE {
            return Err(format!("LIPC payload too large: {} bytes (max {})", length, MAX_PAYLOAD_SIZE).into());
        }
        
        let worker_id = u64::from_be_bytes(head_buf[8..16].try_into()?);
        let msg_type = LipcMsgType::from_u8(head_buf[16]).ok_or("Invalid MsgType")?;

        let mut payload = vec![0u8; length as usize];
        if length > 0 {
            stream.read_exact(&mut payload).await?;
        }

        Ok((
            LipcHeader {
                magic,
                length,
                worker_id,
                msg_type,
            },
            payload,
        ))
    }

    /// Writes a full LIPC frame to the stream
    pub async fn write_frame(
        stream: &mut TcpStream,
        worker_id: u64,
        msg_type: LipcMsgType,
        payload: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
        
        buf.extend_from_slice(&lipc_magic().to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&worker_id.to_be_bytes());
        buf.push(msg_type as u8);
        buf.extend_from_slice(payload);

        stream.write_all(&buf).await?;
        Ok(())
    }
}
