use std::sync::Arc;
use std::net::UdpSocket;
use async_lock::Mutex;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use rand::Rng;
use log::info;

// Use async_io for wrapping std socket
use async_io::Async;

use crate::c::{p2p_magic, p2p_magic_prev};

/// Helper to check if magic is valid (current or previous slot)
fn is_valid_magic(magic: u32) -> bool {
    p2p_magic() == magic || p2p_magic_prev() == magic
}

const DISCOVERY_PORT: u16 = 31338;

// Helper function to get broadcast address as SocketAddr
fn broadcast_addr() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
enum MessageType {
    WhoIsLeader,
    IAmLeader,
    Election,
    Coordinator,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ElectionPacket {
    magic: u32,
    msg_type: MessageType,
    node_id: u64,
    rank: u64, // Static Startup Rank (Random + Time Component) to break ties
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeRole {
    Unbound,
    Leader,
    Worker(SocketAddr), // Carry Leader Address
}

pub struct ElectionService {
    node_id: u64,
    rank: u64,
    role: Arc<Mutex<NodeRole>>,
    socket: Arc<Async<UdpSocket>>,
}

use socket2::{Socket, Domain, Type, Protocol};
use std::net::SocketAddr;

impl ElectionService {
    pub async fn new() -> Self {
        // SECURITY FIX: Use full random range for rank to prevent prediction
        let mut rng = rand::thread_rng();
        let node_id = rng.gen::<u64>();
        
        // Add hardware component to rank for additional unpredictability
        let rank = {
            let hw_component = std::process::id() as u64;
            let time_component = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            rng.gen::<u64>() ^ (hw_component << 32) ^ time_component
        }; 
        
        // Use socket2 to set SO_REUSEPORT/ADDR
        let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => {
                log::error!("[Election] Failed to create socket: {}. Using fallback.", e);
                // Fallback: Create basic socket without advanced options
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                    .expect("Critical: Cannot create any UDP socket")
            }
        };
            
        let _ = socket.set_reuse_address(true);
        // set_reuse_port removed for compatibility (SO_REUSEADDR is sufficient)
        let _ = socket.set_broadcast(true);
        
        let addr: SocketAddr = format!("0.0.0.0:{}", DISCOVERY_PORT).parse()
            .unwrap_or_else(|_| "0.0.0.0:31338".parse().unwrap());
        
        if let Err(e) = socket.bind(&addr.into()) {
            log::warn!("[Election] Failed to bind UDP port {}: {}. Discovery may not work.", DISCOVERY_PORT, e);
        }
        let _ = socket.set_nonblocking(true);

        // Convert socket2::Socket to std::net::UdpSocket, then wrap with async_io::Async
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = match Async::new(std_socket) {
            Ok(s) => s,
            Err(e) => {
                log::error!("[Election] Failed to wrap socket: {}. Creating new.", e);
                Async::new(std::net::UdpSocket::bind("0.0.0.0:0").expect("Critical: Cannot bind")).expect("Failed to wrap")
            }
        };

        Self {
            node_id,
            rank,
            role: Arc::new(Mutex::new(NodeRole::Unbound)),
            socket: Arc::new(socket),
        }
    }

    pub async fn run_discovery(&self) -> NodeRole {
        info!("[Election] Starting Discovery... ID: {}", self.node_id);
        
        // 1. Send WHO_IS_LEADER
        let packet = ElectionPacket {
            magic: p2p_magic(),
            msg_type: MessageType::WhoIsLeader,
            node_id: self.node_id,
            rank: self.rank,
        };
        let bytes = match serde_json::to_vec(&packet) {
            Ok(b) => b,
            Err(e) => { log::error!("[Election] Serialize error: {}", e); return NodeRole::Unbound; }
        };
        
        // Broadcast multiple times for reliability
        for _ in 0..3 {
            let _ = self.socket.send_to(&bytes, broadcast_addr()).await;
            smol::Timer::after(Duration::from_millis(500)).await;
        }

        // 3. Listen for Response (3 seconds)
        let end_time = std::time::Instant::now() + Duration::from_secs(3);
        let mut buf = [0u8; 1024];

        while std::time::Instant::now() < end_time {
            // Try receive with short timeout via async-io Timer
            let recv_future = self.socket.recv_from(&mut buf);
            let timeout_future = smol::Timer::after(Duration::from_millis(100));
            
            // Use try_race - first one wins
            let result = futures_lite::future::or(
                async { Some(recv_future.await) },
                async { timeout_future.await; None }
            ).await;
            
            if let Some(Ok((len, addr))) = result {
                if let Ok(resp) = serde_json::from_slice::<ElectionPacket>(&buf[..len]) {
                    if is_valid_magic(resp.magic) {
                        match resp.msg_type {
                            MessageType::IAmLeader => {
                                // BULLY LOGIC: Only accept Leader if they are Stronger
                                if (resp.rank, resp.node_id) > (self.rank, self.node_id) {
                                    info!("[Election] Found Stronger Leader: {} (Rank {}) @ {}", resp.node_id, resp.rank, addr);
                                    let mut r = self.role.lock().await;
                                    *r = NodeRole::Worker(addr);
                                    return NodeRole::Worker(addr);
                                } else {
                                    info!("[Election] Ignoring Weaker Leader: {} (Rank {})", resp.node_id, resp.rank);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // 4. Timeout -> Become Leader (Simplified Bully: Just claim it if no one answers)
        // Real Bully would trigger an Election process, but spec says "Scenario B: Timeout -> Become Leader"
        info!("[Election] No Stronger Leader found. Promoting self to LEADER.");
        
        let mut r = self.role.lock().await;
        *r = NodeRole::Leader;
        
        // Announce Leadership
        let win_packet = ElectionPacket {
            magic: p2p_magic(),
            msg_type: MessageType::IAmLeader,
            node_id: self.node_id,
            rank: self.rank,
        };
        let bytes = match serde_json::to_vec(&win_packet) {
            Ok(b) => b,
            Err(_) => return NodeRole::Leader,
        };
        let _ = self.socket.send_to(&bytes, broadcast_addr()).await;

        NodeRole::Leader
    }

    /// Background task to respond to WHO_IS_LEADER and maintain dominance
    pub async fn monitor_requests(&self) {
        let node_id = self.node_id;
        let rank = self.rank;
        let socket = self.socket.clone();

        // 1. Periodic Dominance Heartbeat
        let socket_hb = socket.clone();
        smol::spawn(async move {
            loop {
                let packet = ElectionPacket {
                    magic: p2p_magic(),
                    msg_type: MessageType::IAmLeader,
                    node_id,
                    rank,
                };
                if let Ok(bytes) = serde_json::to_vec(&packet) {
                    let _ = socket_hb.send_to(&bytes, broadcast_addr()).await;
                }
            smol::Timer::after(Duration::from_secs(5)).await;
            }
        }).detach();

        // 2. Respond to Challenges
        let mut buf = [0u8; 1024];
        loop {
            if let Ok((len, addr)) = self.socket.recv_from(&mut buf).await {
                if let Ok(pkt) = serde_json::from_slice::<ElectionPacket>(&buf[..len]) {
                    if is_valid_magic(pkt.magic) {
                        // If we are Leader, respond
                        let role = self.role.lock().await;
                        if *role == NodeRole::Leader && pkt.msg_type == MessageType::WhoIsLeader {
                            info!("[Election] Received request from {}. Responding I_AM_LEADER.", pkt.node_id);
                            let resp = ElectionPacket {
                                magic: p2p_magic(),
                                msg_type: MessageType::IAmLeader,
                                node_id: self.node_id,
                                rank: self.rank,
                            };
                            if let Ok(bytes) = serde_json::to_vec(&resp) {
                                let _ = self.socket.send_to(&bytes, addr).await;
                            }
                        }
                        
                        // Conflict Resolution (Higher Rank + NodeID Wins)
                        if *role == NodeRole::Leader && pkt.msg_type == MessageType::IAmLeader {
                            if pkt.node_id != self.node_id {
                                // Tie-breaker using NodeID to prevent Split Brain on equal Rank
                                if (pkt.rank, pkt.node_id) > (self.rank, self.node_id) {
                                    info!("[Election] Stronger leader detected ({} Rank {}), stepping down.", pkt.node_id, pkt.rank);
                                    // FORCE RESTART: Exit process so watchdog/systemd restarts us.
                                    // On restart, we will find the existing Leader and become a Worker.
                                    std::process::exit(1); 
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
