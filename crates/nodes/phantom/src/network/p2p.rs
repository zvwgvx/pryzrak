use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use log::{info, error};
use ed25519_dalek::SigningKey;
use rand::Rng;

use protocol::wire::WireConstants;
use protocol::p2p::{P2PCommand, P2PMessage};
use crate::crypto::{p2p_magic, p2p_magic_prev};

const P2P_PORT: u16 = 31338;

#[derive(Clone)]
struct Peer {
    addr: SocketAddr,
    last_seen: Instant,
}

/// Count response from a Cloud node
#[derive(Debug, Clone)]
pub struct CountResponse {
    pub cloud_count: u32,
}

pub struct P2PService {
    socket: Arc<UdpSocket>,
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    master_key: Arc<SigningKey>,
    // Channel for count responses
    count_tx: mpsc::Sender<CountResponse>,
    count_rx: Arc<Mutex<mpsc::Receiver<CountResponse>>>,
}

impl P2PService {
    pub async fn new(master_key: Arc<SigningKey>) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", P2P_PORT)).await?;
        info!("[P2P] Listening on {}", P2P_PORT);
        
        let (count_tx, count_rx) = mpsc::channel(100);
        
        Ok(Self {
            socket: Arc::new(socket),
            peers: Arc::new(Mutex::new(HashMap::new())),
            master_key,
            count_tx,
            count_rx: Arc::new(Mutex::new(count_rx)),
        })
    }

    pub async fn add_peer(&self, addr: SocketAddr) {
        let mut peers = self.peers.lock().unwrap();
        peers.insert(addr, Peer { addr, last_seen: Instant::now() });
        info!("[P2P] Added Peer: {}", addr);
    }

    pub async fn start(self: Arc<Self>) {
        let socket = self.socket.clone();
        let me = self.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        me.handle_packet(&buf[..len], src).await;
                    }
                    Err(e) => error!("[P2P] Recv Error: {}", e),
                }
            }
        });

        let me_gossip = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                me_gossip.gossip().await;
            }
        });
    }

    async fn handle_packet(&self, buf: &[u8], src: SocketAddr) {
        if buf.len() < 5 { return; }
        // Magic Check (Big Endian)
        let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        // Accept current or previous time slot magic for tolerance
        let current = p2p_magic();
        let prev = p2p_magic_prev();
        if magic != current && magic != prev { return; }

        let type_ = buf[4];
        
        if type_ == WireConstants::P2P_TYPE_GOSSIP {
            // Update peer list logic
            self.add_peer(src).await;
        } else if type_ == WireConstants::P2P_TYPE_COUNT_RESP {
            // CountResponse: [Magic(4)][Type=4(1)][ReqID(4)][NodeCount(4)]
            if buf.len() >= 13 {
                let cloud_count = u32::from_be_bytes(buf[9..13].try_into().unwrap());
                let _ = self.count_tx.send(CountResponse { cloud_count }).await;
            }
        }
    }

    async fn gossip(&self) {
        let peers: Vec<SocketAddr> = {
            let map = self.peers.lock().unwrap();
            map.keys().cloned().collect()
        };

        if peers.is_empty() { return; }

        // Construct Basic Gossip Packet
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&p2p_magic().to_be_bytes()); // Magic
        pkt.push(WireConstants::P2P_TYPE_GOSSIP); // Type
        pkt.push(peers.len() as u8); // Count

        // Add peers...
        for peer in &peers {
             if let std::net::IpAddr::V4(ipv4) = peer.ip() {
                 pkt.extend_from_slice(&ipv4.octets());
                 pkt.extend_from_slice(&peer.port().to_be_bytes());
             }
        }

        // Send to random subsets
        let socket = self.socket.clone();
        for _ in 0..3 {
            if peers.is_empty() { break; }
            let target = peers[rand::thread_rng().gen_range(0..peers.len())];
            let _ = socket.send_to(&pkt, target).await;
        }
    }

    pub async fn broadcast_command(&self, cmd_payload: Vec<u8>) {
        // Create full P2P Command with Signature
        let nonce = rand::thread_rng().gen::<u32>();
        let cmd = P2PCommand::new(nonce, cmd_payload, &self.master_key);
        
        let packet_bytes = P2PMessage::Command(cmd).to_bytes();
        
        // Blast to all peers
        let peers: Vec<SocketAddr> = {
            let map = self.peers.lock().unwrap();
            map.keys().cloned().collect()
        };
        
        let socket = self.socket.clone();
        for peer in peers {
            let _ = socket.send_to(&packet_bytes, peer).await;
        }
        info!("[P2P] Broadcasted Command ({} bytes)", packet_bytes.len());
    }
    
    /// Get count of directly connected peers
    pub fn get_peer_count(&self) -> usize {
        let peers = self.peers.lock().unwrap();
        peers.len()
    }
    
    /// Send count request to mesh and collect responses
    /// Returns (cloud_nodes, total_edge_clients)
    pub async fn request_count(&self, timeout_secs: u64) -> (usize, u32) {
        let peers: Vec<SocketAddr> = {
            let map = self.peers.lock().unwrap();
            map.keys().cloned().collect()
        };
        
        if peers.is_empty() {
            return (0, 0);
        }
        
        let req_id: u32 = rand::thread_rng().gen();
        
        let local_addr = self.socket.local_addr().ok();
        let (origin_ip, origin_port) = match local_addr {
            Some(addr) => {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    (u32::from(ip), addr.port())
                } else {
                    (0x7F000001u32, P2P_PORT)
                }
            }
            None => (0x7F000001u32, P2P_PORT),
        };
        
        // [Magic(4)][Type=3(1)][ReqID(4)][TTL(1)][OriginIP(4)][OriginPort(2)]
        let mut pkt = Vec::with_capacity(16);
        pkt.extend_from_slice(&p2p_magic().to_be_bytes());
        pkt.push(WireConstants::P2P_TYPE_COUNT_REQ);
        pkt.extend_from_slice(&req_id.to_be_bytes());
        pkt.push(10); // TTL = 10 hops
        pkt.extend_from_slice(&origin_ip.to_be_bytes());
        pkt.extend_from_slice(&origin_port.to_be_bytes());
        
        // Send to all known peers
        let socket = self.socket.clone();
        for peer in &peers {
            let _ = socket.send_to(&pkt, peer).await;
        }
        info!("[P2P] Sent COUNT_REQUEST (id={:08x}) to {} peers", req_id, peers.len());
        
        let mut responses = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            
            let rx = self.count_rx.clone();
            let result = tokio::time::timeout(remaining, async {
                let mut guard = rx.lock().unwrap();
                guard.try_recv()
            }).await;
            
            match result {
                Ok(Ok(resp)) => {
                    responses.push(resp);
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        
        let cloud_count = responses.len();
        let edge_count: u32 = responses.iter().map(|r| r.cloud_count).sum();
        
        info!("[P2P] Count results: {} cloud nodes, {} edge clients", cloud_count, edge_count);
        (cloud_count, edge_count)
    }
}
