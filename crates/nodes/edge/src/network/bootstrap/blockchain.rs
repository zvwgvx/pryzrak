use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Deserialize;
use log::{info, warn, debug};
use super::BootstrapProvider;

// --- CONFIGURATION ---
const RPC_ENDPOINTS: &[&str] = &[
    "https://rpc.sepolia.org",
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://1rpc.io/sepolia",
    "https://rpc2.sepolia.org"
];

const CONTRACT_ADDR: &str = "0x8A58Da9B24C24b9D6Faf2118eB3845FE7D4b13c5";
const EVENT_TOPIC_0: &str = "0xf5b2b2c9d749171f81d11324706509c313da5e730b72f44f535144b621404179";
const DGA_SEED: u64 = 0x36A5EC9D09C60386;

#[derive(Deserialize, Debug)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct LogEntry {
    topics: Vec<String>,
    data: String,
    #[serde(rename = "blockNumber")]
    block_number: String,
}

/// Blockchain Fallback Provider (Sepolia)
pub struct EthProvider;

impl EthProvider {
    fn get_daily_magic() -> String {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let day_slot = since_the_epoch.as_secs() / 86400;
        
        let mut state = day_slot ^ DGA_SEED;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        
        format!("0x{:064x}", state)
    }
    
    fn fetch_logs(url: &str, topic: &str) -> Result<Vec<LogEntry>, Box<dyn Error + Send + Sync>> {
        // Get current block number
        let block_req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 0
        });
        
        let block_resp: RpcResponse = ureq::post(url)
            .timeout(std::time::Duration::from_secs(15))
            .send_json(&block_req)?
            .into_json()?;
        
        let current_block = block_resp.result
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "0x0".to_string());
        
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
            .timeout(std::time::Duration::from_secs(15))
            .send_json(&payload)?
            .into_json()?;
        
        if let Some(err) = rpc_res.error {
            return Err(format!("RPC Error: {:?}", err).into());
        }
        
        if let Some(result) = rpc_res.result {
            let logs: Vec<LogEntry> = serde_json::from_value(result)?;
            return Ok(logs);
        }
        
        Ok(Vec::new())
    }
    
    fn parse_payload(hex_data: &str) -> Option<String> {
        let clean_hex = hex_data.trim_start_matches("0x");
        let bytes = hex::decode(clean_hex).ok()?;
        
        if bytes.len() < 64 { return None; }
        
        let length = u64::from_be_bytes(bytes[56..64].try_into().ok()?) as usize;
        if bytes.len() < 64 + length { return None; }
        
        let data = &bytes[64..64+length];
        String::from_utf8(data.to_vec()).ok()
    }
}

impl BootstrapProvider for EthProvider {
    fn fetch_payload(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        let magic_topic = Self::get_daily_magic();
        info!("[Blockchain] Querying Sepolia with magic: {}...", &magic_topic[0..18]);
        
        for endpoint in RPC_ENDPOINTS {
            debug!("[Blockchain] Trying RPC: {}", endpoint);
            match Self::fetch_logs(endpoint, &magic_topic) {
                Ok(logs) => {
                    if logs.is_empty() { 
                        debug!("[Blockchain] No logs at {}", endpoint);
                        continue; 
                    }
                    
                    info!("[Blockchain] Found {} logs at {}", logs.len(), endpoint);
                    
                    for log in logs.iter().rev() {
                        if let Some(payload) = Self::parse_payload(&log.data) {
                            if payload.contains(':') {
                                info!("[Blockchain] Successfully retrieved payload from block {}", log.block_number);
                                return Ok(payload);
                            }
                        }
                    }
                }
                Err(e) => warn!("[Blockchain] RPC {} failed: {}", endpoint, e),
            }
        }
        
        Err("No valid blockchain bootstrap data found".into())
    }

    fn name(&self) -> String {
        "Ethereum Sepolia (Tier 4 Fallback)".to_string()
    }
}
