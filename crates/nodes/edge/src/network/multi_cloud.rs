//! Multi-Cloud Connection Manager
//!
//! Manages connections to multiple Cloud nodes simultaneously for redundancy.
//! Commands are deduplicated by nonce to prevent duplicate execution.
//! Using smol/async-channel for lightweight async.

use std::sync::Arc;
use std::num::NonZeroUsize;
use async_channel::{Sender, Receiver};
use async_lock::Mutex;
use log::{info, warn, debug};
use lru::LruCache;

use crate::n::client::PolyMqttClient;

/// Maximum number of Cloud connections to maintain
pub const MAX_CLOUD_CONNECTIONS: usize = 6;

/// Size of nonce deduplication cache
const NONCE_CACHE_SIZE: usize = 256;

/// Manager for multiple Cloud connections
pub struct MultiCloudManager {
    clients: Vec<Arc<PolyMqttClient>>,
    seen_nonces: Arc<Mutex<LruCache<u32, ()>>>,
    master_key: [u8; 32],
}

impl MultiCloudManager {
    /// Create a new MultiCloudManager with up to MAX_CLOUD_CONNECTIONS nodes
    pub fn new(nodes: Vec<(String, u16)>, key: &[u8; 32]) -> Self {
        let selected: Vec<_> = nodes.into_iter().take(MAX_CLOUD_CONNECTIONS).collect();
        
        let clients: Vec<Arc<PolyMqttClient>> = selected
            .iter()
            .map(|(ip, port)| {
                info!("[MultiCloud] Adding Cloud: {}:{}", ip, port);
                Arc::new(PolyMqttClient::new(ip, *port, key))
            })
            .collect();
        
        info!("[MultiCloud] Initialized with {} Cloud connections", clients.len());
        
        Self {
            clients,
            seen_nonces: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(NONCE_CACHE_SIZE).unwrap()
            ))),
            master_key: *key,
        }
    }

    /// Start persistent loops for all Cloud connections
    /// Commands from any Cloud are sent to cmd_tx after deduplication
    pub async fn start_all(
        &self,
        cmd_tx: Sender<Vec<u8>>,
        msg_rx: Receiver<Vec<u8>>,
    ) {
        if self.clients.is_empty() {
            warn!("[MultiCloud] No Cloud nodes configured!");
            return;
        }

        // Store senders to broadcast messages to all clients
        let mut client_senders = Vec::new();

        // Spawn connection task for each Cloud node
        for (idx, client) in self.clients.iter().enumerate() {
            let client = client.clone();
            let cmd_tx = cmd_tx.clone();
            let seen_nonces = self.seen_nonces.clone();
            
            // Create internal channels for this client
            let (internal_msg_tx, internal_msg_rx) = async_channel::bounded::<Vec<u8>>(100);
            client_senders.push(internal_msg_tx);

            // Spawn client loop
            smol::spawn(async move {
                Self::run_client_loop(idx, client, cmd_tx, seen_nonces, internal_msg_rx).await;
            }).detach();
        }

        // Spawn Distributor Task (Fan-out)
        // Reads from main msg_rx and broadcasts to ALL clients for redundancy
        smol::spawn(async move {
            info!("[MultiCloud] Distributor started. Broadcasting to {} clients.", client_senders.len());
            while let Ok(msg) = msg_rx.recv().await {
                for (i, tx) in client_senders.iter().enumerate() {
                    // Try to send to each client. If full, drop (don't block everyone).
                    // Cloning the message for each client is necessary.
                    if let Err(_) = tx.try_send(msg.clone()) {
                        debug!("[MultiCloud] Client {} queue full/closed, dropping msg", i);
                    }
                }
            }
            warn!("[MultiCloud] Distributor stopped (input channel closed)");
        }).detach();
        
        info!("[MultiCloud] All {} Cloud connections started", self.clients.len());
    }

    /// Run persistent loop for a single Cloud client
    async fn run_client_loop(
        idx: usize,
        client: Arc<PolyMqttClient>,
        cmd_tx: Sender<Vec<u8>>,
        seen_nonces: Arc<Mutex<LruCache<u32, ()>>>,
        internal_msg_rx: Receiver<Vec<u8>>,
    ) {
        // Internal command channel handling
        let (internal_cmd_tx, internal_cmd_rx) = async_channel::bounded::<Vec<u8>>(100);
        
        // Start the client's persistent loop
        // It reads from internal_msg_rx and writes to internal_cmd_tx
        let client_for_loop = client.clone();
        smol::spawn(async move {
            client_for_loop.start_persistent_loop(internal_msg_rx, internal_cmd_tx).await;
        }).detach();
        
        // Process incoming commands with deduplication
        while let Ok(cmd) = internal_cmd_rx.recv().await {
            if cmd.len() < 5 {
                // Too short to contain nonce, forward anyway
                if cmd_tx.send(cmd).await.is_err() {
                    break;
                }
                continue;
            }
            
            // Extract nonce (bytes 1-4, after opcode)
            let nonce = u32::from_be_bytes([cmd[1], cmd[2], cmd[3], cmd[4]]);
            
            // Check deduplication
            {
                let mut cache = seen_nonces.lock().await;
                if cache.contains(&nonce) {
                    debug!("[MultiCloud][{}] Duplicate nonce 0x{:08X}, skipping", idx, nonce);
                    continue;
                }
                cache.put(nonce, ());
            }
            
            debug!("[MultiCloud][{}] New command nonce 0x{:08X}", idx, nonce);
            if cmd_tx.send(cmd).await.is_err() {
                break;
            }
        }
        
        warn!("[MultiCloud][{}] Client loop ended", idx);
    }

    /// Get number of configured Cloud nodes
    pub fn connection_count(&self) -> usize {
        self.clients.len()
    }
}
