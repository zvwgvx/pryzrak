use clap::Parser;
use ed25519_dalek::{SigningKey, Signer, SecretKey};
use base64::{Engine as _, engine::general_purpose};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "DNS TXT Signer")]
#[command(version = "1.0")]
#[command(about = "Generates Signed Payload for Pryzrak Mesh DNS Bootstrapping", long_about = None)]
struct Cli {
    /// Path to Master Private Key
    #[arg(long, default_value = "keys/master.key")]
    key: PathBuf,

    /// List of IP:PORT peers to include (comma or space separated)
    /// Example: "1.2.3.4:31337 5.6.7.8:80"
    #[arg(required = true)]
    peers: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    let key_bytes = fs::read(&cli.key).expect("Failed to read master key file");
    let secret: SecretKey = if key_bytes.len() == 32 {
        key_bytes.try_into().unwrap()
    } else if key_bytes.len() == 64 {
        key_bytes[0..32].try_into().unwrap()
    } else {
        panic!("Invalid key length");
    };
    let signing_key = SigningKey::from(secret);

    let mut msg = String::new();
    for peer in cli.peers {
        // Simple normalization: replace spaces with ; if user pasted a list
        let clean = peer.replace(',', ";").replace(' ', ";");
        msg.push_str(&clean);
        if !msg.ends_with(';') {
            msg.push(';');
        }
    }

    println!("[*] Message Content: {}", msg);

    let signature = signing_key.sign(msg.as_bytes());
    let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());
    let msg_b64 = general_purpose::STANDARD.encode(msg.as_bytes());

    let payload = format!("SIG:{}|MSG:{}", sig_b64, msg_b64);
    
    println!("\nGENERATED DNS TXT RECORD:");
    println!("---------------------------------------------------");
    println!("{}", payload);
    println!("---------------------------------------------------");
    println!("(Copy the string above to your 'dht.polydevs.uk' TXT record)");
}
