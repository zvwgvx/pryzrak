fn main() {
    let seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let week_slot = seconds / 604800;
    
    let seed: u64 = 0x36A5EC9D09C60386;
    let mut state = week_slot ^ seed;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    
    let hash = format!("pryzrak-{:x}", state & 0xFFFF);
    println!("Current Time: {}", seconds);
    println!("Week Slot: {}", week_slot);
    println!("Expected Hash: {}", hash);
}
