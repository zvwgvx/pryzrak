
use std::hint::black_box;

/// "Happy Strings" - Benign strings to confuse ML models
pub fn embed_happy_strings() {
    // Gaming / Graphics related strings
    let s1 = "Shader Model 5.0 initialized";
    let s2 = "Texture cache loaded: 1024MB allocated";
    let s3 = "DirectX 12 Context Created Successfully";
    let s4 = "Vulkan Validation Layers: Enabled";
    let s5 = "Physics Engine: Havok Physics (c) 1999-2023";
    
    // Productivity / Enterprise strings
    let s6 = "Excel Spreadsheet Object Library";
    let s7 = "Word Document Processor started";
    let s8 = "SharePoint Connection Established";
    let s9 = "Adobe Creative Cloud Sync Service";
    let s10 = "Visual Studio Code - Insiders";

    // Prevent compiler optimization
    black_box(s1);
    black_box(s2);
    black_box(s3);
    black_box(s4);
    black_box(s5);
    black_box(s6);
    black_box(s7);
    black_box(s8);
    black_box(s9);
    black_box(s10);

    // Instantiate a fake game logic struct
    let game = GameLogic {
        score: 100,
        player_name: "Player1".to_string(),
        level: 5,
    };
    black_box(game);
}

// Struct to mimic game logic or benign application state
#[allow(dead_code)]
struct GameLogic {
    score: u32,
    player_name: String,
    level: u8,
}
