//! # Native Library Loader (Zero String Artifacts)
//! 
//! Replacement for `libloading` crate using hash-based API resolution.
//! No "LoadLibraryExW failed", "GetProcAddress failed" strings.

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr;
use crate::s::windows::api_resolver::{self, djb2};

// Precomputed hashes
const HASH_KERNEL32: u32 = 0x3E003875;
const HASH_LOAD_LIBRARY_A: u32 = 0x01ED9ADD;
const HASH_GET_PROC_ADDRESS: u32 = 0xAADFAB0B;
const HASH_FREE_LIBRARY: u32 = 0x2146C2DE;

type LoadLibraryAFn = unsafe extern "system" fn(*const u8) -> *const c_void;
type GetProcAddressFn = unsafe extern "system" fn(*const c_void, *const u8) -> Option<*const c_void>;
type FreeLibraryFn = unsafe extern "system" fn(*const c_void) -> i32;

/// Native library handle with zero string artifacts
pub struct NativeLibrary {
    handle: *const c_void,
}

// SAFETY: Library handles are just opaque pointers, safe to send between threads
// once loaded. The underlying Windows handles are process-wide.
unsafe impl Send for NativeLibrary {}
unsafe impl Sync for NativeLibrary {}

impl NativeLibrary {
    /// Load a DLL by path (null-terminated)
    pub unsafe fn new(path: &[u8]) -> Result<Self, ()> {
        let load_lib: LoadLibraryAFn = api_resolver::resolve_api(
            HASH_KERNEL32, 
            HASH_LOAD_LIBRARY_A
        ).ok_or(())?;
        
        let handle = load_lib(path.as_ptr());
        if handle.is_null() {
            return Err(());
        }
        
        Ok(Self { handle })
    }
    
    /// Get a symbol by name (null-terminated)
    pub unsafe fn get<T>(&self, symbol: &[u8]) -> Result<T, ()> {
        let get_proc: GetProcAddressFn = api_resolver::resolve_api(
            HASH_KERNEL32, 
            HASH_GET_PROC_ADDRESS
        ).ok_or(())?;
        
        let addr = get_proc(self.handle, symbol.as_ptr()).ok_or(())?;
        Ok(std::mem::transmute_copy(&addr))
    }
    
    pub fn handle(&self) -> *const c_void {
        self.handle
    }
}

impl Drop for NativeLibrary {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                if let Some(free_lib) = api_resolver::resolve_api::<FreeLibraryFn>(
                    HASH_KERNEL32, 
                    HASH_FREE_LIBRARY
                ) {
                    free_lib(self.handle);
                }
            }
        }
    }
}
