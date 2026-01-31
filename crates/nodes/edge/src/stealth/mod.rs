//! # Stealth Module
//!
//! Platform-specific stealth and evasion capabilities.

// Windows Stealth Module
#[cfg(target_os = "windows")]
pub mod windows;

// Linux Stealth Module
#[cfg(target_os = "linux")]
pub mod linux;

/// Check and apply stealth measures based on platform
pub fn check_and_apply_stealth() {
    #[cfg(target_os = "windows")]
    windows::check_and_apply_stealth();
    
    #[cfg(target_os = "linux")]
    linux::check_and_apply_stealth();
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    log::debug!("[Stealth] No stealth module available for this platform");
}
