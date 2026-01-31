use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{BOOL, HMODULE, HWND, LPARAM, TRUE};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::Threading::{CreateThread, GetCurrentProcessId};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, SetWindowDisplayAffinity, IsWindowVisible, GetWindowDisplayAffinity
};
use windows_sys::Win32::System::Diagnostics::Debug::Beep;
use std::ffi::c_void;
use std::ptr;

// WDA_MONITOR = 0x01 (Black rectangle in capture)
// WDA_EXCLUDEFROMCAPTURE = 0x11 (Invisible in capture - Windows 10 2004+)
// Using 0x11 for transparent hiding on GUI apps like Edge
const WDA_EXCLUDEFROMCAPTURE: u32 = 0x00000011;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    hinst_dll: HMODULE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            unsafe { 
                DisableThreadLibraryCalls(hinst_dll);
                // Beep 1: Entry
                Beep(500, 100);
                CreateThread(
                    ptr::null(),
                    0,
                    Some(stealth_thread),
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                );
            }
        }
        _ => {}
    }
    TRUE
}

unsafe extern "system" fn stealth_thread(_param: *mut c_void) -> u32 {
    let current_pid = unsafe { GetCurrentProcessId() };
    loop {
        unsafe { EnumWindows(Some(enum_window_proc), current_pid as LPARAM); }
        thread::sleep(Duration::from_millis(1000));
    }
}

unsafe extern "system" fn enum_window_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let target_pid = lparam as u32;
    let mut window_pid = 0;
    unsafe { GetWindowThreadProcessId(hwnd, &mut window_pid); }

    if window_pid == target_pid && unsafe { IsWindowVisible(hwnd) != 0 } {
        let mut current_affinity: u32 = 0;
        let get_res = unsafe { GetWindowDisplayAffinity(hwnd, &mut current_affinity) };
        
        // Only Apply & Beep if NOT ALREADY SET
        if get_res != 0 && current_affinity != WDA_EXCLUDEFROMCAPTURE {
             let res = unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) };
             if res != 0 {
                 // Beep 3: Success (High) - NOW ONLY ONCE PER HIDE
                 unsafe { Beep(1000, 500); }
             }
        }
    }
    TRUE
}
