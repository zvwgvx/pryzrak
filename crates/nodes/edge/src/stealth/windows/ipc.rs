//! IPC Module for Debug Logging (Named Pipes)
//! 
//! Allows the Daemon to stay hidden while a second "Viewer" process connects to receive logs.
//! Uses native Windows APIs.

#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use std::thread;
#[cfg(target_os = "windows")]
use std::time::Duration;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use std::ffi::CString;

// Constants
#[cfg(target_os = "windows")]
const PIPE_NAME: &str = "\\\\.\\pipe\\pryzrak_log";
#[cfg(target_os = "windows")]
const BUFFER_SIZE: u32 = 4096;

// WinAPI Constants
#[cfg(target_os = "windows")]
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
#[cfg(target_os = "windows")]
const PIPE_TYPE_MESSAGE: u32 = 0x00000004;
#[cfg(target_os = "windows")]
const PIPE_READMODE_MESSAGE: u32 = 0x00000002;
#[cfg(target_os = "windows")]
const PIPE_WAIT: u32 = 0x00000000;
#[cfg(target_os = "windows")]
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
#[cfg(target_os = "windows")]
const GENERIC_READ: u32 = 0x80000000;
#[cfg(target_os = "windows")]
const GENERIC_WRITE: u32 = 0x40000000;
#[cfg(target_os = "windows")]
const OPEN_EXISTING: u32 = 3;
#[cfg(target_os = "windows")]
const INVALID_HANDLE_VALUE: isize = -1;

// Type Defs
#[cfg(target_os = "windows")]
type Handle = isize;

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn CreateNamedPipeA(
        lpName: *const u8,
        dwOpenMode: u32,
        dwPipeMode: u32,
        nMaxInstances: u32,
        nOutBufferSize: u32,
        nInBufferSize: u32,
        nDefaultTimeOut: u32,
        lpSecurityAttributes: *const u8
    ) -> Handle;

    fn ConnectNamedPipe(hNamedPipe: Handle, lpOverlapped: *const u8) -> i32;
    fn DisconnectNamedPipe(hNamedPipe: Handle) -> i32;
    
    #[link_name = "WriteFile"]
    fn WinWriteFile(
        hFile: Handle,
        lpBuffer: *const u8,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *const u8
    ) -> i32;
    
    fn CloseHandle(hObject: Handle) -> i32;
    fn GetLastError() -> u32;
}

/// Try to connect as a Viewer. Returns true if successful.
/// Used by the 'log_viewer' tool essentially, but logic kept here for reference or dual-mode.
#[cfg(target_os = "windows")]
pub fn try_connect_viewer() -> bool {
    let path = r"\\.\pipe\pryzrak_log";
    // Try to open pipe
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(false) // Viewer only reads
        .open(path);

    if let Ok(mut f) = file {
        println!("[Viewer] Connected to Pryzrak Daemon. Streaming logs...");
        println!("[Viewer] Press Ctrl+C to detach (Daemon will continue).");
        println!("-------------------------------------------------------");
        
        use std::io::Read;
        let mut buffer = [0u8; 4096];
        loop {
            match f.read(&mut buffer) {
                Ok(0) => {
                     println!("[Viewer] Disconnected (Daemon closed).");
                     break;
                }
                Ok(n) => {
                     let msg = String::from_utf8_lossy(&buffer[..n]);
                     print!("{}", msg);
                }
                Err(_) => {
                     println!("[Viewer] Read Error (Disconnect).");
                     break;
                }
            }
        }
        return true;
    }
    false
}

#[cfg(target_os = "windows")]
pub fn is_pipe_active() -> bool {
    let path = r"\\.\pipe\pryzrak_log";
    // Try to open pipe just to check existence
    std::fs::OpenOptions::new().read(true).write(false).open(path).is_ok()
}

#[cfg(not(target_os = "windows"))]
pub fn is_pipe_active() -> bool { false }

// Global Server State
#[cfg(target_os = "windows")]
static SERVER_HANDLE: Mutex<Handle> = Mutex::new(INVALID_HANDLE_VALUE);
#[cfg(target_os = "windows")]
static HAS_CLIENT: AtomicBool = AtomicBool::new(false);

// Log History Buffer
#[cfg(target_os = "windows")]
static LOG_HISTORY: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Start the Daemon Pipe Server (Background Thread)
#[cfg(target_os = "windows")]
pub fn start_daemon_server() {
    thread::spawn(move || {
        unsafe {
            let name = CString::new(PIPE_NAME).unwrap();
            loop {
                // 1. Create Pipe
                let handle = CreateNamedPipeA(
                    name.as_ptr() as *const u8,
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    BUFFER_SIZE,
                    BUFFER_SIZE,
                    0,
                    ptr::null() as *const u8
                );

                if handle == INVALID_HANDLE_VALUE {
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }

                // 2. Publish Handle for Logger
                *SERVER_HANDLE.lock().unwrap() = handle;

                // 3. Wait for Client
                ConnectNamedPipe(handle, ptr::null() as *const u8);
                HAS_CLIENT.store(true, Ordering::SeqCst);

                // Send Welcome Message
                let welcome = "[Daemon] Connection Accepted. Replaying Log History:\n------------------------------------------------\n";
                let mut written = 0;
                WinWriteFile(handle, welcome.as_ptr(), welcome.len() as u32, &mut written, ptr::null() as *const u8);

                // Replay History
                {
                    let history = LOG_HISTORY.lock().unwrap();
                    for log in history.iter() {
                        let line = format!("{}\n", log);
                         WinWriteFile(handle, line.as_ptr(), line.len() as u32, &mut written, ptr::null() as *const u8);
                    }
                }
                let end_history = "------------------------------------------------\n[Daemon] Live Stream Active:\n";
                WinWriteFile(handle, end_history.as_ptr(), end_history.len() as u32, &mut written, ptr::null() as *const u8);

                // 4. Client Connected. Wait for Disconnect.
                // We check HAS_CLIENT flag which is cleared on write error.
                while HAS_CLIENT.load(Ordering::Relaxed) {
                     std::thread::sleep(Duration::from_millis(500));
                }

                // 5. Cleanup & Loop
                DisconnectNamedPipe(handle);
                CloseHandle(handle);
                *SERVER_HANDLE.lock().unwrap() = INVALID_HANDLE_VALUE;
            }
        }
    });

    // Set the debug sink
    crate::k::debug::set_log_sink(Box::new(|msg| {
        push_log_to_pipe(msg);
    }));
}

#[cfg(not(target_os = "windows"))]
pub fn start_daemon_server() {}

#[cfg(target_os = "windows")]
fn push_log_to_pipe(msg: &str) {
    // 1. Always store in History
    unsafe {
        if let Ok(mut history) = LOG_HISTORY.lock() {
            if history.len() >= 100 {
                history.remove(0); // Maintain circular buffer of 100 lines
            }
            history.push(msg.to_string());
        }
    }

    // 2. If client connected, push to pipe
    if !HAS_CLIENT.load(Ordering::Relaxed) { return; }
    
    unsafe {
        // Need to lock to get current handle
        let guard = SERVER_HANDLE.lock().unwrap();
        let handle = *guard;
        if handle == INVALID_HANDLE_VALUE { return; }
        // Drop lock implies we hold it for write. Fine.
        
        let mut full_msg = msg.to_string();
        full_msg.push('\n');
        
        let mut bytes_written = 0;
        let status = WinWriteFile(
            handle,
            full_msg.as_ptr(),
            full_msg.len() as u32,
            &mut bytes_written,
            ptr::null() as *const u8
        );
        
        if status == 0 {
            // Write failed. Client likely gone.
            HAS_CLIENT.store(false, Ordering::Relaxed);
        }
    }
}
#[cfg(not(target_os = "windows"))]
fn push_log_to_pipe(_: &str) {}
