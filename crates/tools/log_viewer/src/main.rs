use std::io::{self, Read};
use std::thread;
use std::time::Duration;

const PIPE_NAME: &str = r"\\.\pipe\pryzrak_log";

fn main() {
    println!("========================================");
    println!("   PRYZRAK LOG VIEWER v1.0.1.1         ");
    println!("========================================");
    println!("[*] Waiting for Pryzrak Edge Daemon...");

    // Retry loop
    loop {
        match try_connect() {
            Ok(_) => {
                println!("\n[!] Disconnected from Daemon. Reconnecting in 2s...");
            }
            Err(_) => {
                // Connection failed (pipe not found usually)
                // Just wait and retry
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn try_connect() -> io::Result<()> {
    // Try to open the named pipe
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(PIPE_NAME);

    match file {
        Ok(mut f) => {
            println!("[+] Connected! Stream active below:\n");
            
            let mut buffer = [0u8; 4096];
            loop {
                match f.read(&mut buffer) {
                    Ok(0) => return Ok(()), // EOF
                    Ok(n) => {
                        let s = String::from_utf8_lossy(&buffer[..n]);
                        print!("{}", s);
                    },
                    Err(e) => return Err(e),
                }
            }
        }
        Err(_) => {
            // print!("."); 
            // use std::io::Write;
            // io::stdout().flush().ok();
            Err(io::Error::new(io::ErrorKind::NotFound, "Pipe not found"))
        }
    }
}
