use log::info;
#[cfg(target_os = "linux")]
use nix::mount::{mount, MsFlags};

#[cfg(target_os = "linux")]
pub struct BindMounter;

#[cfg(target_os = "linux")]
impl BindMounter {
    pub fn mask_path(source: &str, target: &str) -> Result<(), String> {
        mount(Some(source), target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .map_err(|e| format!("bind: {}", e))?;
        info!("[Mask] {} -> {}", source, target);
        Ok(())
    }
}
