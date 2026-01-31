use plugin_api::HostContext;
use log::info;

/// Ransomware Plugin Implementation
pub struct RansomPlugin {
    key: [u8; 32],
}

impl RansomPlugin {
    pub fn new() -> Self {
        Self { key: [0u8; 32] }
    }

    pub fn opcode(&self) -> u8 {
        0x06
    }

    pub fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), String> {
        info!("plugin(ransom): target {} bytes", cmd.len());
        Ok(())
    }
}

plugin_api::declare_plugin!(RansomPlugin, "Ransomware Plugin v2");
