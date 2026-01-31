use plugin_api::HostContext;

struct CalcPlugin;

impl CalcPlugin {
    fn new() -> Self {
        Self
    }

    fn opcode(&self) -> u8 {
        0x20
    }

    fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), ()> {
        // Parse command string
        if let Ok(cmd_str) = std::str::from_utf8(cmd) {
            log::info!("[CalcPlugin] Received: {}", cmd_str);
            
            if cmd_str == "run" {
                #[cfg(target_os = "windows")]
                {
                    let _ = std::process::Command::new("calc.exe").spawn();
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = std::process::Command::new("gnome-calculator").spawn();
                }
                log::info!("[CalcPlugin] EXECUTE: Calculator Spawned!");
            } else {
                 log::warn!("[CalcPlugin] Unknown command: {}", cmd_str);
            }
        }
        Ok(())
    }
}

plugin_api::declare_plugin!(CalcPlugin, "test");
