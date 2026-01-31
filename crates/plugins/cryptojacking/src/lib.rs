use plugin_api::HostContext;
use log::info;

/// Cryptojacking Plugin Implementation
pub struct CryptoPlugin {
    wallet: String,
}

impl CryptoPlugin {
    pub fn new() -> Self {
        Self { wallet: String::new() }
    }

    pub fn opcode(&self) -> u8 {
        0x05
    }

    pub fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), String> {
        let duration = if cmd.len() >= 2 {
            u16::from_be_bytes([cmd[0], cmd[1]]) as u64
        } else {
            60
        };
        
        info!("plugin(crypto): Starting CPU stress test for {}s", duration);
        
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut count = 0;
            // CPU Burner: Prime Number Search
            while start.elapsed().as_secs() < duration {
                let mut candidate = 2;
                'next_num: while start.elapsed().as_secs() < duration {
                     candidate += 1;
                     // Simple Primality Test
                     let f_can = candidate as f64;
                     let limit = f_can.sqrt() as u64;
                     for i in 2..=limit {
                         if candidate % i == 0 {
                             continue 'next_num;
                         }
                     }
                     count += 1;
                }
            }
            info!("plugin(crypto): Finished. Found {} primes.", count);
        });
        Ok(())
    }
}

plugin_api::declare_plugin!(CryptoPlugin, "Cryptojacking Plugin v2");
