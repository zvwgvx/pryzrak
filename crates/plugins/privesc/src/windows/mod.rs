use log::info;

pub fn execute(_cmd: &[u8]) -> Result<(), String> {
    info!("[PrivEsc:Win] Windows escalation not yet implemented");
    // Future: Juicy Potato, PrintNightmare, etc.
    Err("Not implemented".into())
}
