use log::{info, warn, debug};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

#[cfg(target_os = "linux")]
pub struct RpathHijacker;

#[cfg(target_os = "linux")]
impl RpathHijacker {
    pub fn inject_origin(target_path: &str) -> Result<(), String> {
        let mut buffer = Vec::new();
        File::open(target_path)
            .map_err(|e| e.to_string())?
            .read_to_end(&mut buffer)
            .map_err(|e| e.to_string())?;

        // Parse ELF and extract needed info (borrow ends after this block)
        let (already_patched, try_patchelf, patchelf_rpath) = {
            let elf = goblin::elf::Elf::parse(&buffer)
                .map_err(|e| format!("parse: {}", e))?;

            let already = elf.rpaths.iter().chain(elf.runpaths.iter())
                .any(|rpath| rpath.contains("$ORIGIN"));
            
            let existing = elf.rpaths.first().map(|s| s.to_string()).unwrap_or_default();
            let new_rpath = if existing.is_empty() { "$ORIGIN".to_string() } 
                else { format!("$ORIGIN:{}", existing) };
            
            (already, true, new_rpath)
        };

        if already_patched {
            info!("[Hijack] already patched");
            return Ok(());
        }

        if try_patchelf && std::process::Command::new("patchelf").arg("--version").output().is_ok() {
            let out = std::process::Command::new("patchelf")
                .args(["--set-rpath", &patchelf_rpath, target_path])
                .output().map_err(|e| e.to_string())?;
                
            if out.status.success() {
                info!("[Hijack] patchelf ok: {}", patchelf_rpath);
                return Ok(());
            }
            warn!("[Hijack] patchelf failed, trying native");
        }

        // Reparse for native patch (now we can mutate buffer after)
        Self::native_patch_standalone(&mut buffer)?;
        
        OpenOptions::new().write(true).truncate(true).open(target_path)
            .map_err(|e| e.to_string())?
            .write_all(&buffer).map_err(|e| e.to_string())?;
        
        info!("[Hijack] native patch ok");
        Ok(())
    }

    fn native_patch_standalone(buffer: &mut Vec<u8>) -> Result<(), String> {
        const DT_RPATH: u64 = 15;
        const DT_RUNPATH: u64 = 29;
        
        // Parse ELF from buffer
        let elf = goblin::elf::Elf::parse(buffer)
            .map_err(|e| format!("parse: {}", e))?;
        
        let dynstr_offset = elf.dynamic.as_ref()
            .map(|d| d.info.strtab)
            .filter(|&s| s > 0)
            .ok_or("no dynstr")?;
        
        let mut rpath_offset: Option<usize> = None;
        if let Some(dyn_sec) = &elf.dynamic {
            for entry in &dyn_sec.dyns {
                if entry.d_tag == DT_RPATH || entry.d_tag == DT_RUNPATH {
                    rpath_offset = Some(entry.d_val as usize);
                    break;
                }
            }
        }
        
        let strtab_off = rpath_offset.ok_or("no existing rpath")?;
        let file_off = dynstr_offset + strtab_off;
        
        // Drop ELF borrow here - we only need the offsets now
        drop(elf);
        
        if file_off >= buffer.len() { return Err("offset oob".into()); }
        
        let mut end = file_off;
        while end < buffer.len() && buffer[end] != 0 { end += 1; }
        let existing_len = end - file_off;
        
        debug!("[Hijack] rpath len: {}", existing_len);
        
        if existing_len < 7 {
            return Err("rpath too short".into());
        }
        
        buffer[file_off..file_off+7].copy_from_slice(b"$ORIGIN");
        buffer[file_off+7] = 0;
        for i in 8..existing_len { buffer[file_off+i] = 0; }
        
        Ok(())
    }
}
