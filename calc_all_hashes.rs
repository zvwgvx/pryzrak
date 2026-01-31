fn djb2(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for c in s.bytes() {
        hash = ((hash << 5).wrapping_add(hash)) ^ (c as u32);
    }
    hash
}

fn main() {
    // All needed functions
    let funcs = [
        "VirtualAlloc", "VirtualProtect", "VirtualFree", 
        "CreateFileW", "WriteFile", "ReadFile", "CloseHandle",
        "GetModuleHandleA", "GetModuleFileNameA", "GetProcAddress", "LoadLibraryA",
        "CreateProcessA", "SetFileAttributesW", "CreateDirectoryW",
        "RegCreateKeyExW", "RegSetValueExW", "RegCloseKey", "RegOpenKeyExW", "RegQueryValueExW",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", 
        "NtCreateFile", "NtClose",
    ];
    
    println!("// Kernel32 Functions");
    for f in &funcs[..14] {
        println!("pub const HASH_{}: u32 = 0x{:08X};", 
            f.chars().flat_map(|c| {
                if c.is_uppercase() { vec!['_', c] } else { vec![c.to_ascii_uppercase()] }
            }).skip(1).collect::<String>(),
            djb2(f));
    }
    
    println!("\n// Registry Functions (advapi32)");
    for f in &funcs[14..19] {
        println!("pub const HASH_{}: u32 = 0x{:08X};", 
            f.chars().flat_map(|c| {
                if c.is_uppercase() { vec!['_', c] } else { vec![c.to_ascii_uppercase()] }
            }).skip(1).collect::<String>(),
            djb2(f));
    }
    
    println!("\n// Ntdll Functions");
    for f in &funcs[19..] {
        println!("pub const HASH_{}: u32 = 0x{:08X};", 
            f.chars().flat_map(|c| {
                if c.is_uppercase() { vec!['_', c] } else { vec![c.to_ascii_uppercase()] }
            }).skip(1).collect::<String>(),
            djb2(f));
    }
}
