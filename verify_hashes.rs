fn djb2(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for c in s.bytes() {
        hash = ((hash << 5).wrapping_add(hash)) ^ (c as u32);
    }
    hash
}

fn djb2_lower(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for c in s.bytes() {
        let c_lower = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
        hash = ((hash << 5).wrapping_add(hash)) ^ (c_lower as u32);
    }
    hash
}

fn main() {
    println!("HASH_KERNEL32: 0x{:X}", djb2_lower("kernel32.dll"));
    println!("HASH_NTDLL: 0x{:X}", djb2_lower("ntdll.dll"));
    println!("HASH_ADVAPI32: 0x{:X}", djb2_lower("advapi32.dll"));
    
    println!("HASH_VIRTUAL_ALLOC: 0x{:X}", djb2("VirtualAlloc"));
    println!("HASH_VIRTUAL_PROTECT: 0x{:X}", djb2("VirtualProtect"));
    println!("HASH_CREATE_FILE_W: 0x{:X}", djb2("CreateFileW"));
    println!("HASH_WRITE_FILE: 0x{:X}", djb2("WriteFile"));
    println!("HASH_CREATE_DIRECTORY_W: 0x{:X}", djb2("CreateDirectoryW"));
    println!("HASH_SET_FILE_ATTRIBUTES_W: 0x{:X}", djb2("SetFileAttributesW"));
    
    println!("HASH_REG_CREATE_KEY_EX_W: 0x{:X}", djb2("RegCreateKeyExW"));
    println!("HASH_REG_SET_VALUE_EX_W: 0x{:X}", djb2("RegSetValueExW"));
    println!("HASH_REG_CLOSE_KEY: 0x{:X}", djb2("RegCloseKey"));
    println!("HASH_REG_OPEN_KEY_EX_W: 0x{:X}", djb2("RegOpenKeyExW"));
    println!("HASH_REG_QUERY_VALUE_EX_W: 0x{:X}", djb2("RegQueryValueExW"));
    
    println!("HASH_CREATE_PROCESS_A: 0x{:X}", djb2("CreateProcessA"));
    println!("HASH_GET_MODULE_FILE_NAME_A: 0x{:X}", djb2("GetModuleFileNameA"));
    println!("HASH_LOAD_LIBRARY_A: 0x{:X}", djb2("LoadLibraryA"));
    println!("HASH_GET_PROC_ADDRESS: 0x{:X}", djb2("GetProcAddress"));
    println!("HASH_CLOSE_HANDLE: 0x{:X}", djb2("CloseHandle"));
}
