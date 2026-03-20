---
name: arch-overview
description: Quick architectural overview of the DSM system — component map, data flow diagram, layer boundaries, key abstractions, and where to find anything. Use when onboarding or orienting before a task.
---

# DSM Architecture Overview

You provide instant architectural orientation for the DSM codebase. When invoked, you explain the system architecture, component relationships, data flows, and where to find things.

## System Architecture

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: FRONTEND (React 18 + TypeScript + Webpack)│
│  GameBoy-themed UI, custom router (no React Router) │
│  Contexts: Wallet, BLE, Contacts, UX               │
│  Proto types: dsm_app_pb.ts (generated)             │
│                                                     │
│  MessagePort: [8B msgId][BridgeRpcRequest proto]    │
├─────────────────────────────────────────────────────┤
│  Layer 2: ANDROID (Kotlin, API 24+, compileSdk 35)  │
│  MainActivity → SinglePathWebViewBridge             │
│  UnifiedNativeApi (87+ external JNI methods)        │
│  BleCoordinator (actor pattern, Channel-serialized) │
│                                                     │
│  JNI: extern "system" fn Java_com_dsm_wallet_*      │
├─────────────────────────────────────────────────────┤
│  Layer 3: SDK (Rust, cdylib + rlib)                 │
│  unified_protobuf_bridge.rs — main RPC dispatcher   │
│  bootstrap.rs — PBI (device_id + genesis + DBRW)    │
│  bilateral_ble_handler.rs — 3-phase BLE protocol    │
│  SDK_READY atomic flag gates all operations         │
│                                                     │
│  Pure function calls (no JNI boundary)              │
├─────────────────────────────────────────────────────┤
│  Layer 4: CORE (Pure Rust — no I/O, no time, no UI)│
│  State machine, bilateral, token, merkle/SMT        │
│  Crypto: BLAKE3, SPHINCS+, ML-KEM-768, Pedersen    │
│  Vaults: DLV, fulfillment, External Commitments    │
│  DJTE emissions, CPTA policies, dBTC bridge        │
│  Recovery: capsule, tombstone, rollup              │
└─────────────────────────────────────────────────────┘
         ↕ Storage nodes (index-only, signature-free)
```

## Key Directories

```
dsm/
├── .github/instructions/          # 14 authoritative specs
├── .Codex/
│   ├── skills/                    # 20 slash-command skills
│   ├── agents/                    # 6 specialized agents
│   └── hooks/                     # Invariant guard hook
├── proto/
│   └── dsm_app.proto              # Schema v2.4.0, wire v3
├── dsm_client/
│   ├── new_frontend/              # React 18 + TypeScript
│   │   ├── src/
│   │   │   ├── App.tsx            # Router + app state machine
│   │   │   ├── bridge/            # Bridge injection + registry
│   │   │   ├── dsm/               # WebViewBridge, EventBridge
│   │   │   ├── contexts/          # Wallet, BLE, Contacts, UX
│   │   │   ├── services/          # dsmClient, policy, storage
│   │   │   ├── hooks/             # useGenesisFlow, useAppBootstrap
│   │   │   └── proto/             # Generated dsm_app_pb.ts
│   │   └── AGENTS.md              # Frontend layer spec
│   ├── android/
│   │   ├── app/src/main/
│   │   │   ├── java/.../wallet/
│   │   │   │   ├── ui/            # MainActivity
│   │   │   │   └── bridge/        # WebView bridge, JNI, BLE
│   │   │   ├── jniLibs/           # .so files (3 ABIs)
│   │   │   └── assets/            # Webpack output + index.html
│   │   └── AGENTS.md              # Android layer spec
│   └── deterministic_state_machine/
│       ├── dsm/src/               # Core library (PURE)
│       │   ├── core/              # State machine, bilateral, token
│       │   ├── crypto/            # BLAKE3, SPHINCS+, Kyber, DBRW
│       │   ├── merkle/            # Sparse Merkle Tree
│       │   ├── vault/             # DLV, limbo vaults, fulfillment
│       │   ├── cpta/              # Token policy anchors
│       │   ├── emissions.rs       # DJTE
│       │   ├── bitcoin/           # dBTC bridge
│       │   ├── recovery/          # Capsule, tombstone, rollup
│       │   └── common/            # Domain tags, device tree
│       ├── dsm_sdk/src/           # SDK (JNI + BLE + I/O mediation)
│       │   ├── jni/               # JNI bridge functions
│       │   ├── sdk/               # High-level SDK APIs
│       │   ├── bluetooth/         # BLE handler, frame coordinator
│       │   └── security/          # DBRW validation
│       ├── dsm_storage_node/src/  # Storage node binary
│       └── AGENTS.md              # Rust layer spec
```

## App State Machine

```
loading → runtime_loading → needs_genesis → wallet_ready → locked → error
```

- `loading`: Initial load, waiting for bridge
- `runtime_loading`: Bridge connected, PBI bootstrap in progress
- `needs_genesis`: No genesis state, show creation flow
- `wallet_ready`: Full operational state
- `locked`: App locked (background/timeout)
- `error`: Unrecoverable error state

## PBI Bootstrap Sequence

1. `useAppBootstrap` → bridge `sdkBootstrap` call
2. Kotlin sends device_id (32 bytes) + genesis_hash + DBRW entropy to JNI
3. `bootstrap.rs`: Initialize PlatformContext in OnceLock
4. Derive SPHINCS+ keys from DBRW binding + genesis
5. Set `SDK_READY = true` → all operations unblocked

## Cryptographic Stack

| Primitive | Algorithm | Key Property |
|-----------|-----------|-------------|
| Hashing | BLAKE3-256 | Domain-separated, `"DSM/<name>\0"` |
| Signatures | SPHINCS+ (SPX256f) | Post-quantum, EUF-CMA |
| Key Exchange | ML-KEM-768 | Post-quantum encapsulation |
| Anti-Cloning | C-DBRW | Chaotic silicon attractor |
| Commitments | Pedersen | Hiding + binding |
| Encryption | ChaCha20-Poly1305 | At-rest storage |

## 12 Hard Invariants (Quick Reference)

1. Envelope v3 only (`0x03` framing)
2. No JSON (protobuf-only)
3. No hex in protocol (raw bytes, Base32 Crockford at boundaries)
4. No wall-clock time in protocol (logical ticks only)
5. No TODO/FIXME/HACK/XXX
6. No legacy code (fully remove old paths)
7. Single authoritative path
8. Core is pure (no I/O)
9. BLAKE3 domain separation
10. Tripwire fork-exclusion
11. Token conservation (B >= 0)
12. Storage nodes index-only

## Test Devices

| Role | Serial | Model |
|------|--------|-------|
| Sender | R5CW620MQVL | Galaxy A54 |
| Receiver | RF8Y90PX5GN | Galaxy A16 (flaky USB) |

## Available Skills

**Operational**: `/ndk-build`, `/ble-test`, `/cargo-check`, `/full-ci`, `/proto-regen`, `/storage-cluster`, `/verify-symbols`, `/device-status`

**Expert Knowledge**: `/spec-lookup`, `/bilateral-debug`, `/dbtc-guide`, `/dlv-guide`, `/crypto-guide`, `/cross-layer-trace`, `/emissions-guide`, `/storage-guide`, `/invariant-check`, `/wire-format`, `/mainnet-checklist`, `/arch-overview`

**Master Orchestrator**: `/dsm-auto` — autonomous skill routing with Ralph Loop-style looping
