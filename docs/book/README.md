# DSM Developer Handbook

Comprehensive guide to developing with the Deterministic State Machine protocol.

## Table of Contents

### Getting Started

1. [Introduction](01-introduction.md) -- What is DSM, design philosophy, who this is for
2. [Quickstart](02-quickstart.md) -- Zero to running in under 30 minutes
3. [Development Setup](03-development-setup.md) -- Full dev environment for all platforms

### Architecture and Protocol

4. [Architecture](04-architecture.md) -- System design, layer boundaries, data flow
5. [Protocol Reference](05-protocol-reference.md) -- Wire format, bridge protocol, JNI interface
6. [Cryptographic Architecture](06-cryptographic-architecture.md) -- Post-quantum crypto stack

### Running and Testing

7. [Storage Nodes](07-storage-nodes.md) -- Local multi-node setup, API, cloud deployment
8. [Bitcoin and dBTC](08-bitcoin-dbtc.md) -- Signet setup, HTLC workflows, integration tests
9. [BLE Testing](09-ble-testing.md) -- Bluetooth pairing and bilateral transfers
10. [Testing and CI](10-testing-and-ci.md) -- Test suites, CI pipeline, E2E tools

### Building on DSM

11. [Integration Guide](11-integration-guide.md) -- Custom wallets and apps

### Reference

12. [Command Reference](12-command-reference.md) -- Every make target, npm script, and shell script
13. [Troubleshooting](13-troubleshooting.md) -- Common issues across all layers
14. [Contributing](14-contributing.md) -- How to contribute
15. [Security Model](15-security-model.md) -- Threat model and security guarantees
16. [Code Generation](16-code-generation.md) -- `dsm-gen` for typed DLV and policy clients
17. [DSM Primitive](17-dsm-primitive.md) -- Defines the primitive boundary, trust surface, and composition model
18. [In-App Developer Walkthroughs](18-in-app-developer-walkthroughs.md) -- Hidden dev menu, C-DBRW monitor, DLV tools, token creation, and BLE app flows

### Appendices

- [Glossary](appendix-a-glossary.md) -- Terminology reference
- [Hard Invariants](appendix-b-hard-invariants.md) -- The 12 inviolable rules
- [Spec Index](appendix-c-spec-index.md) -- Index into protocol specifications

## Quick Links

- [Changelog](../../CHANGELOG.md)
- [Code Generation (`dsm-gen`)](16-code-generation.md)
- [DSM Primitive Paper](../papers/dsm_primitive.pdf)
- [Protocol Reference](05-protocol-reference.md)
- [Proto Schema](../../proto/dsm_app.proto)
- [Hard Invariants](appendix-b-hard-invariants.md)

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT License](../../LICENSE-MIT) at your option.
