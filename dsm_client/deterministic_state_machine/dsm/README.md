# DSM Core

The Rust core of the Deterministic State Machine: the device head and its one transition path,
relationships, the online economic root, SoFi, offline accounts, storage-cell recognition and the
cryptography they use. It does no I/O; the SDK (`../dsm_sdk`) reads and writes for it.

The protocol it implements is specified in [`specs/`](../../../specs/) at the repository root,
`DSM_High_Level_Explainer.md` first. Where to start in the code, and how the whole repository fits
together, is in the root [README](../../../README.md); building apps that plug into DSM is in
[BUILDING_APPS.md](../../../BUILDING_APPS.md) and [the guide](https://deterministicstatemachine.github.io/dsm/).

- [Operations.md](Operations.md): the operations a device head advances by.
- [CONTRIBUTING.md](CONTRIBUTING.md): working on this crate.

## License

Licensed under either of [Apache License, Version 2.0](../../../LICENSE-APACHE) or
[MIT License](../../../LICENSE-MIT) at your option.
