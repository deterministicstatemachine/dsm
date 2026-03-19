# Contributing to DSM

Thank you for considering contributions to the DSM project! This document provides guidelines and workflows for contributing.

## Code of Conduct

Contributors are expected to adhere to the project's code of conduct. Please treat everyone with respect and collaborate constructively.

## Pull Request Process

1. **Fork the Repository**: Start by forking the repository and cloning it locally.

2. **Create a Feature Branch**: Always create a dedicated branch for your changes.
   ```
   git checkout -b feature/your-feature-name
   ```

3. **Follow Coding Standards**:
   - Use the project's code style (enforced by rustfmt)
   - Write tests for all new code
   - Document your code with proper comments
   - Ensure all existing tests pass
   - Use meaningful commit messages

4. **Avoid Circular Dependencies**: The codebase strictly prohibits circular dependencies. Ensure your changes maintain proper dependency direction.

5. **Memory Safety**: Be extra careful with any code that:
   - Uses `unsafe` blocks (document these with `// SAFETY:` comments)
   - Deals with raw pointers
   - Interacts with FFI
   - Manipulates shared state between threads

6. **Documentation**: Update relevant documentation to reflect your changes.

7. **Create a Pull Request**: When your changes are ready, submit a pull request with a clear description of:
   - What the change does
   - Why it's needed
   - How it was tested
   - Any potential risks

8. **Code Review**: All pull requests require at least one review before merging.

## Reporting Issues

When reporting bugs or requesting features, please include:

1. **For Bugs**:
   - The specific behavior observed
   - Steps to reproduce
   - Expected vs. actual behavior
   - Environment details (OS, Rust version, etc.)

2. **For Feature Requests**:
   - Clear description of the feature
   - Rationale for adding it
   - Potential implementation approach, if known

## Development Environment Setup

1. Install Rust (stable):
   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Install required tools:
   ```
   rustup component add rustfmt clippy
   cargo install cargo-audit cargo-deny
   ```

3. Configure git hooks (optional):
   ```
   git config core.hooksPath .github/hooks
   ```

## Testing

- Run tests: `cargo test --all-features`
- Run linting: `cargo clippy --all-targets --all-features -- -D warnings`
- Format code: `cargo fmt --all`
- Check for security issues: `cargo audit`

## Cryptographic Code Guidelines

Cryptographic code is held to higher standards:

1. **Post-Quantum Only**: All cryptographic primitives must be post-quantum resistant. DSM uses SPHINCS+ (signatures), ML-KEM-768 (key encapsulation), and BLAKE3 (hashing). Do not introduce classical-only primitives.

2. **Domain Separation**: All BLAKE3 hashing must use domain-separated prefixes: `BLAKE3("DSM/<domain>\0" || data)`.

3. **Random Numbers**: Use cryptographically secure random number generators. Deterministic derivation (BLAKE3 keyed mode) is preferred over raw randomness where possible.

4. **Side Channels**: Be aware of potential side-channel attacks.

5. **Constant Time**: All cryptographic operations should run in constant time.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's license.
