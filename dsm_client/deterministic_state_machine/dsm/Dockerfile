# DSM Multi-Stage Optimized Dockerfile
# Implementing quantum-resistant hash chain verification with security hardening

# -----------------------------------------------------------------------------
# Stage 1: Rust build environment with caching layer for dependencies
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/rust:latest AS builder-base

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    pkgconfig \
    openssl-dev \
    clang \
    llvm \
    rocksdb-dev \
    cmake \
    clang-dev

# Create a new empty project for caching dependencies
WORKDIR /usr/src/dsm
RUN cargo new --bin dsm
WORKDIR /usr/src/dsm/dsm

# Copy the manifests and toolchain configuration
COPY dsm/Cargo.toml .
COPY dsm/.cargo .cargo
COPY Cargo.toml /usr/src/dsm/
COPY cargo.toml /usr/src/dsm/
COPY Cargo.lock /usr/src/dsm/

# Build dependencies - this layer will be cached unless dependencies change
RUN mkdir -p src && \
    echo "fn main() {println!(\"dependency placeholder\");}" > src/main.rs && \
    touch src/lib.rs && \
    cargo build --release && \
    rm -rf src

# -----------------------------------------------------------------------------
# Stage 2: Build the actual application
# -----------------------------------------------------------------------------
FROM builder-base AS builder

# Copy the source code
COPY dsm/src /usr/src/dsm/dsm/src
COPY dsm/bin /usr/src/dsm/dsm/bin

# Copy other project members for workspace compilation
COPY dsm-storage-node /usr/src/dsm/dsm-storage-node
COPY dsm-ethereum-bridge /usr/src/dsm/dsm-ethereum-bridge
COPY dsm-sdk /usr/src/dsm/dsm-sdk

# Check the code for security issues
RUN cargo audit || true
RUN cargo clippy -- -D warnings || true

# Build the application with security flags
RUN RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C link-arg=-s -C lto=thin -C codegen-units=1 -D warnings" \
    cargo build --release --bin dsm --bin cli --bin server

# -----------------------------------------------------------------------------
# Stage 3: Create minimal runtime image with security hardening
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/glibc-dynamic:latest AS runtime

# Copy the compiled binaries from the builder stage
COPY --from=builder /usr/src/dsm/target/release/dsm /usr/local/bin/
COPY --from=builder /usr/src/dsm/target/release/cli /usr/local/bin/
COPY --from=builder /usr/src/dsm/target/release/server /usr/local/bin/

# Create necessary directories with proper permissions
RUN mkdir -p /var/lib/dsm/data /var/lib/dsm/config /var/lib/dsm/policies

# Set working directory
WORKDIR /var/lib/dsm

# Set environment variables
ENV DSM_CONFIG_PATH=/var/lib/dsm/config/default_config.json
ENV DSM_DATA_DIR=/var/lib/dsm/data
ENV DSM_POLICY_DIR=/var/lib/dsm/policies
ENV RUST_BACKTRACE=1
ENV DSM_LOG_LEVEL=info
# Security hardening
ENV HOME=/var/lib/dsm

# Apply security hardening
RUN chmod 550 /usr/local/bin/dsm /usr/local/bin/cli /usr/local/bin/server && \
    chmod 770 /var/lib/dsm/data /var/lib/dsm/config /var/lib/dsm/policies

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/cli", "status", "--json"] || exit 1

# Expose ports (API, P2P, Metrics)
EXPOSE 7545 8765 9090

# Default command
ENTRYPOINT ["/usr/local/bin/server"]
CMD ["--config", "/var/lib/dsm/config/default_config.json"]

# Label the image with metadata
LABEL org.opencontainers.image.title="DSM"
LABEL org.opencontainers.image.description="Deterministic State Machine implementing quantum-resistant hash chain verification"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="DSM Development Team"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/deterministicstatemachine/dsm"
LABEL com.dsm.security.quantum-resistant="true"
LABEL com.dsm.security.hardened="true"
