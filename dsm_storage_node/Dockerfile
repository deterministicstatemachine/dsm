# DSM Storage Node Dockerfile
# Workspace-aware local/prod image with baked runtime hardening.

# Build from workspace root:
#   docker build -f dsm_storage_node/Dockerfile -t dsm-storage-node:local .

# ---------------------------------------------------------------------------
# Stage 1: Rust builder
# ---------------------------------------------------------------------------
FROM rust:1.91-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Workspace manifests (for caching)
COPY Cargo.toml Cargo.lock ./
COPY dsm_storage_node/Cargo.toml dsm_storage_node/Cargo.toml
COPY dsm_client/deterministic_state_machine/dsm/Cargo.toml dsm_client/deterministic_state_machine/dsm/Cargo.toml
COPY dsm_client/deterministic_state_machine/dsm_sdk/Cargo.toml dsm_client/deterministic_state_machine/dsm_sdk/Cargo.toml
COPY tools/vector_runner/Cargo.toml tools/vector_runner/Cargo.toml
COPY tools/vector_builder/Cargo.toml tools/vector_builder/Cargo.toml
COPY tools/vertical_validation/Cargo.toml tools/vertical_validation/Cargo.toml

# Stub sources so dependency build can cache.
RUN mkdir -p dsm_storage_node/src && echo 'fn main(){}' > dsm_storage_node/src/main.rs && echo '' > dsm_storage_node/src/lib.rs
RUN mkdir -p dsm_client/deterministic_state_machine/dsm/src && echo '' > dsm_client/deterministic_state_machine/dsm/src/lib.rs
RUN mkdir -p dsm_client/deterministic_state_machine/dsm_sdk/src && echo '' > dsm_client/deterministic_state_machine/dsm_sdk/src/lib.rs
RUN mkdir -p tools/vector_runner/src && echo 'fn main(){}' > tools/vector_runner/src/main.rs
RUN mkdir -p tools/vector_builder/src && echo 'fn main(){}' > tools/vector_builder/src/main.rs
RUN mkdir -p tools/vertical_validation/src && echo 'fn main(){}' > tools/vertical_validation/src/main.rs

# Proto + build scripts required by workspace crates.
COPY proto/ proto/
COPY dsm_client/deterministic_state_machine/dsm/build.rs dsm_client/deterministic_state_machine/dsm/build.rs
COPY dsm_client/deterministic_state_machine/dsm_sdk/build.rs dsm_client/deterministic_state_machine/dsm_sdk/build.rs

# Prebuild dependencies (cache warm-up).
RUN cargo build --release --package dsm_storage_node 2>/dev/null || true

# Real sources
COPY dsm_storage_node/src/ dsm_storage_node/src/
COPY dsm_client/deterministic_state_machine/dsm/src/ dsm_client/deterministic_state_machine/dsm/src/
COPY dsm_client/deterministic_state_machine/dsm_sdk/src/ dsm_client/deterministic_state_machine/dsm_sdk/src/

ENV DSM_PROTO_ROOT=/build/proto
RUN cargo build --release --package dsm_storage_node

# ---------------------------------------------------------------------------
# Stage 2: Runtime image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Add non-root user.
RUN groupadd -r dsm && useradd -r -g dsm dsm

# Copy the compiled binary.
COPY --from=builder /build/target/release/storage_node /usr/local/bin/storage_node
RUN chmod 550 /usr/local/bin/storage_node

# Create secure directory structure.
RUN mkdir -p /var/lib/dsm-storage/data \
             /var/lib/dsm-storage/config \
             /var/lib/dsm-storage/keys/production \
             /var/lib/dsm-storage/keys/ca \
             /var/lib/dsm-storage/logs/secure \
             /var/lib/dsm-storage/config/production \
    && chown -R dsm:dsm /var/lib/dsm-storage \
    && chmod 700 /var/lib/dsm-storage/keys/production \
    && chmod 700 /var/lib/dsm-storage/keys/ca \
    && chmod 750 /var/lib/dsm-storage/config/production \
    && chmod 750 /var/lib/dsm-storage/logs/secure \
    && chmod 770 /var/lib/dsm-storage/data

# Generate self-signed TLS certificates during build.
RUN openssl genrsa -out /var/lib/dsm-storage/keys/ca/ca.key 4096 && \
    openssl req -new -x509 -days 365 -key /var/lib/dsm-storage/keys/ca/ca.key \
        -subj "/C=US/ST=State/L=City/O=DSM/CN=DSM-CA" \
        -out /var/lib/dsm-storage/keys/ca/ca.crt && \
    openssl genrsa -out /var/lib/dsm-storage/keys/production/node.key 4096 && \
    openssl req -new -key /var/lib/dsm-storage/keys/production/node.key \
        -subj "/C=US/ST=State/L=City/O=DSM/CN=dsm-storage-node" \
        -out /var/lib/dsm-storage/keys/production/node.csr && \
    openssl x509 -req -days 365 -in /var/lib/dsm-storage/keys/production/node.csr \
        -CA /var/lib/dsm-storage/keys/ca/ca.crt \
        -CAkey /var/lib/dsm-storage/keys/ca/ca.key \
        -CAcreateserial \
        -out /var/lib/dsm-storage/keys/production/node.crt && \
    chown dsm:dsm /var/lib/dsm-storage/keys/production/* && \
    chown dsm:dsm /var/lib/dsm-storage/keys/ca/* && \
    chmod 600 /var/lib/dsm-storage/keys/production/node.key && \
    chmod 644 /var/lib/dsm-storage/keys/production/node.crt && \
    chmod 644 /var/lib/dsm-storage/keys/ca/ca.crt

# Create environment configuration template.
RUN echo '# DSM Storage Node - Production Environment Configuration' > /var/lib/dsm-storage/.env.template && \
    echo '# Copy this file to .env and fill in your production values' >> /var/lib/dsm-storage/.env.template && \
    echo '' >> /var/lib/dsm-storage/.env.template && \
    echo '# Node Security' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_NODE_PRIVATE_KEY_PATH="/var/lib/dsm-storage/keys/production/node.key"' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_TLS_CERT_PATH="/var/lib/dsm-storage/keys/production/node.crt"' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_TLS_KEY_PATH="/var/lib/dsm-storage/keys/production/node.key"' >> /var/lib/dsm-storage/.env.template && \
    echo '' >> /var/lib/dsm-storage/.env.template && \
    echo '# Database Security' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_DATABASE_ENCRYPTION_KEY=""' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_DATABASE_PATH="/var/lib/dsm-storage/data/storage_encrypted.db"' >> /var/lib/dsm-storage/.env.template && \
    echo '' >> /var/lib/dsm-storage/.env.template && \
    echo '# Network Security' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_RATE_LIMIT_PER_MINUTE="60"' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_MAX_CONNECTIONS="500"' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_CONNECTION_TIMEOUT="15"' >> /var/lib/dsm-storage/.env.template

# Default config (TOML only; protobuf transport, no JSON).
COPY dsm_storage_node/config/production.toml /var/lib/dsm-storage/config/config.toml
RUN chown dsm:dsm /var/lib/dsm-storage/config/config.toml

WORKDIR /var/lib/dsm-storage

ENV DSM_STORAGE_CONFIG_PATH=/var/lib/dsm-storage/config/config.toml
ENV DSM_STORAGE_DATA_DIR=/var/lib/dsm-storage/data
ENV RUST_BACKTRACE=1

USER dsm

# Health check via local endpoint (TLS, self-signed cert).
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf --insecure https://localhost:8080/api/v2/health || exit 1

EXPOSE 8080 8081 9090

ENTRYPOINT ["/usr/local/bin/storage_node"]
CMD ["--config", "/var/lib/dsm-storage/config/config.toml"]

LABEL org.opencontainers.image.title="DSM Storage Node"
LABEL org.opencontainers.image.description="Decentralized storage node for DSM policy and state storage"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="DSM Development Team"
