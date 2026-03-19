# DSM Storage Node Dockerfile
# Optimized for distributed policy storage with quantum resistance
# Implements declarative containerization to replace imperative shell scripts

# -----------------------------------------------------------------------------
# Stage 1: Build environment with dependency caching
# -----------------------------------------------------------------------------
FROM rust:1.76-slim-bullseye AS builder-base

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    librocksdb-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Create a new empty project for caching dependencies
WORKDIR /usr/src/dsm
RUN cargo new --bin dsm-storage-node
WORKDIR /usr/src/dsm/dsm-storage-node

# Copy the manifests
COPY dsm-storage-node/Cargo.toml .
COPY Cargo.toml /usr/src/dsm/
COPY cargo.toml /usr/src/dsm/
COPY Cargo.lock /usr/src/dsm/

# Build dependencies
RUN mkdir -p src && \
    echo "fn main() {println!(\"dependency placeholder\");}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# -----------------------------------------------------------------------------
# Stage 2: Build the application
# -----------------------------------------------------------------------------
FROM builder-base AS builder

# Copy the source code
COPY dsm-storage-node/src /usr/src/dsm/dsm-storage-node/src
COPY dsm-storage-node/bin /usr/src/dsm/dsm-storage-node/bin

# Copy required workspace dependencies
COPY dsm/src/types /usr/src/dsm/dsm/src/types
COPY dsm/src/crypto /usr/src/dsm/dsm/src/crypto
COPY dsm/src/policy /usr/src/dsm/dsm/src/policy

# Build the application
RUN RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C link-arg=-s -C lto=thin -C codegen-units=1" \
    cargo build --release --bin storage-node --bin storage-cli

# -----------------------------------------------------------------------------
# Stage 3: Create minimal runtime image with baked-in configuration
# -----------------------------------------------------------------------------
FROM debian:bullseye-slim AS runtime

# Add non-root user
RUN groupadd -r dsm && useradd -r -g dsm dsm

# Install runtime dependencies including OpenSSL for certificate generation
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl1.1 \
    librocksdb6.11 \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binaries
COPY --from=builder /usr/src/dsm/target/release/storage-node /usr/local/bin/
COPY --from=builder /usr/src/dsm/target/release/storage-cli /usr/local/bin/

# Create secure directory structure (baked into container)
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

# Generate self-signed TLS certificates during build (baked into container)
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

# Create environment configuration template
RUN echo '# DSM Storage Node - Production Environment Configuration' > /var/lib/dsm-storage/.env.template && \
    echo '# Copy this file to .env and fill in your production values' >> /var/lib/dsm-storage/.env.template && \
    echo '' >> /var/lib/dsm-storage/.env.template && \
    echo '# Node Security' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_NODE_PRIVATE_KEY_PATH="/var/lib/dsm-storage/keys/production/node.key"' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_NODE_PUBLIC_KEY_PATH="/var/lib/dsm-storage/keys/production/node.pub"' >> /var/lib/dsm-storage/.env.template && \
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
    echo 'DSM_CONNECTION_TIMEOUT="15"' >> /var/lib/dsm-storage/.env.template && \
    echo '' >> /var/lib/dsm-storage/.env.template && \
    echo '# API Security' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_API_SECRET_KEY=""' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_CORS_ORIGINS="https://yourdomain.com"' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_MAX_BODY_SIZE="5242880"' >> /var/lib/dsm-storage/.env.template && \
    echo '' >> /var/lib/dsm-storage/.env.template && \
    echo '# Staking Security (if enabled)' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_STAKING_PRIVATE_KEY=""' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_STAKING_ADDRESS=""' >> /var/lib/dsm-storage/.env.template && \
    echo 'DSM_VALIDATOR_ID=""' >> /var/lib/dsm-storage/.env.template

# Default config (TOML only; protobuf transport, no JSON)
COPY dsm-storage-node/config/local.toml /var/lib/dsm-storage/config/config.toml
RUN chown dsm:dsm /var/lib/dsm-storage/config/config.toml

# Set working directory
WORKDIR /var/lib/dsm-storage

# Set environment variables
ENV DSM_STORAGE_CONFIG_PATH=/var/lib/dsm-storage/config/config.toml
ENV DSM_STORAGE_DATA_DIR=/var/lib/dsm-storage/data
ENV RUST_BACKTRACE=1

# Apply security hardening
RUN chmod 550 /usr/local/bin/storage-node /usr/local/bin/storage-cli

# Switch to non-root user
USER dsm

# Health check (human-readable; no JSON)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/storage-cli", "status"] || exit 1

# Expose ports for P2P communication (baked into container networking)
EXPOSE 8080 8081 9090

# Default command
ENTRYPOINT ["/usr/local/bin/storage-node"]
CMD ["--config", "/var/lib/dsm-storage/config/config.toml"]

# Labels
LABEL org.opencontainers.image.title="DSM Storage Node"
LABEL org.opencontainers.image.description="Decentralized storage node for DSM policy and state storage - Containerized with baked-in security setup"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="DSM Development Team"
