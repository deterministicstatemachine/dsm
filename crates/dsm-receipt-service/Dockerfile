# The DSM receipt service (DSM Amendment A17).
#
# Build from the workspace root:
#   docker build -f crates/dsm-receipt-service/Dockerfile -t dsm-receipt-service:latest .
#
# Run behind an HTTPS proxy (the wallet reaches it only over https://):
#   docker run --rm -p 127.0.0.1:8090:8090 \
#     -e RECEIPT_BIND=0.0.0.0:8090 \
#     -e RECEIPT_SMTP_URL='smtps://USER:PASSWORD@smtp.example.com:465' \
#     -e RECEIPT_FROM='DSM Receipts <receipts@example.com>' \
#     -e RECEIPT_PER_DEVICE=30 -e RECEIPT_PER_RECIPIENT=20 -e RECEIPT_WINDOW_SECS=3600 \
#     dsm-receipt-service:latest

FROM rust:1.98-slim-bookworm AS builder
# python3 runs the real-code guard every crate's build script runs;
# protobuf-compiler serves the proto build scripts.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config protobuf-compiler python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
ENV DSM_PROTO_ROOT=/build/proto
RUN cargo build --release --locked --package dsm-receipt-service

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -r dsm && useradd -r -g dsm -d /app dsm
COPY --from=builder /build/target/release/dsm-receipt-service /usr/local/bin/dsm-receipt-service
USER dsm
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/dsm-receipt-service"]
