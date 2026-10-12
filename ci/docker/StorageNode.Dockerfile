FROM rust:slim-trixie AS build
WORKDIR /src
COPY . .
# python3 runs the real-code guard, which every crate's build script runs.
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler python3 \
	&& rm -rf /var/lib/apt/lists/*
RUN cargo build -p dsm_storage_node --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build --chown=nonroot:nonroot /src/target/release/storage_node /usr/local/bin/storage-node
ENTRYPOINT ["/usr/local/bin/storage-node"]