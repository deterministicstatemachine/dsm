FROM rust:1.81 as build
WORKDIR /src
COPY . .
RUN apt-get update && apt-get install -y protobuf-compiler
RUN cargo build -p dsm_storage_node --release

FROM gcr.io/distroless/cc
COPY --from=build /src/target/release/storage_node /usr/local/bin/storage-node
ENTRYPOINT ["/usr/local/bin/storage-node"]