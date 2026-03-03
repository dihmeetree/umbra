# Stage 1: Build
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y cmake gcc g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency build
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    echo 'fn main() {}' > src/bin/simulator.rs && \
    cargo build --release 2>/dev/null ; \
    rm -rf src

# Copy full source and build
COPY . .
RUN touch src/main.rs src/lib.rs && cargo build --release --bin umbra --bin faucet

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/umbra /usr/local/bin/
COPY --from=builder /build/target/release/faucet /usr/local/bin/

EXPOSE 9732 9733 9742 9743 9744

VOLUME /data

ENTRYPOINT ["umbra"]
CMD ["node", "--network", "testnet", "--data-dir", "/data"]
