###############
# Build stage #
###############
FROM rust:1.84-bookworm AS builder
WORKDIR /app

# Install native dependencies for openssl/native-tls
RUN apt-get update && apt-get install -y pkg-config libssl-dev cmake && rm -rf /var/lib/apt/lists/*

# Cache deps by building a dummy project first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Build the real binary
COPY src ./src
RUN touch src/main.rs && cargo build --release

####################
# Production stage #
####################
FROM debian:bookworm-slim AS production
WORKDIR /app

# Runtime deps for native-tls and DNS resolution
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

ENV LISTEN_PORT=7891
ENV HEALTH_PORT=7892
ENV HTTPS=true

COPY --from=builder /app/target/release/punchd-bridge-rs ./punchd-bridge-rs

# Copy public assets (static files served by the gateway)
COPY public ./public

EXPOSE 7891 7892

USER nobody

ENTRYPOINT ["./punchd-bridge-rs"]
