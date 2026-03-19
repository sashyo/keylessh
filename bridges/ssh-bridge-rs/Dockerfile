###############
# Build stage #
###############
FROM rust:1.84-bookworm AS builder
WORKDIR /app

# Cache deps by building a dummy project first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Build the real binary
COPY src ./src
RUN touch src/main.rs && cargo build --release

####################
# Production stage #
####################
FROM gcr.io/distroless/cc-debian12:nonroot AS production
WORKDIR /app

ENV PORT=8080

COPY --from=builder /app/target/release/ssh-bridge-rs ./ssh-bridge-rs

EXPOSE 8080

USER nonroot

ENTRYPOINT ["./ssh-bridge-rs"]
