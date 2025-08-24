# Multi-stage build to compile risu-rs
FROM rust:1-bullseye AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/risu-rs

# Copy source code
COPY . .

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
 && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /usr/src/risu-rs/target/release/risu-rs /usr/local/bin/risu-rs

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/risu-rs"]
