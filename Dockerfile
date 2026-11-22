FROM rust:1-bookworm AS builder
WORKDIR /app

# Build dependencies separately so source changes can reuse the dependency layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && printf 'fn main() {}\n' > src/main.rs && cargo build --release && rm -rf src

COPY src ./src
COPY static ./static
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home ledgerly
WORKDIR /app
COPY --from=builder /app/target/release/ledgerly /usr/local/bin/ledgerly
COPY --from=builder /app/static ./static
USER ledgerly
ENV PORT=8080
EXPOSE 8080
CMD ["/usr/local/bin/ledgerly"]
