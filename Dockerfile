FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo fetch && cargo update home --precise 0.5.11 || true && cargo update sdp --precise 0.9.0 || true
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/nosta /usr/local/bin/nosta

EXPOSE 8080
VOLUME /data

CMD ["nosta", "start", "--addr", "0.0.0.0:8080", "--data-dir", "/data"]
