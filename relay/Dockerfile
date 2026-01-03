FROM golang:1.25.5-bookworm AS builder

WORKDIR /build

# Copy relay go.mod and go.sum
COPY relay/go.mod relay/go.sum ./
RUN go mod download

# Copy relay source
COPY relay/ ./

# Build relay binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o zgate-relay .

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zgate-relay /zgate-relay
COPY relay/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/zgate-relay"]
