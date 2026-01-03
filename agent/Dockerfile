FROM golang:1.25.5-bookworm AS builder

WORKDIR /build

# Copy agent go.mod and go.sum (isolated dependencies)
COPY agent/go.mod agent/go.sum ./
RUN go mod download

# Copy agent source only
COPY agent/ ./

# Build agent binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o zgate-agent .

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    ca-certificates \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zgate-agent /zgate-agent
COPY agent/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/zgate-agent"]
