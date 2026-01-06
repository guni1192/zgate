FROM golang:1.25.5-bookworm AS builder

WORKDIR /build

# Copy root go.mod and pkg/ for capsule package (agent depends on it via replace directive)
COPY go.mod go.sum ./
COPY pkg/ ./pkg/

# Copy agent go.mod and go.sum (isolated dependencies)
COPY agent/go.mod agent/go.sum ./agent/
WORKDIR /build/agent
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
    netcat-openbsd \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/agent/zgate-agent /zgate-agent
COPY agent/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/zgate-agent"]
