FROM golang:1.25.5-bookworm AS builder

WORKDIR /build

# Copy root go.mod and pkg/ for capsule package
COPY go.mod go.sum ./
COPY pkg/ ./pkg/

# Copy relay go.mod and go.sum
COPY relay/go.mod relay/go.sum ./relay/
WORKDIR /build/relay
RUN go mod download

# Copy relay source (includes policy, audit, acl, session, internal)
COPY relay/ ./

# Build arguments for versioning
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Build relay binary with version info
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o zgate-relay .

# Runtime stage
FROM debian:bookworm-slim

# OCI annotations
LABEL org.opencontainers.image.title="zgate-relay"
LABEL org.opencontainers.image.description="Zero Trust Network Access Gateway - Relay Server"
LABEL org.opencontainers.image.source="https://github.com/guni1192/zgate"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="guni1192"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/relay/zgate-relay /zgate-relay
COPY relay/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/zgate-relay"]
