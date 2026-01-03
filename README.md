# zgate - Zero Trust Network Access Gateway

A Hub-Spoke ZTNA (Zero Trust Network Access) implementation using **MASQUE** (Multiplexed Application Substrate over QUIC Encryption) based on RFC 9484.

## Overview

zgate implements a secure IP proxy using HTTP/3 CONNECT with stream-based packet encapsulation, providing:

- ✅ **100% reliable packet delivery** via QUIC streams
- ✅ **mTLS authentication** with client certificates
- ✅ **Encrypted tunneling** using TLS 1.3
- ✅ **Hub-Spoke architecture** for centralized access control
- ✅ **Static binary** with zero CGO dependencies

## Quick Start

```bash
# 1. Generate certificates (first time only)
make certs

# 2. Start the environment
docker compose up --build

# 3. Test connectivity (from another terminal)
docker compose exec agent ping -c 4 8.8.8.8

# 4. Run E2E tests
make e2e
```

## Architecture

```
┌─────────────────┐       ┌─────────────────┐       ┌──────────────┐
│  Agent          │       │  Relay          │       │  Internet    │
│  (Client)       │◄─────►│  (Hub)          │◄─────►│  (8.8.8.8)   │
│  172.28.0.20    │ QUIC  │  172.28.0.10    │  NAT  │              │
└─────────────────┘ mTLS  └─────────────────┘       └──────────────┘
      TUN: 10.100.0.2         TUN: 10.100.0.1
```

### Components

- **zgate-agent**: Creates TUN interface, captures OS packets, encapsulates in HTTP/3 streams
- **zgate-relay**: Terminates QUIC connections, decapsulates packets, routes via NAT
- **Framing**: Length-prefixed packets (`[uint16 length][IP packet]`)

## Project Structure

```
zgate/
├── relay/                 # Relay subsystem
│   ├── go.mod            # Independent dependencies
│   ├── Dockerfile
│   └── main.go
├── agent/                 # Agent subsystem
│   ├── go.mod            # Independent dependencies
│   ├── Dockerfile
│   └── main.go
├── go.work               # Workspace configuration
├── compose.yaml          # Docker Compose
└── Makefile              # Build automation
```

## Build

```bash
# Build all binaries
make all

# Build individual components
make relay    # Builds bin/zgate-relay (7.9MB)
make agent    # Builds bin/zgate-agent (8.4MB)

# Clean build artifacts
make clean
```

**Binary Properties:**
- Static binaries (CGO_ENABLED=0)
- Stripped symbols (-ldflags="-s -w")
- Cross-platform compatible (Linux, macOS, Windows)

## Development

```bash
# Start development environment
make dev-up

# View logs
make logs-relay
make logs-agent

# Stop environment
make dev-down
```

## Roadmap

### ✅ Phase 1: TUN/TAP Interface (Completed)
- Local TUN device creation and configuration
- IP packet read/write from OS network stack

### ✅ Phase 2: Stream-based Tunneling (Completed)
- HTTP/3 CONNECT with length-prefixed framing
- End-to-End connectivity with 100% reliability
- NAT configuration for Internet access

### ✅ Phase 3.1: mTLS Authentication (Completed)
- Client certificate-based authentication
- TLS 1.3 enforcement
- Client ID extraction from certificate CN

### 🚧 Phase 3.2: Access Control List (In Progress)
- **Destination IP-based ACL**
  - YAML-based policy configuration
  - Allow/Deny rules per client
  - Structured audit logging
- **Extensible design for future enhancements**
  - FQDN-based matching (Phase 3.3+)
  - GeoIP filtering (Phase 4+)
  - API-based policy management (Phase 4+)

### 📋 Phase 3.3: On-prem Connector (Planned)
- **Reverse tunnel for internal resources**
  - Connector registration to Relay
  - Private network routing
  - FQDN-based ACL extension

### 📋 Phase 4: Policy Management API (Planned)
- **REST API for dynamic policy updates**
  - Policy CRUD endpoints
  - Client management
  - Audit log query
- **Database backend**
  - PostgreSQL for policy persistence
  - Migration system
- **Web UI** (Optional)
  - Policy administration dashboard
  - Real-time monitoring

## Technology Stack

- **Language**: Go 1.25.5
- **Architecture**: Hybrid Go Workspace (go.work)
- **QUIC/HTTP3**: [quic-go/quic-go](https://github.com/quic-go/quic-go)
- **TUN/TAP**: [songgao/water](https://github.com/songgao/water)
- **Packet Analysis**: [google/gopacket](https://github.com/google/gopacket)

## Why Not HTTP/3 Datagrams?

While RFC 9484 recommends HTTP/3 Datagrams for IP proxying, we found them unsuitable for production VPN use:

- ❌ **75% packet loss** in local Docker network
- ❌ Silent packet dropping (no error reporting)
- ❌ Unconfigurable send buffer size
- ❌ Aggressive congestion control even on localhost

Stream-based tunneling provides 100% reliability with acceptable latency. See [FAQ](docs/FAQ.md) for detailed investigation.

## Documentation

- **[Packet Flow Diagram](docs/packet-flow.md)** - How packets flow through the tunnel
- **[FAQ](docs/FAQ.md)** - Frequently asked questions
- **[Phase 3.2 ACL Plan](docs/architecture/phase-3.2-acl-plan.md)** - Detailed ACL implementation plan

## License

MIT

## References

- [RFC 9484 - Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [RFC 9297 - HTTP/3 Datagrams](https://www.rfc-editor.org/rfc/rfc9297.html)
- [MASQUE Working Group](https://datatracker.ietf.org/wg/masque/about/)
