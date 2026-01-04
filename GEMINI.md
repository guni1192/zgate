# zgate ZTNA Project Documentation

## 1. Project Overview

**Name:** zgate (Zero Trust Network Access Gateway)
**Goal:** Implement a Hub-Spoke ZTNA solution using **MASQUE (Multiplexed Application Substrate over QUIC Encryption)**.
**Key Standard:** RFC 9484 (IP Proxying support for HTTP).
**Use Case:** Secure access for medical institutions to SaaS (Split Tunnel) and On-prem resources (Connector).

## 2. Tech Stack & Environment

* **Language:** Go `1.25.5`
* **Architecture:** Hybrid Go Monorepo with go.work
* **Base Image:** Debian Bookworm (via Docker)
* **Core Libraries:**
  * QUIC/HTTP3: `github.com/quic-go/quic-go`
  * TUN/TAP: `github.com/songgao/water`
  * Packet Analysis: `github.com/google/gopacket`
* **Container Runtime:** Docker Compose (v2)
* **Deployment:**
  * **Host:** macOS (Development environment)
  * **Container:** Linux (Production-like environment for routing isolation)

## 3. System Architecture & Current Implementation

### 3.1 Hub-and-Spoke Model

* **Agent (Spoke):** Creates a TUN interface, captures OS packets, encapsulates them in HTTP/3, and sends them to the Relay.
* **Relay (Hub):** Terminates QUIC connections, decapsulates packets, writes them to its own TUN interface, and routes them to the destination (Internet) via NAT.

### 3.2 Network Flow (Docker Environment)

```mermaid
graph LR
    subgraph "Docker Network (zgate-net: 172.28.0.0/24)"
        C[Agent Container] --"QUIC (UDP/4433)"--> R[Relay Container]
    end

    subgraph "Agent Internal"
        App[Ping/App] --"IP Packet"--> TunC[tun0]
        TunC --"Read/Encap"--> GoAgent[Agent App]
    end

    subgraph "Relay Internal"
        GoRelay[Relay Server] --"Decap/Write"--> TunR[tun0]
        TunR --"Routing/NAT"--> EthR[eth0]
    end

    GoAgent --"HTTP/3 Stream"--> GoRelay
    EthR --"Masquerade"--> Internet((Internet))
```

### 3.3 Current Tunneling Mechanism (Phase 2)

* **Method:** HTTP/3 **Stream Tunneling** (Request/Response Body)
* **Framing:** Simple Length-Prefixed framing to handle packet boundaries in a stream
  * Format: `[Length (uint16 big-endian)] [IP Packet Payload]`
* **Method:** `CONNECT`
* **Header:** `Protocol: connect-ip` (RFC 9484 adherence)

## 4. Directory Structure (Hybrid Monorepo)

```text
zgate/
├── go.mod                          # Root go.mod (relay, connector, shared code)
├── go.sum
├── go.work                         # Go workspace (development)
├── go.work.sum
│
├── cmd/                            # Binary entry points
│   └── zgate-relay/
│       └── main.go
│
├── agent/                          # Agent (isolated go.mod)
│   ├── go.mod
│   ├── go.sum
│   ├── main.go
│   ├── net_linux.go
│   └── net_darwin.go
│
├── relay/                          # Relay server packages
│   ├── main.go                     # Relay entry point
│   ├── acl/                        # Access Control List
│   ├── audit/                      # Structured audit logging
│   ├── policy/                     # Policy storage abstraction
│   ├── ipam/                       # IP Address Management
│   ├── session/                    # Session management
│   └── internal/                   # Platform-specific helpers
│
├── internal/                       # Private packages (deprecated)
│   └── relay/
│       ├── net_linux.go
│       └── net_darwin.go
│
├── pkg/                            # Shared libraries (future)
│   ├── protocol/                   # Framing, constants
│   ├── cert/                       # TLS utilities
│   └── tunutil/                    # TUN interface helpers
│
├── deployments/
│   └── docker/
│       ├── relay.Dockerfile
│       ├── agent.Dockerfile
│       ├── compose.yaml
│       ├── relay-entrypoint.sh
│       └── agent-entrypoint.sh
│
├── scripts/
│   ├── generate-certs.sh           # Certificate generation
│   └── test-acl.sh                 # ACL E2E test script
│
├── certs/                          # Generated certificates (gitignored)
├── policy.yaml                     # ACL policy configuration
│
├── docs/
│   ├── architecture/
│   │   └── phase-3.2-acl-plan.md   # Phase 3.2 implementation plan
│   ├── packet-flow.md
│   └── FAQ.md
│
├── Makefile                        # Build automation
├── README.md
└── CLAUDE.md -> GEMINI.md          # Project context
```

### Monorepo Architecture Rationale

**Why Hybrid (Agent isolated, Server components share)?**

1. **Agent Isolation:**
   - Independent `agent/go.mod` with minimal dependencies
   - Binary distributed to end users (size matters)
   - Prevents accidental bloat from server dependencies
   - Enables independent version upgrades

2. **Server Components Share:**
   - Relay and future Connector use root `go.mod`
   - Share heavy dependencies (DB drivers, policy engine)
   - Coordinated deployment (both are datacenter services)

3. **go.work Benefits:**
   - Seamless development across modules
   - IDE support works out of the box
   - `go test ./...` tests entire codebase
   - Lower friction than full multi-module setup

**Binary Sizes (Phase 3.1):**
- `zgate-relay`: 11MB (CGO_ENABLED=1, stripped)
- `zgate-agent`: 12MB (CGO_ENABLED=1, stripped)

## 5. Security & Configuration Constraints

1. **Least Privilege:**
   * Do **NOT** use `privileged: true` in Docker Compose
   * Use `cap_add: [NET_ADMIN]` and `devices: [/dev/net/tun:/dev/net/tun]`

2. **Routing Isolation:**
   * Agent and Relay must run in separate network namespaces (Docker containers) to avoid routing loops

3. **TLS:**
   * Using mTLS with CA-signed client certificates
   * TLS 1.3 minimum version enforced
   * Certificate generation via `scripts/generate-certs.sh`

## 6. Current Status

* [x] **Phase 1: Local TUN/TAP** - Can read/write IP packets from OS
* [x] **Phase 2: Stream-based Tunneling**
  * End-to-End Ping (`agent` -> `relay` -> `8.8.8.8`) works with 100% reliability
  * Routing loop resolved via Docker network isolation
  * NAT (IP Masquerade) configured on Relay
  * Length-prefixed framing ensures reliable packet boundaries over HTTP/3 streams
* [x] **Phase 3.1: mTLS Authentication**
  * Client certificate-based authentication
  * Client ID extraction from CN field
  * TLS 1.3 enforcement
* [x] **Phase 3.2: ACL (Access Control List)** - Completed
  * **Phase 3.2.1: ACL Foundation** ✅
    * YAML-based policy engine with IP CIDR matching
    * Structured audit logging (JSON format to stdout)
    * Client-specific rule enforcement (first-match-wins)
    * Default deny policy with explicit allow rules
  * **Phase 3.2.2: IPAM (IP Address Management)** ✅
    * Dynamic Virtual IP allocation (10.100.0.2-254)
    * ClientID-based deterministic allocation (same client = same IP)
    * Dual-index session manager (routing + admin lookups)
    * HTTP 503 on IP pool exhaustion
    * 94.4% test coverage (IPAM), 80.3% (session manager)
  * **Phase 3.2.3: Integration** - TODO
    * Agent dynamic IP configuration from Relay
    * ACL enforcement in packet path (handleMasqueRequest)
    * VirtualIP → ClientID lookup for ACL checks
    * E2E validation with multi-client ACL enforcement
* [ ] **Phase 3.3+: Connector & Advanced Features**
  * On-prem Connector (reverse tunnel)
  * FQDN-based ACL
  * Policy management API
  * IPAM persistence (optional)

## 7. How to Run (Development)

```bash
# 1. Generate certificates (first time only)
make certs

# 2. Start environment (rebuilds images)
cd deployments/docker
docker compose up --build

# 3. Verify connectivity (from separate terminal)
docker compose exec agent-1 ping -c 4 8.8.8.8
docker compose exec agent-2 ping -c 4 8.8.8.8

# 4. Check IPAM allocation logs
docker compose logs relay | grep "Virtual IP"
```

### E2E Tests

```bash
make e2e
```

### Test ACL Enforcement

```bash
bash scripts/test-acl.sh
```

### Build Binaries

```bash
# Build all
make all

# Build individual components
make relay    # Builds zgate-relay
make agent    # Builds zgate-agent

# Clean build artifacts
make clean
```

## 8. Next Steps

### Phase 3.2.3: ACL-IPAM Integration (Immediate)

**Goal**: Complete Phase 3.2 by integrating ACL enforcement with IPAM

**Tasks**:
1. **Agent Dynamic IP Configuration**
   - Modify Relay to send Virtual IP via HTTP header (`X-Virtual-IP`)
   - Update Agent to read and configure TUN interface dynamically
   - Remove hardcoded `ClientIP = "10.100.0.2"` from agent/main.go

2. **ACL Enforcement in Packet Path**
   - Add ACL check in `handleMasqueRequest` upstream handler
   - Extract packet info (src/dst IP, protocol, ports)
   - Call `aclEngine.CheckAccess(clientID, packetInfo)`
   - Drop packets on deny, log via audit logger

3. **VirtualIP → ClientID Lookup**
   - Use `sessionManager.GetByVirtualIP()` to resolve ClientID
   - Enable ACL enforcement based on source Virtual IP

4. **E2E Validation**
   - Verify client-1 can only reach 8.8.8.8/32 and 1.1.1.1/32
   - Verify client-2 can reach any destination (0.0.0.0/0)
   - Confirm audit logs show ACL decisions

**Estimated Effort**: 1-2 days

---

### Phase 3.3: On-prem Connector (Future)
- Reverse tunnel for internal resources
- Extend ACL for connector routing
- IPAM persistence for production deployments

### Phase 4: Policy Management API (Future)
- REST API for dynamic policy updates
- Database backend for policy storage
- Web UI for administration

## 9. Development Workflow

### Working with go.work

```bash
# Clone repository
git clone https://github.com/guni1192/zgate
cd zgate

# go.work is already configured - builds work immediately
go build ./cmd/zgate-relay     # Uses root go.mod
cd agent && go build .          # Uses agent/go.mod
cd .. && go test ./...          # Tests all modules
```

### Adding Dependencies

**For relay/server components:**
```bash
go get <package>
go mod tidy
```

**For agent:**
```bash
cd agent
go get <package>
go mod tidy
```

### Docker Development

```bash
# Start development environment
make dev-up

# View logs
make logs-relay
make logs-agent

# Stop environment
make dev-down
```

## 10. References

- **MASQUE Protocol**: [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484.html)
- **QUIC Go**: [github.com/quic-go/quic-go](https://github.com/quic-go/quic-go)
- **TUN/TAP (water)**: [github.com/songgao/water](https://github.com/songgao/water)
- **Architecture Documentation**: `docs/architecture/`
