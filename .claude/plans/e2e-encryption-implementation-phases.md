# Plan: E2E Encryption Phased Implementation

## Context

The E2E encryption design (`.claude/plans/e2e-encryption-design.md`) defines a Nested TLS architecture where Agent and Connector communicate through the Relay, but the Relay cannot decrypt the Inner TLS traffic. This plan breaks the implementation into 6 human-reviewable phases, each deliverable as a single PR (~200-300 lines).

**Current state:** Agent ↔ Relay (Outer TLS, QUIC/HTTP3, connect-ip, IP packet forwarding via Capsule Protocol). No Connector exists.

**Target state:** Agent ↔ Relay ↔ Connector with Inner TLS (E2E). Relay acts as opaque byte proxy.

---

## Phase 1: Connector Certificate Generation + Policy Type Definitions

**Goal:** Lay certificate and type-system groundwork. No runtime behavior changes.

**Changes:**
- `scripts/generate-certs.sh` (+35 lines) — Add `connector-1.crt`/`connector-1.key` generation (EKU: both `serverAuth` + `clientAuth`, SAN: `connector-1`, `172.28.0.30`)
- `relay/policy/types.go` (+3 lines) — Add `RuleTypeConnector = "connector"`, update `IsValid()`
- `relay/policy/policy.go` (+12 lines) — Add `ConnectorID string` field to `Rule` struct (yaml tag: `connector_id`), validate that connector rules require non-empty `ConnectorID`

**Testable:**
- `make certs` → `openssl verify -CAfile certs/ca.crt certs/connector-1.crt` succeeds
- Unit tests: `RuleTypeConnector.IsValid()` returns true; `Rule{Type: connector, ConnectorID: ""}` validation fails
- `make e2e` passes (no runtime changes)

**Review focus:** Certificate EKU (`serverAuth` for Inner TLS server + `clientAuth` for Relay mTLS), SAN configuration, policy backward compatibility.

**~50 lines changed**

---

## Phase 2: Connector Registry + ConnectorSession Type

**Goal:** Create data structures for managing reverse-tunnel connections from Connectors. Pure library code, no networking.

**New files:**
- `relay/connector/registry.go` (~120 lines) — `Registry` with `Register()`, `Unregister()`, `Get()`, `List()` using `sync.Map`
- `relay/connector/registry_test.go` (~150 lines) — Concurrent register/unregister/get tests

**Changes:**
- `relay/session/session.go` (+25 lines) — Add `ConnectorSession` struct:
  ```go
  type ConnectorSession struct {
      ConnectorID  string
      SourceIP     string
      Stream       io.ReadWriteCloser  // Reverse tunnel stream
      RegisteredAt time.Time
      LastActivity time.Time
      mu           sync.Mutex
  }
  ```

**Testable:** Unit tests for registry thread safety, duplicate detection, cleanup on unregister. Existing E2E passes.

**Review focus:** Thread safety (`sync.Map`), `Stream` field uses generic `io.ReadWriteCloser` for pluggability.

**~295 lines changed**

---

## Phase 3: Connector ACL Matcher

**Goal:** ACL engine can load and evaluate `connector` type rules. Relay doesn't route yet, but the matching logic is ready.

**New files:**
- `relay/acl/connector_matcher.go` (~70 lines) — `ConnectorMatcher` implementing `RuleMatcher`
- `relay/acl/connector_matcher_test.go` (~120 lines)

**Changes:**
- `relay/acl/engine.go` (+3 lines) — Add `case policy.RuleTypeConnector` to `createMatcher()` switch
- `policy.yaml` (+10 lines) — Add connector routing rule example for client-1

**Design:**
```go
type ConnectorMatcher struct {
    cidrs       []*net.IPNet
    connectorID string
    ruleID      string
    action      policy.Action
}
// Match() checks DstIP against cidrs, returns connectorID in MatchResult.Metadata
```

**Testable:** Unit tests for ConnectorMatcher with destination CIDRs. `Engine.CheckAccess()` returns match with `connector_id` in metadata. Existing policy loading unchanged.

**Review focus:** `Metadata` map carries `connector_id` for routing dispatch. Existing `ip_cidr` rules unaffected.

**~200 lines changed**

---

## Phase 4: Connector Binary + Reverse Tunnel Registration

**Goal:** New `connector/` binary connects to Relay via mTLS reverse tunnel. Relay registers it in the registry. No traffic forwarding yet.

**New files:**
- `connector/main.go` (~130 lines) — Load mTLS cert, HTTP/3 CONNECT to Relay with `Protocol: register-connector`, keepalive loop with reconnection
- `connector/go.mod` (~20 lines) — Isolated module (same pattern as `agent/go.mod`)
- `connector/Dockerfile` (~45 lines)
- `connector/entrypoint.sh` (~5 lines)

**Changes:**
- `relay/main.go` (+60 lines) — Handler dispatch by `Protocol` header:
  - `register-connector` → new `handleConnectorRegister()` (register in registry, block until disconnect)
  - `connect-ip` → existing handler (unchanged)
  - `connect-tcp` → `501 Not Implemented` (Phase 5)
- `compose.yaml` (+30 lines) — Add `connector-1` (172.28.0.30) + `internal-server` (nginx, 172.28.0.100) services
- `go.work` — Add `connector/` module
- `Makefile` — Add `connector` build target

**Testable:**
- `docker compose up --build` → Relay logs `"Connector registered: connector-1"`
- Stop connector → Relay logs `"Connector unregistered: connector-1"`
- Existing agent E2E tests pass (connect-ip path unaffected)

**Review focus:** Handler dispatch backward-compat (empty/missing Protocol treated as connect-ip). `ConnectorSession.Stream` wraps `r.Body` + `ResponseWriter`.

**~290 lines changed**

---

## Phase 5: Relay Opaque Proxy (connect-tcp)

**Goal:** Relay receives `connect-tcp` requests from Agent and performs opaque bidirectional byte forwarding to the registered Connector. Traffic flows end-to-end but is **plaintext** through Relay at this stage.

**New files:**
- `relay/proxy/proxy.go` (~80 lines) — `Forward(ctx, dst, src)` bidirectional `io.Copy` with byte counting, half-close handling, context cancellation
- `relay/proxy/proxy_test.go` (~120 lines) — Tests with `io.Pipe` pairs

**Changes:**
- `relay/main.go` (+80 lines) — `handleConnectTCP()`:
  1. Extract `Connector-ID` header
  2. ACL check (uses Phase 3 ConnectorMatcher)
  3. Look up Connector in registry
  4. `proxy.Forward()` between Agent stream and Connector stream
  5. Audit log (metadata only)
- `relay/audit/` (+15 lines) — `EventConnectorProxy` event type

**Connector-side session handling:** When Relay forwards a session, Connector opens TCP to internal resource and bidirectionally copies.

**Testable:**
- Agent sends HTTP CONNECT with `Protocol: connect-tcp`, `Connector-ID: connector-1` → Relay proxies to Connector → Connector reaches `internal-server` (nginx)
- `curl` through the tunnel returns nginx default page
- Existing connect-ip E2E tests pass

**Review focus:** `io.Copy` half-close correctness (one direction EOF must propagate). Resource cleanup on disconnect. ACL check uses `CheckAccess()` with connector matcher, not IP packet inspection.

**~295 lines changed**

---

## Phase 6: Inner TLS (E2E Encryption) + Integration Test

**Goal:** Agent and Connector perform Inner TLS handshake through the Relay's opaque proxy. Relay can no longer see application data. This completes the E2E encryption.

**New files:**
- `agent/connector.go` (~100 lines) — `ConnectorDialer` with Inner TLS client, CN verification
- `connector/innertls.go` (~100 lines) — Inner TLS server, Agent cert verification, TCP forwarding to internal resource
- `scripts/test-connector.sh` (~50 lines) — E2E test: Agent → Relay → Connector → Internal DB

**Changes:**
- `agent/main.go` (+30 lines) — Mode dispatch: if `CONNECTOR_ID` env set, use `startConnectorTunnel()` instead of `startStreamTunnel()`
- `connector/main.go` (+20 lines) — Per-session Inner TLS wrapping
- `Makefile` (+10 lines) — `e2e-connector` target

**Critical implementation detail:** `tls.Client()`/`tls.Server()` require `net.Conn`. Need a thin adapter wrapping the HTTP/3 stream (`io.ReadWriter`) as `net.Conn` (no-op `LocalAddr`/`RemoteAddr`/`SetDeadline`).

**Inner TLS config (Agent side):**
```go
tls.Config{
    Certificates: []tls.Certificate{agentCert},
    RootCAs:      caPool,
    ServerName:   connectorID,   // CN pinning
    MinVersion:   tls.VersionTLS13,
}
```

**Inner TLS config (Connector side):**
```go
tls.Config{
    Certificates: []tls.Certificate{connectorCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    caPool,
    MinVersion:   tls.VersionTLS13,
}
```

**Testable:**
- E2E: Agent → (Outer TLS) → Relay → (opaque bytes) → Connector → (Inner TLS decrypted) → internal-server → response back
- Relay logs contain only metadata, never application data
- `tcpdump` on Relay shows only ciphertext between Agent and Connector streams
- Wrong Connector CN → Agent rejects with `"connector CN mismatch"`
- `make e2e` tests both connect-ip and connect-tcp paths

**Review focus:** `net.Conn` adapter correctness. Certificate pinning (CN match). Mutual TLS on Inner TLS. Relay handler does pure `io.Copy` (no byte inspection).

**~310 lines changed**

---

## Phase Summary

| Phase | Goal | Lines | Key Deliverable |
|-------|------|-------|-----------------|
| 1 | Cert + Policy types | ~50 | Connector certs, `RuleTypeConnector` |
| 2 | Connector Registry | ~295 | `ConnectorRegistry`, `ConnectorSession` |
| 3 | Connector ACL Matcher | ~200 | `ConnectorMatcher`, policy YAML |
| 4 | Connector binary + Reverse Tunnel | ~290 | `connector/` binary, registration |
| 5 | Relay Opaque Proxy | ~295 | `connect-tcp` handler, `io.Copy` |
| 6 | Inner TLS E2E | ~310 | Full E2E encryption |

**Total: ~1,440 lines across 6 PRs (avg ~240 lines/PR)**

## Dependency Graph

```
Phase 1 (types) ──→ Phase 2 (registry) ──→ Phase 4 (connector binary)
                         │                         │
                         ↓                         ↓
                    Phase 3 (ACL) ──────→ Phase 5 (opaque proxy) ──→ Phase 6 (Inner TLS)
```

Phases 1-3 are additive (new types/packages/tests) with zero risk to existing functionality.
Phase 4 first modifies `relay/main.go` but behind new `Protocol` header.
Phase 5 enables traffic flow. Phase 6 adds cryptographic layer.

## Verification (after Phase 6)

```bash
# Full E2E: Agent → Relay → Connector → Internal Resource
make e2e-connector

# Relay blindness: confirm no plaintext in relay logs
docker compose logs relay | grep -i "SELECT"  # Expected: no match

# Certificate pinning: wrong CN rejected
CONNECTOR_ID=wrong-cn docker compose exec agent-1 ./zgate-agent  # Expected: error

# Existing functionality preserved
make e2e  # connect-ip path still works
```
