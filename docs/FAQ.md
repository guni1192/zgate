# FAQ - Frequently Asked Questions

## Q1. Why use Streams instead of HTTP/3 Datagrams?

**A:** HTTP/3 Datagrams have **75% packet loss** even in local Docker networks with quic-go v0.58.0. Streams provide 100% reliability with negligible performance impact for VPN use cases.

| Metric | Streams | Datagrams |
|--------|---------|-----------|
| Packet Loss | 0% | 75% |
| Reliability | Guaranteed | Best-effort |
| HOL Blocking | Minor | None |
| Complexity | Low | High |

---

## Q2. Does this follow RFC 9484 (MASQUE) standards?

**A:** Partially. We use:
- ✅ HTTP CONNECT method
- ✅ `Protocol: connect-ip` header
- ✅ QUIC/HTTP3 transport
- ❌ Datagram framing (replaced with length-prefixed streams)

RFC 9484 recommends Datagrams, but doesn't mandate them. Our stream-based approach is a pragmatic alternative until Datagram support matures.

---

## Q3. What caused the 75% Datagram packet loss?

**A:** Three main issues with quic-go:

1. **Silent dropping**: `SendDatagram()` returns success even when packets are dropped
2. **Aggressive congestion control**: Throttles Datagrams even on localhost
3. **Fixed buffer sizes**: No way to increase Datagram send/receive buffers

We tried pacing, retry logic, and window tuning—nothing helped.

---

## Q4. Will you support Datagrams in the future?

**A:** Yes, if/when:
- quic-go exposes configurable Datagram buffer sizes
- Congestion control becomes tunable for Datagrams
- Error reporting improves (explicit drop notifications)

For now, Streams are the production-ready choice.

---

## Q5. How does length-prefixed framing work?

**A:** Each packet is prefixed with a 2-byte length header:

```
┌──────────────┬─────────────────────────┐
│ Length (u16) │ IP Packet (variable)    │
│ Big-endian   │ IPv4/IPv6 + payload     │
└──────────────┴─────────────────────────┘
```

This preserves packet boundaries over the HTTP/3 stream, similar to how TLS records work.

---

## Q6. What's the performance overhead of Streams vs Datagrams?

**A:** In our tests:
- **Latency**: ~10-15ms RTT overhead (acceptable for VPN)
- **Throughput**: No significant difference
- **CPU**: Slightly higher due to stream management

The reliability gain far outweighs the minimal latency increase.

---

## Q7. Can I run multiple clients simultaneously?

**A:** Currently, the Relay assigns a **fixed virtual IP** (10.100.0.2) to all clients, so only one client works at a time.

For multi-client support, you'd need:
- Dynamic IPAM (IP Address Management)
- Session tracking per client
- Updated routing logic

This is planned for Phase 3 (Connector & Security).

---

## Q8. Why Docker instead of running natively?

**A:** Two main reasons:

1. **Routing isolation**: Prevents routing loops on the host
2. **Privilege separation**: Uses `NET_ADMIN` capability instead of `privileged: true`

You can run natively on Linux, but need careful routing table management.

---

## Q9. Is this production-ready?

**A:** Not yet. Missing features:

- ❌ Authentication (no mTLS/OIDC)
- ❌ Multi-client support
- ❌ Access control lists (ACL)
- ❌ Connection pooling
- ❌ Metrics/monitoring

This is a **proof-of-concept** for the core tunneling mechanism.

---

## Q10. How do I debug packet flow?

**A:** Three approaches:

1. **Check logs**: Both client/relay log packet routing
   ```bash
   docker compose logs -f client relay
   ```

2. **Inspect TUN interfaces**:
   ```bash
   docker compose exec relay ip addr show tun0
   docker compose exec relay ip route
   ```

3. **Verify NAT**:
   ```bash
   docker compose exec relay iptables -t nat -L -n -v
   ```

See [packet-flow.md](packet-flow.md) for detailed debugging steps.

---

## Q11. Can I use this for UDP traffic (DNS, gaming, etc.)?

**A:** Yes! The tunnel is protocol-agnostic. Any IP traffic works:
- ✅ ICMP (ping/traceroute)
- ✅ TCP (HTTP, SSH, etc.)
- ✅ UDP (DNS, QUIC apps, gaming)

Just add the target IP/CIDR to `TARGET_CIDRS` environment variable.

---

## Q12. What's the maximum packet size (MTU)?

**A:** Currently **1300 bytes** for both Client and Relay TUN interfaces.

This is conservative to avoid fragmentation over QUIC. You can increase it in:
- `masque-client/main.go`: `MTU = 1300`
- `masque-relay/main.go`: `ServerMTU = 1300`

But beware of path MTU issues in real networks.

---

## Q13. How is this different from traditional VPNs (OpenVPN, WireGuard)?

| Feature | This Project | WireGuard | OpenVPN |
|---------|--------------|-----------|---------|
| Protocol | HTTP/3 (QUIC) | UDP | TCP/UDP |
| Encryption | TLS 1.3 | ChaCha20 | OpenSSL |
| Firewall Traversal | Excellent (port 443) | Poor | Good (TCP) |
| Performance | Good | Excellent | Moderate |
| Standards | RFC 9484 (MASQUE) | RFC 8926 | Proprietary |

**Advantage**: Works through corporate proxies (looks like HTTPS traffic)

---

## Q14. Why Go instead of Rust/C++?

**A:** Practicality:
- ✅ Excellent QUIC library (quic-go)
- ✅ Simple TUN/TAP support (water)
- ✅ Fast development iteration
- ✅ Cross-platform (macOS/Linux)

Performance isn't the bottleneck—QUIC overhead dominates.

---

## Q15. Where can I learn more about MASQUE?

**A:** Key resources:

- [RFC 9484 - Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html) - Core spec
- [RFC 9297 - HTTP/3 Datagrams](https://www.rfc-editor.org/rfc/rfc9297.html) - Datagram transport
- [MASQUE IETF Working Group](https://datatracker.ietf.org/wg/masque/) - Latest discussions
- [Apple's iCloud Private Relay](https://www.apple.com/privacy/docs/iCloud_Private_Relay_Overview_Dec2021.PDF) - Real-world MASQUE deployment

---

## Need More Help?

- 📖 Read the [Packet Flow Documentation](packet-flow.md)
- 💬 Check existing [GitHub Issues](https://github.com/yourusername/masque-playground/issues)
- 🐛 Report bugs with detailed logs
