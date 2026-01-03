# Phase 2: Stream-based Tunneling - Packet Flow

This document explains how ICMP packets (ping) flow through the MASQUE tunnel from Client to Internet and back.

---

## High-Level Architecture

```
┌─────────────────┐       ┌─────────────────┐       ┌──────────────┐
│  Client         │       │  Relay          │       │  Internet    │
│  Container      │◄─────►│  Container      │◄─────►│  (8.8.8.8)   │
│  172.28.0.20    │ QUIC  │  172.28.0.10    │  NAT  │              │
└─────────────────┘       └─────────────────┘       └──────────────┘
      TUN: 10.100.0.2         TUN: 10.100.0.1
```

---

## Detailed Packet Flow: ICMP Echo Request

### Step 1: Application Layer (Client Container)

```bash
$ ping 8.8.8.8
```

The `ping` command generates an **ICMP Echo Request** packet:

```
┌─────────────────────────────────────┐
│ IPv4 Header                         │
│  - Source IP: 10.100.0.2            │
│  - Dest IP: 8.8.8.8                 │
│  - Protocol: ICMP                   │
├─────────────────────────────────────┤
│ ICMP Header                         │
│  - Type: 8 (Echo Request)           │
│  - Code: 0                          │
│  - Sequence: 1                      │
└─────────────────────────────────────┘
```

---

### Step 2: OS Routing (Client Container)

The Linux kernel checks its routing table:

```bash
$ ip route show
8.8.8.8 via 10.100.0.1 dev tun0
```

The packet is **sent to TUN interface** `tun0` (virtual interface).

---

### Step 3: TUN Read (Client App)

The Client Go application reads from the TUN interface:

```go
// masque-client/main.go
n, err := iface.Read(buf)  // Read raw IP packet (84 bytes for ICMP)
```

At this point, the raw packet looks like:

```
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    45 00 00 54 xx xx xx xx xx 01 xx xx 0A 64 00 02  IPv4 Header
0010    08 08 08 08 08 00 xx xx xx xx xx xx xx xx xx xx  ICMP Echo Request
...     (84 bytes total)
```

---

### Step 4: Framing & Encapsulation (Client App)

The Client **adds a length prefix** (2 bytes, big-endian) and writes to the HTTP/3 stream:

```go
// Write length prefix (uint16)
binary.Write(pw, binary.BigEndian, uint16(n))  // Example: 0x0054 (84 bytes)

// Write raw IP packet
pw.Write(buf[:n])
```

The stream now contains:

```
┌──────┬────────────────────────────────┐
│ 0x00 │ Length (2 bytes): 0x0054       │
├──────┼────────────────────────────────┤
│ 0x02 │ IP Packet (84 bytes)           │
│      │   - IPv4 Header (20 bytes)     │
│      │   - ICMP Data (64 bytes)       │
└──────┴────────────────────────────────┘
```

---

### Step 5: QUIC/HTTP3 Transport (Client → Relay)

The data travels over an **HTTP/3 bidirectional stream** inside a QUIC connection:

```
Client                                    Relay
  |                                         |
  | HTTP CONNECT /                          |
  | Protocol: connect-ip                    |
  |========================================>|
  |                                         |
  | 200 OK                                  |
  |<========================================|
  |                                         |
  | [0x00 0x54][84-byte IP packet]          |
  |========================================>|
  |                                         |
```

**Key Properties:**
- ✅ **Reliable delivery** (QUIC guarantees in-order, lossless transmission)
- ✅ **Encrypted** (TLS 1.3)
- ✅ **Multiplexed** (multiple packets can be in-flight)

---

### Step 6: De-framing (Relay Server)

The Relay reads the stream and extracts the packet:

```go
// masque-relay/main.go (handleMasqueRequest goroutine)

// Read length prefix
lenBuf := make([]byte, 2)
io.ReadFull(r.Body, lenBuf)
plen := binary.BigEndian.Uint16(lenBuf)  // 84

// Read packet payload
packetBuf := make([]byte, 2000)
io.ReadFull(r.Body, packetBuf[:plen])  // Read exactly 84 bytes
```

Now the Relay has the **original IP packet** (10.100.0.2 → 8.8.8.8).

---

### Step 7: TUN Write (Relay Server)

The Relay writes the packet to its TUN interface:

```go
tun.Write(packetBuf[:plen])
```

The Linux kernel receives the packet on `tun0`:

```
┌─────────────────────────────────────┐
│ IPv4 Header                         │
│  - Source IP: 10.100.0.2 ← Client  │
│  - Dest IP: 8.8.8.8     ← Internet │
│  - Protocol: ICMP                   │
└─────────────────────────────────────┘
```

---

### Step 8: NAT Translation (Relay Container)

The kernel applies **iptables NAT rules** (configured in `entrypoint.sh`):

```bash
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

**Before NAT:**
```
Source: 10.100.0.2  (Client's virtual IP)
Dest:   8.8.8.8     (Google DNS)
```

**After NAT:**
```
Source: 172.28.0.10  (Relay's Docker IP)
Dest:   8.8.8.8      (Google DNS)
```

The NAT table stores a **connection tracking entry**:
```
10.100.0.2:12345 ↔ 8.8.8.8:echo-request
    mapped to
172.28.0.10:54321 ↔ 8.8.8.8:echo-request
```

---

### Step 9: Forwarding to Internet (Relay → 8.8.8.8)

The packet is sent via the Relay's `eth0` interface to the Docker bridge, then to the host, and finally to the Internet:

```
Relay eth0 → Docker Bridge → Host → Internet Router → 8.8.8.8
```

Google's DNS server (8.8.8.8) receives:

```
┌─────────────────────────────────────┐
│ IPv4 Header                         │
│  - Source IP: 172.28.0.10 (Relay)  │
│  - Dest IP: 8.8.8.8                 │
│  - Protocol: ICMP                   │
├─────────────────────────────────────┤
│ ICMP Echo Request                   │
└─────────────────────────────────────┘
```

---

## Return Path: ICMP Echo Reply

### Step 10: Internet Response (8.8.8.8 → Relay)

Google sends back an **ICMP Echo Reply**:

```
┌─────────────────────────────────────┐
│ IPv4 Header                         │
│  - Source IP: 8.8.8.8              │
│  - Dest IP: 172.28.0.10 (Relay)    │
│  - Protocol: ICMP                   │
├─────────────────────────────────────┤
│ ICMP Echo Reply                     │
│  - Type: 0 (Echo Reply)             │
└─────────────────────────────────────┘
```

---

### Step 11: NAT Reverse Translation (Relay)

The kernel looks up the **NAT tracking table** and translates:

**Before (from Internet):**
```
Source: 8.8.8.8
Dest:   172.28.0.10:54321
```

**After (to TUN):**
```
Source: 8.8.8.8
Dest:   10.100.0.2  (Client's virtual IP)
```

The kernel routes the packet to `tun0` (because 10.100.0.2 is in the tun0 subnet).

---

### Step 12: TUN Read (Relay Server)

The Relay's background goroutine reads from TUN:

```go
// masque-relay/main.go (handleTunRead)
n, err := tun.Read(buf)
```

The packet is:

```
┌─────────────────────────────────────┐
│ IPv4 Header                         │
│  - Source IP: 8.8.8.8              │
│  - Dest IP: 10.100.0.2 (Client)    │
│  - Protocol: ICMP                   │
├─────────────────────────────────────┤
│ ICMP Echo Reply                     │
└─────────────────────────────────────┘
```

---

### Step 13: Session Lookup & Routing (Relay)

The Relay uses **gopacket** to extract the destination IP:

```go
packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
    ip, _ := ipLayer.(*layers.IPv4)
    dstIP = ip.DstIP  // 10.100.0.2
}
```

It looks up the **session map**:

```go
if val, ok := sessionMap.Load(dstIP.String()); ok {
    pw := val.(*io.PipeWriter)
    pw.Write(raw)  // Write raw packet to pipe
}
```

The `sessionMap` stores:
```
"10.100.0.2" → *io.PipeWriter (connected to HTTP response stream)
```

---

### Step 14: Framing & Stream Write (Relay → Client)

The Relay's response goroutine reads from the pipe and frames the packet:

```go
// Read from pipe (written by handleTunRead)
n, err := pr.Read(buf)

// Write length prefix
binary.Write(w, binary.BigEndian, uint16(n))

// Write packet
w.Write(buf[:n])

// Flush HTTP response
if f, ok := w.(http.Flusher); ok {
    f.Flush()
}
```

The HTTP/3 stream now carries:

```
┌──────┬────────────────────────────────┐
│ 0x00 │ Length: 0x0054 (84 bytes)      │
├──────┼────────────────────────────────┤
│ 0x02 │ IP Packet (8.8.8.8 → Client)   │
└──────┴────────────────────────────────┘
```

---

### Step 15: QUIC Transport (Relay → Client)

The packet travels back over the **same HTTP/3 bidirectional stream**:

```
Relay                                  Client
  |                                      |
  | [0x00 0x54][84-byte IP packet]       |
  |=====================================>|
  |                                      |
```

---

### Step 16: De-framing & TUN Write (Client App)

The Client reads from the HTTP response stream:

```go
// Read length
io.ReadFull(resp.Body, lenBuf)
plen := binary.BigEndian.Uint16(lenBuf)  // 84

// Read packet
io.ReadFull(resp.Body, pBuf[:plen])

// Write to TUN
iface.Write(pBuf[:plen])
```

---

### Step 17: OS Delivery (Client Container)

The Linux kernel receives the packet on `tun0`:

```
┌─────────────────────────────────────┐
│ IPv4 Header                         │
│  - Source IP: 8.8.8.8              │
│  - Dest IP: 10.100.0.2 (local)     │
│  - Protocol: ICMP                   │
├─────────────────────────────────────┤
│ ICMP Echo Reply                     │
└─────────────────────────────────────┘
```

The kernel delivers the packet to the **waiting ping process**:

```bash
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=15.2 ms
```

---

## Summary: Complete Round Trip

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│  Ping   │   │  TUN    │   │  QUIC   │   │  TUN    │   ┌──────────┐
│  App    ├──►│ (Client)├──►│ Tunnel  ├──►│ (Relay) ├──►│ Internet │
└─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────┬────┘
     ▲                                                          │
     │        ┌─────────┐   ┌─────────┐   ┌─────────┐          │
     └────────┤  TUN    │◄──┤  QUIC   │◄──┤  TUN    │◄─────────┘
              │ (Client)│   │ Tunnel  │   │ (Relay) │
              └─────────┘   └─────────┘   └─────────┘
```

### Key Components

| Component | Role |
|-----------|------|
| **TUN Interface** | Virtual network device that captures/injects IP packets |
| **Length-Prefix Framing** | Preserves packet boundaries in TCP-like stream |
| **HTTP/3 CONNECT** | Establishes bidirectional stream for tunnel |
| **QUIC** | Provides encryption, multiplexing, and reliability |
| **io.Pipe** | Connects TUN reader to HTTP response writer |
| **NAT (iptables)** | Translates internal IPs to routable IPs |
| **Session Map** | Routes return packets to correct client connection |

---

## Performance Characteristics

| Metric | Value | Note |
|--------|-------|------|
| **Reliability** | 100% | QUIC guarantees delivery |
| **Packet Loss** | 0% | Automatic retransmission |
| **RTT Overhead** | ~10-15ms | Compared to direct routing |
| **Head-of-Line Blocking** | Possible | Minor impact for VPN use case |
| **Encryption** | TLS 1.3 | All traffic encrypted |

---

## Framing Format

### Upstream (Client → Relay)

```
┌────────────┬──────────────────────────────────┐
│ Length (2) │ IP Packet (variable)             │
│ Big-endian │ - IPv4/IPv6 Header               │
│            │ - Transport Layer (TCP/UDP/ICMP) │
│            │ - Application Data               │
└────────────┴──────────────────────────────────┘
```

### Downstream (Relay → Client)

```
┌────────────┬──────────────────────────────────┐
│ Length (2) │ IP Packet (variable)             │
│ Big-endian │ - Modified by NAT                │
│            │ - Return traffic                 │
└────────────┴──────────────────────────────────┘
```

**Maximum Packet Size:** 2000 bytes (larger than typical MTU of 1500)

---

## Debugging Tips

### 1. Check TUN Interface Status
```bash
# Client container
docker compose exec client ip addr show tun0
docker compose exec client ip route show

# Relay container
docker compose exec relay ip addr show tun0
```

### 2. Monitor Packet Flow
```bash
# Enable debug logging in Go code
log.Printf("TUN Read: %d bytes", n)
log.Printf("Routing to %s", dstIP)
```

### 3. Verify NAT Rules
```bash
docker compose exec relay iptables -t nat -L -n -v
```

### 4. Test Connectivity
```bash
# From client container
docker compose exec client ping -c 4 8.8.8.8
docker compose exec client traceroute 8.8.8.8
```

---

## References

- [RFC 9484 - Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [TUN/TAP Interfaces (Linux Kernel)](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
- [quic-go HTTP/3 Server Documentation](https://github.com/quic-go/quic-go)
