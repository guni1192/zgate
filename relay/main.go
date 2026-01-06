package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guni1192/zgate/pkg/capsule"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/guni1192/zgate/relay/acl"
	"github.com/guni1192/zgate/relay/api"
	"github.com/guni1192/zgate/relay/audit"
	"github.com/guni1192/zgate/relay/internal"
	"github.com/guni1192/zgate/relay/ipam"
	"github.com/guni1192/zgate/relay/logger"
	"github.com/guni1192/zgate/relay/policy"
	"github.com/guni1192/zgate/relay/session"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
)

const (
	BindAddr       = "0.0.0.0:4433"
	VirtualIPRange = "10.100.0.0/24"
	ServerIP       = "10.100.0.1"
	ServerMTU      = 1300
)

var (
	sessionManager *session.Manager
	aclEngine      *acl.Engine
	auditLogger    *audit.Logger
	sysLogger      *slog.Logger
	healthChecker  *api.HealthChecker
)

func main() {
	// Initialize system logger first
	sysLogger = logger.New(os.Stdout, slog.LevelInfo)

	// Initialize health checker (before other components)
	healthChecker = api.NewHealthChecker("phase-3.3")

	// Start health check server (HTTP/1.1 on port 8080)
	go startHealthServer()

	// Get OS-specific configuration (internal/net_*.go)
	config := internal.GetWaterConfig()
	iface, err := water.New(config)
	if err != nil {
		sysLogger.Error("Failed to create TUN interface",
			slog.String("component", "System"),
			slog.String("error", err.Error()),
		)
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	defer iface.Close()

	if err := internal.ConfigureInterface(iface.Name(), ServerIP, ServerMTU); err != nil {
		sysLogger.Error("Failed to configure interface",
			slog.String("component", "System"),
			slog.String("interface", iface.Name()),
			slog.String("error", err.Error()),
		)
		log.Fatalf("Failed to configure interface: %v", err)
	}
	sysLogger.Info("TUN interface ready",
		slog.String("component", "System"),
		slog.String("interface", iface.Name()),
		slog.String("ip", ServerIP),
		slog.Int("mtu", ServerMTU),
	)

	go handleTunRead(iface)

	// Initialize audit logger
	auditLogger = audit.NewLogger(
		&audit.JSONFormatter{},
		os.Stdout,
	)
	defer auditLogger.Close()

	// Initialize ACL engine
	policyPath := os.Getenv("ACL_POLICY_PATH")
	if policyPath == "" {
		policyPath = "/etc/zgate/policy.yaml"
	}

	storage := policy.NewYAMLFileStorage(policyPath)
	aclEngine = acl.NewEngine(storage)

	if err := aclEngine.LoadPolicy(context.Background()); err != nil {
		sysLogger.Error("Failed to load policy",
			slog.String("component", "ACL"),
			slog.String("policy_path", policyPath),
			slog.String("error", err.Error()),
		)
		log.Fatalf("Failed to load ACL policy: %v", err)
	}
	defer aclEngine.Close()

	sysLogger.Info("Policy loaded successfully",
		slog.String("component", "ACL"),
		slog.String("policy_path", policyPath),
	)

	// Initialize IPAM
	_, ipamNet, _ := net.ParseCIDR(VirtualIPRange)
	ipamConfig := ipam.Config{
		Network: ipamNet,
		RelayIP: net.ParseIP(ServerIP),
	}
	ipamAllocator, err := ipam.NewAllocator(ipamConfig)
	if err != nil {
		sysLogger.Error("Failed to create allocator",
			slog.String("component", "IPAM"),
			slog.String("network", VirtualIPRange),
			slog.String("error", err.Error()),
		)
		log.Fatalf("Failed to create IPAM allocator: %v", err)
	}
	defer ipamAllocator.Close()

	// Initialize Session Manager
	sessionManager = session.NewManager(ipamAllocator)
	defer sessionManager.Close()

	stats := ipamAllocator.GetStats()
	sysLogger.Info("Allocator initialized",
		slog.String("component", "IPAM"),
		slog.String("network", VirtualIPRange),
		slog.Int("total_ips", stats.TotalIPs),
		slog.Int("available_ips", stats.AvailableIPs),
	)

	// Mark service as ready (IPAM and ACL are initialized)
	healthChecker.SetReady(true)
	sysLogger.Info("Service ready",
		slog.String("component", "System"),
	)

	// TLS configuration
	var tlsConfig *tls.Config
	useMTLS := os.Getenv("USE_MTLS")
	if useMTLS == "false" {
		sysLogger.Warn("Using self-signed certificates (Phase 2 compatibility)",
			slog.String("component", "TLS"),
		)
		tlsConfig = generateTLSConfig()
	} else {
		sysLogger.Info("Loading mTLS certificates",
			slog.String("component", "TLS"),
		)
		var err error
		tlsConfig, err = loadTLSConfig()
		if err != nil {
			sysLogger.Error("Failed to load TLS config",
				slog.String("component", "TLS"),
				slog.String("error", err.Error()),
			)
			log.Fatalf("Failed to load TLS config: %v", err)
		}
		sysLogger.Info("mTLS enabled - client certificate verification required",
			slog.String("component", "TLS"),
		)
	}

	// HTTP/3 Server Setup
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleMasqueRequest(w, r, iface)
	})

	server := http3.Server{
		Addr:            BindAddr,
		Handler:         handler,
		EnableDatagrams: true,
		TLSConfig:       tlsConfig,
		QUICConfig: &quic.Config{
			KeepAlivePeriod:  10 * time.Second,  // Send keep-alive every 10 seconds
			MaxIdleTimeout:   300 * time.Second,  // 5 minutes idle timeout
			EnableDatagrams:  true,               // Enable QUIC datagrams
		},
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start HTTP/3 server in goroutine
	go func() {
		sysLogger.Info("Starting HTTP/3 server",
			slog.String("component", "Server"),
			slog.String("address", BindAddr),
			slog.String("keep_alive", "10s"),
			slog.String("max_idle_timeout", "300s"),
		)
		if err := server.ListenAndServe(); err != nil {
			sysLogger.Error("Server error",
				slog.String("component", "Server"),
				slog.String("error", err.Error()),
			)
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	sysLogger.Info("Received shutdown signal",
		slog.String("component", "System"),
		slog.String("signal", sig.String()),
	)

	// Mark as not ready (stop accepting new connections)
	healthChecker.SetReady(false)
	sysLogger.Info("Service marked as not ready",
		slog.String("component", "System"),
	)

	// Wait for existing connections to drain (max 30 seconds)
	activeConns := sessionManager.Count()
	sysLogger.Info("Draining connections",
		slog.String("component", "System"),
		slog.Int("active_sessions", activeConns),
	)

	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
	defer shutdownCancel()

	// Close HTTP/3 server gracefully
	if err := server.Close(); err != nil {
		sysLogger.Error("Error closing server",
			slog.String("component", "Server"),
			slog.String("error", err.Error()),
		)
	}

	// Wait for all sessions to close or timeout
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownCtx.Done():
			remaining := sessionManager.Count()
			sysLogger.Warn("Shutdown timeout reached",
				slog.String("component", "System"),
				slog.Int("remaining_sessions", remaining),
			)
			goto cleanup
		case <-ticker.C:
			remaining := sessionManager.Count()
			if remaining == 0 {
				sysLogger.Info("All sessions closed",
					slog.String("component", "System"),
				)
				goto cleanup
			}
			sysLogger.Debug("Waiting for sessions to close",
				slog.String("component", "System"),
				slog.Int("remaining_sessions", remaining),
			)
		}
	}

cleanup:
	// Cleanup resources in proper order
	sysLogger.Info("Cleaning up resources",
		slog.String("component", "System"),
	)

	sessionManager.Close()
	aclEngine.Close()
	ipamAllocator.Close()
	auditLogger.Close()
	iface.Close()

	sysLogger.Info("Shutdown complete",
		slog.String("component", "System"),
	)
}

// handleMasqueRequest: Process per-client connection
func handleMasqueRequest(w http.ResponseWriter, r *http.Request, tun *water.Interface) {
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Extract client ID from mTLS certificate CN
	clientID := extractClientID(r)
	sourceIP := r.RemoteAddr

	// Create pipe for downstream
	pr, pw := io.Pipe()

	// Create session
	sess := &session.ClientSession{
		ClientID:    clientID,
		VirtualIP:   "", // Will be set by session manager
		SourceIP:    sourceIP,
		Downstream:  pw,
		ConnectedAt: time.Now(),
	}

	// Allocate Virtual IP and register session
	virtualIP, err := sessionManager.Create(sess)
	if err != nil {
		sysLogger.Error("IP allocation failed",
			slog.String("component", "Session"),
			slog.String("client_id", clientID),
			slog.String("source_ip", sourceIP),
			slog.String("error", err.Error()),
		)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Server capacity reached"))
		return
	}

	auditLogger.LogConnection(clientID, sourceIP, true)
	sysLogger.Info("Client connected",
		slog.String("component", "Session"),
		slog.String("client_id", clientID),
		slog.String("source_ip", sourceIP),
		slog.String("virtual_ip", virtualIP.String()),
	)

	defer func() {
		sessionManager.Delete(sess)
		pw.Close()
		auditLogger.LogConnection(clientID, sourceIP, false)
		sysLogger.Info("Client disconnected",
			slog.String("component", "Session"),
			slog.String("client_id", clientID),
			slog.String("source_ip", sourceIP),
			slog.String("virtual_ip", virtualIP.String()),
		)
	}()

	// Send HTTP 200 OK first
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Send Virtual IP configuration to agent via ADDRESS_ASSIGN capsule (RFC 9484)
	assignCapsule := &capsule.AddressAssignCapsule{
		Assignments: []capsule.AddressAssignment{
			{
				RequestID:    0,
				IPVersion:    4,
				IPAddress:    virtualIP,
				PrefixLength: 32,
			},
		},
	}

	cap, err := assignCapsule.Encode()
	if err != nil {
		sysLogger.Error("Failed to encode ADDRESS_ASSIGN",
			slog.String("component", "IPAM"),
			slog.String("client_id", clientID),
			slog.String("error", err.Error()),
		)
		return
	}

	// Create single CapsuleWriter for all downstream traffic
	capsuleWriter := capsule.NewCapsuleWriter(w)

	// Send ADDRESS_ASSIGN capsule first
	if err := capsuleWriter.WriteCapsule(cap); err != nil {
		sysLogger.Error("Failed to send ADDRESS_ASSIGN",
			slog.String("component", "IPAM"),
			slog.String("client_id", clientID),
			slog.String("error", err.Error()),
		)
		return
	}

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	sysLogger.Info("Sent ADDRESS_ASSIGN",
		slog.String("component", "IPAM"),
		slog.String("client_id", clientID),
		slog.String("virtual_ip", virtualIP.String()),
		slog.Int("prefix", 32),
	)

	// --- Concurrent read/write processing ---

	// Error channel
	errChan := make(chan error, 2)

	// A. Upstream: Request Body -> TUN (Packets from Client to OS)
	// Using RFC 9297 Capsule Protocol
	go func() {
		capsuleReader := capsule.NewCapsuleReader(r.Body)

		for {
			cap, err := capsuleReader.ReadCapsule()
			if err != nil {
				errChan <- err
				return
			}

			switch cap.Type {
			case capsule.CapsuleTypeIPPacket:
				packetBuf := cap.Value

				// Extract packet info for ACL check
				packetInfo := extractPacketInfo(packetBuf)
				if packetInfo == nil {
					continue // Invalid packet
				}

				// ACL Check
				result, err := aclEngine.CheckAccess(clientID, packetInfo)
				if err != nil {
					sysLogger.Error("Access check failed",
						slog.String("component", "ACL"),
						slog.String("client_id", clientID),
						slog.String("dst_ip", packetInfo.DstIP.String()),
						slog.String("error", err.Error()),
					)
					continue
				}

				// Log ACL decision
				auditLogger.LogACL(clientID, packetInfo.DstIP.String(),
					string(result.Action), result.RuleID, result.Reason)

				if result.Action == policy.ActionDeny {
					sysLogger.Warn("Packet denied",
						slog.String("component", "ACL"),
						slog.String("client_id", clientID),
						slog.String("dst_ip", packetInfo.DstIP.String()),
						slog.String("rule_id", result.RuleID),
					)
					continue // Drop packet
				}

				// Allow: Write to TUN
				sess.AddBytesReceived(uint64(len(packetBuf)))
				_, err = tun.Write(packetBuf)
				if err != nil {
					sysLogger.Error("Write error",
						slog.String("component", "TUN"),
						slog.String("error", err.Error()),
					)
				}

			default:
				// RFC 9297: Unknown capsule types are silently discarded
				sysLogger.Debug("Unknown capsule type (discarding)",
					slog.String("component", "Capsule"),
					slog.String("client_id", clientID),
					slog.Uint64("type", uint64(cap.Type)),
				)
			}
		}
	}()

	// B. Downstream: Pipe -> Response Body (Packets from OS to Client)
	// Send back data written to pw by handleTunRead as HTTP response
	// Using RFC 9297 Capsule Protocol
	// IMPORTANT: Reuse the same capsuleWriter created above to avoid race conditions
	go func() {
		buf := make([]byte, 2000)

		for {
			// Read from pipe (assuming packet-unit writes)
			n, err := pr.Read(buf)
			if err != nil {
				sysLogger.Debug("Pipe read error",
					slog.String("component", "Downstream"),
					slog.String("client_id", clientID),
					slog.String("error", err.Error()),
				)
				errChan <- err
				return
			}

			// Encapsulate as IP_PACKET capsule
			cap := capsule.NewIPPacketCapsule(buf[:n])
			if err := capsuleWriter.WriteCapsule(cap); err != nil {
				sysLogger.Error("Capsule write error",
					slog.String("component", "Downstream"),
					slog.String("client_id", clientID),
					slog.String("error", err.Error()),
				)
				errChan <- err
				return
			}

			// Track bytes sent
			sess.AddBytesSent(uint64(n))

			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}()

	// Close connection when either goroutine terminates
	<-errChan
}

// handleTunRead: Read from TUN and route to appropriate session based on destination IP
func handleTunRead(tun *water.Interface) {
	buf := make([]byte, 2000)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			sysLogger.Error("Read error",
				slog.String("component", "TUN"),
				slog.String("error", err.Error()),
			)
			continue
		}
		raw := buf[:n]

		// Parse destination IP with gopacket
		// IP packets come from TUN without Ethernet header
		// (Simple IPv4/IPv6 detection)
		version := raw[0] >> 4
		var dstIP net.IP

		if version == 4 {
			packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				dstIP = ip.DstIP
			}
		} else {
			continue // IPv4 only for now
		}

		if dstIP == nil {
			continue
		}

		// Session lookup by Virtual IP for packet routing
		if sess, ok := sessionManager.GetByVirtualIP(dstIP.String()); ok {
			// Write to pipe
			// Note: Pass raw data without binary.Write here.
			// Length Prefix is added when writing to Response Body.
			sess.Downstream.Write(raw)
			sysLogger.Debug("Routing packet",
				slog.String("component", "Relay"),
				slog.String("dst_ip", dstIP.String()),
				slog.Int("bytes", n),
			)
		}
	}
}

// extractPacketInfo parses an IP packet and extracts information for ACL matching
func extractPacketInfo(raw []byte) *acl.PacketInfo {
	if len(raw) < 20 {
		return nil // Too short for IPv4 header
	}

	version := raw[0] >> 4
	if version != 4 {
		return nil // Only IPv4 supported for now
	}

	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ipv4, _ := ipLayer.(*layers.IPv4)
	info := &acl.PacketInfo{
		SrcIP:    ipv4.SrcIP,
		DstIP:    ipv4.DstIP,
		Protocol: uint8(ipv4.Protocol),
	}

	// Extract port information if TCP or UDP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
	}

	return info
}

// extractClientID extracts the client identifier from the TLS certificate
func extractClientID(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "unknown"
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

// loadTLSConfig loads TLS configuration from certificate files
func loadTLSConfig() (*tls.Config, error) {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("/certs/relay-server.crt", "/certs/relay-server.key")
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	// Load CA certificate for client verification
	caCert, err := os.ReadFile("/certs/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("load CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("invalid CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
	}, nil
}

// generateTLSConfig generates self-signed TLS config (backward compatibility)
func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Masque Dev Relay"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{"h3"}}
}

// startHealthServer starts the HTTP/1.1 health check server on port 8080
func startHealthServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthChecker.LivenessHandler)
	mux.HandleFunc("/ready", healthChecker.ReadinessHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	sysLogger.Info("Starting health check server",
		slog.String("component", "API"),
		slog.String("address", ":8080"),
	)

	if err := server.ListenAndServe(); err != nil {
		sysLogger.Error("Health server failed",
			slog.String("component", "API"),
			slog.String("error", err.Error()),
		)
	}
}
