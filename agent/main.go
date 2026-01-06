// main.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/guni1192/zgate/pkg/capsule"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
)

// Configuration constants
const (
	MTU        = 1300
	TargetCIDR = "0.0.0.0/1,128.0.0.0/1" // Route all traffic through TUN (split into two halves to avoid default route conflict)
)

// Get from environment variable, or use default (for macOS local)
var RelayURL = getEnv("RELAY_URL", "https://127.0.0.1:4433/")

func main() {
	// 1. Get OS-specific TUN configuration (defined in net_*.go)
	config := getWaterConfig()

	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	defer iface.Close()

	log.Printf("TUN %s created. Target: %s via %s", iface.Name(), TargetCIDR, RelayURL)
	log.Println("Waiting for Virtual IP assignment from Relay...")

	// 3. TLS Configuration
	var tlsConfig *tls.Config
	useMTLS := os.Getenv("USE_MTLS")
	if useMTLS == "false" {
		log.Println("Using insecure TLS (Phase 2 compatibility)")
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		log.Println("Loading mTLS certificates...")
		clientID := getEnv("CLIENT_ID", "client-1")

		// Load client certificate
		cert, err := tls.LoadX509KeyPair(
			fmt.Sprintf("/certs/%s.crt", clientID),
			fmt.Sprintf("/certs/%s.key", clientID),
		)
		if err != nil {
			log.Fatalf("Failed to load client cert: %v", err)
		}

		// Load CA certificate
		caCert, err := os.ReadFile("/certs/ca.crt")
		if err != nil {
			log.Fatalf("Failed to load CA cert: %v", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			log.Fatalf("Invalid CA certificate")
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
		}
		log.Printf("mTLS enabled with client ID: %s", clientID)
	}

	// 4. HTTP/3 Transport (shared)
	tr := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			KeepAlivePeriod: 10 * time.Second,   // Send keep-alive every 10 seconds
			MaxIdleTimeout:  300 * time.Second,   // 5 minutes idle timeout
		},
		EnableDatagrams: true,
	}
	defer tr.Close()

	client := &http.Client{Transport: tr, Timeout: 0}

	// 4. Tunnel loop
	for {
		err := startStreamTunnel(client, iface)
		log.Printf("Tunnel disconnected: %v. Reconnecting in 3 seconds...", err)
		time.Sleep(3 * time.Second)
	}
}

// startStreamTunnel (shared logic)
func startStreamTunnel(client *http.Client, iface *water.Interface) error {
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, RelayURL, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Protocol", "connect-ip")

	// Upstream: TUN -> Request Body
	// Using RFC 9297 Capsule Protocol
	go func() {
		defer pw.Close()
		buf := make([]byte, 2000)
		capsuleWriter := capsule.NewCapsuleWriter(pw)

		for {
			n, err := iface.Read(buf)
			if err != nil {
				return
			}
			// Log output (simplified)
			// logPacketDetails(buf[:n])

			// Encapsulate as IP_PACKET capsule
			cap := capsule.NewIPPacketCapsule(buf[:n])
			if err := capsuleWriter.WriteCapsule(cap); err != nil {
				log.Printf("[Agent] Capsule send error: %v", err)
				return
			}
		}
	}()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status: %s", resp.Status)
	}

	// Read Virtual IP configuration from ADDRESS_ASSIGN capsule (RFC 9484)
	capsuleReader := capsule.NewCapsuleReader(resp.Body)

	// Read first capsule (must be ADDRESS_ASSIGN)
	cap, err := capsuleReader.ReadCapsule()
	if err != nil {
		return fmt.Errorf("read ADDRESS_ASSIGN capsule: %w", err)
	}

	if cap.Type != capsule.CapsuleTypeAddressAssign {
		return fmt.Errorf("expected ADDRESS_ASSIGN (type %d), got type %d", capsule.CapsuleTypeAddressAssign, cap.Type)
	}

	assign, err := capsule.DecodeAddressAssign(cap)
	if err != nil {
		return fmt.Errorf("decode ADDRESS_ASSIGN: %w", err)
	}

	if len(assign.Assignments) == 0 {
		return fmt.Errorf("no IP assignments in ADDRESS_ASSIGN capsule")
	}

	firstAssign := assign.Assignments[0]
	assignedIP := firstAssign.IPAddress.String()
	gatewayIP := "10.100.0.1" // Hard-coded for now (Phase 3.3: ROUTE_ADVERTISEMENT)

	// Configure TUN interface with assigned Virtual IP
	log.Printf("Assigned Virtual IP: %s/%d, Gateway: %s", assignedIP, firstAssign.PrefixLength, gatewayIP)
	if err := configureInterface(iface.Name(), assignedIP, gatewayIP, MTU); err != nil {
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	// Add routes for target CIDRs via gateway
	cidrs := strings.Split(TargetCIDR, ",")
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if err := addRoute(cidr, gatewayIP, iface.Name()); err != nil {
			return fmt.Errorf("failed to add route for %s: %w", cidr, err)
		}
		log.Printf("Added route: %s via %s dev %s", cidr, gatewayIP, iface.Name())
	}

	log.Printf("TUN %s configured with Virtual IP %s", iface.Name(), assignedIP)

	log.Println("--- Tunnel Established! ---")

	// Downstream: Response Body -> TUN
	// capsuleReader already created above
	for {
		cap, err := capsuleReader.ReadCapsule()
		if err != nil {
			return err
		}

		switch cap.Type {
		case capsule.CapsuleTypeIPPacket:
			// Log output (for ICMP Type verification)
			logPacketDetails(cap.Value)

			iface.Write(cap.Value)

		case capsule.CapsuleTypeRouteAdvertisement:
			log.Printf("[Agent] ROUTE_ADVERTISEMENT (not implemented)")

		default:
			// RFC 9297: Unknown capsule types are silently discarded
			log.Printf("[Agent] Unknown capsule type %d (discarding)", cap.Type)
		}
	}
}

// Helper for logging
func logPacketDetails(data []byte) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		// Display only error packets
		if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest &&
			icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
			log.Printf("[ICMP Error] Type:%d Code:%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
		} else {
			// Normal packets at debug level (commented out or displayed as needed)
			// log.Printf("ICMP Echo Type:%d", icmp.TypeCode.Type())
		}
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
