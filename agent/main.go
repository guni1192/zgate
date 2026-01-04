// main.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
)

// 設定定数
const (
	MTU        = 1300
	TargetCIDR = "0.0.0.0/1,128.0.0.0/1" // Route all traffic through TUN (split into two halves to avoid default route conflict)
)

// 環境変数から取得、なければデフォルト (macOSローカル用)
var RelayURL = getEnv("RELAY_URL", "https://127.0.0.1:4433/")

func main() {
	// 1. OSごとの TUN 設定を取得 (net_*.go で定義)
	config := getWaterConfig()

	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("TUN作成失敗: %v", err)
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

	// 4. HTTP/3 Transport (共通)
	tr := &http3.Transport{
		TLSClientConfig: tlsConfig,
		// QuicConfig:      &quic.Config{KeepAlivePeriod: 10 * time.Second},
		EnableDatagrams: true,
	}
	defer tr.Close()

	client := &http.Client{Transport: tr, Timeout: 0}

	// 4. トンネルループ
	for {
		err := startStreamTunnel(client, iface)
		log.Printf("トンネル切断: %v. 3秒後に再接続...", err)
		time.Sleep(3 * time.Second)
	}
}

// startStreamTunnel (共通ロジック)
func startStreamTunnel(client *http.Client, iface *water.Interface) error {
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, RelayURL, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Protocol", "connect-ip")

	// Upstream: TUN -> Request Body
	go func() {
		defer pw.Close()
		buf := make([]byte, 2000)
		for {
			n, err := iface.Read(buf)
			if err != nil {
				return
			}
			// ログ出力 (簡易版)
			// logPacketDetails(buf[:n])

			binary.Write(pw, binary.BigEndian, uint16(n))
			pw.Write(buf[:n])
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

	// Read Virtual IP configuration from response headers
	assignedIP := resp.Header.Get("Zgate-Virtual-IP")
	gatewayIP := resp.Header.Get("Zgate-Gateway-IP")

	if assignedIP == "" || gatewayIP == "" {
		return fmt.Errorf("relay did not provide Virtual IP assignment (got IP=%s, Gateway=%s)", assignedIP, gatewayIP)
	}

	// Configure TUN interface with assigned Virtual IP
	log.Printf("Assigned Virtual IP: %s, Gateway: %s", assignedIP, gatewayIP)
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
	lenBuf := make([]byte, 2)
	pBuf := make([]byte, 2000)
	for {
		if _, err := io.ReadFull(resp.Body, lenBuf); err != nil {
			return err
		}
		plen := binary.BigEndian.Uint16(lenBuf)
		if _, err := io.ReadFull(resp.Body, pBuf[:plen]); err != nil {
			return err
		}

		// ログ出力 (ICMP Type確認用)
		logPacketDetails(pBuf[:plen])

		iface.Write(pBuf[:plen])
	}
}

// ログ用ヘルパー
func logPacketDetails(data []byte) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		// エラーパケットのみ強調表示
		if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest &&
			icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
			log.Printf("[ICMP Error] Type:%d Code:%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
		} else {
			// 正常パケットはデバッグレベルで (ここではコメントアウトか適宜表示)
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
