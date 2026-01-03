package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/guni1192/zgate/relay/internal"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
)

const (
	BindAddr  = "0.0.0.0:4433"
	ServerIP  = "10.100.0.1"
	ServerMTU = 1300
)

var sessionMap sync.Map

func main() {
	// OSごとの設定を取得 (internal/net_*.go)
	config := internal.GetWaterConfig()
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("TUN作成失敗: %v", err)
	}
	defer iface.Close()

	if err := internal.ConfigureInterface(iface.Name(), ServerIP, ServerMTU); err != nil {
		log.Fatalf("IF設定失敗: %v", err)
	}
	log.Printf("Relay TUN %s is UP at %s", iface.Name(), ServerIP)

	go handleTunRead(iface)

	// TLS configuration
	var tlsConfig *tls.Config
	useMTLS := os.Getenv("USE_MTLS")
	if useMTLS == "false" {
		log.Println("Using self-signed certificates (Phase 2 compatibility)")
		tlsConfig = generateTLSConfig()
	} else {
		log.Println("Loading mTLS certificates...")
		var err error
		tlsConfig, err = loadTLSConfig()
		if err != nil {
			log.Fatalf("Failed to load TLS config: %v", err)
		}
		log.Println("mTLS enabled - client certificate verification required")
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
		// QuicConfig:      &quic.Config{KeepAlivePeriod: 10 * time.Second},
	}

	log.Printf("Listening on QUIC %s", BindAddr)
	log.Fatal(server.ListenAndServe())
}

// handleMasqueRequest: クライアント接続ごとの処理
func handleMasqueRequest(w http.ResponseWriter, r *http.Request, tun *water.Interface) {
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// クライアントID抽出（mTLS証明書のCNから）
	clientID := extractClientID(r)

	// 今回は簡易的に Client IP を決め打ち、もしくはヘッダから取る想定
	// 本来は IPAM (IP Address Management) で動的に割り当てる
	clientVirtualIP := "10.100.0.2"

	log.Printf("Client connected: %s (CN: %s), Assigning Virtual IP: %s", r.RemoteAddr, clientID, clientVirtualIP)

	// ダウンストリーム用のパイプを作成
	// TUN Reader (別ゴルーチン) がここに書き込み、HTTP Response Body がここから読む
	pr, pw := io.Pipe()

	// セッション登録
	sessionMap.Store(clientVirtualIP, pw)
	defer func() {
		sessionMap.Delete(clientVirtualIP)
		pw.Close()
		log.Printf("Client disconnected: %s", clientVirtualIP)
	}()

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// --- 読み書きの並行処理 ---

	// Error channel
	errChan := make(chan error, 2)

	// A. Upstream: Request Body -> TUN (Clientから来たパケットをOSへ)
	go func() {
		lenBuf := make([]byte, 2)
		packetBuf := make([]byte, 2000)
		for {
			// Length Header
			if _, err := io.ReadFull(r.Body, lenBuf); err != nil {
				errChan <- err
				return
			}
			plen := binary.BigEndian.Uint16(lenBuf)

			// Payload
			if _, err := io.ReadFull(r.Body, packetBuf[:plen]); err != nil {
				errChan <- err
				return
			}

			// TUNへ書き込み (OSがルーティング処理を行う)
			_, err := tun.Write(packetBuf[:plen])
			if err != nil {
				log.Printf("TUN Write Error: %v", err)
			}
		}
	}()

	// B. Downstream: Pipe -> Response Body (OSから来たパケットをClientへ)
	// handleTunRead が pw に書き込んだデータを、HTTP レスポンスとして送り返す
	go func() {
		buf := make([]byte, 2000)
		for {
			// パイプから読む (パケット単位で書き込まれている想定)
			n, err := pr.Read(buf)
			if err != nil {
				errChan <- err
				return
			}

			// Length Prefix を付けて HTTP Response Body へ
			binary.Write(w, binary.BigEndian, uint16(n))
			_, err = w.Write(buf[:n])
			if err != nil {
				errChan <- err
				return
			}

			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}()

	// どちらかが終了したら接続終了
	<-errChan
}

// handleTunRead: TUNから読み出し、宛先IPを見て適切なセッションへ配送
func handleTunRead(tun *water.Interface) {
	buf := make([]byte, 2000)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			log.Printf("TUN Read Error: %v", err)
			continue
		}
		raw := buf[:n]

		// gopacketで宛先IP解析
		// TUNからはEthernetヘッダなしでIPパケットが来る
		// (IPv4/IPv6判定は簡易実装)
		version := raw[0] >> 4
		var dstIP net.IP

		if version == 4 {
			packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				dstIP = ip.DstIP
			}
		} else {
			continue // 今回はIPv4のみ
		}

		if dstIP == nil {
			continue
		}

		// セッション検索
		if val, ok := sessionMap.Load(dstIP.String()); ok {
			// パイプへ書き込み
			pw := val.(*io.PipeWriter)
			// 注意: ここで binary.Write せず、生データを渡す。
			// Length Prefix は Response Body に書く段階で付与する。
			pw.Write(raw)
			log.Printf("[Relay] Routing packet to %s (%d bytes)", dstIP, n)
		} else {
			// 宛先が見つからないパケット（例: 自分宛てや不明なクライアント）
			// log.Printf("No session for IP: %s", dstIP)
		}
	}
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
