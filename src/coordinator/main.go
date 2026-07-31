package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	isListenerMode = flag.Bool("listener", false, "Run as Process A (gVisor Listener)")
)

// Process B globals
var (
	signingKey ed25519.PrivateKey
	peerKey    ed25519.PublicKey
	cfg        *Config
)

func main() {
	flag.Parse()

	var err error
	cfg, err = LoadConfig("/etc/vault-device/coordinator.env")
	if err != nil {
		// Use a local mock config for development/testing if /etc isn't present
		log.Printf("Warning: failed to load /etc config, using fallback for testing: %v", err)
		cfg = &Config{
			Role:           "pc",
			PeerWgIP:       "127.0.0.1",
			ListenWgPort:   "8891",
			ListenTSPort:   "8889",
			SocketPath:     "/tmp/vault-coordinator.sock",
			PhaseTokenPath: "/tmp/phase-token.sha256",
		}
	}

	if *isListenerMode {
		RunListener(cfg)
		return
	}

	// Initialize Process B (Verifier)
	log.Printf("Process B (Verifier) starting as role: %s", cfg.Role)
	
	// Start local device HTTP listener (Tailscale port)
	go startLocalDeviceListener(cfg)

	// Start Unix Socket listener for peer wg-cross payloads from Process A
	startUnixSocketListener(cfg)
}

func startLocalDeviceListener(cfg *Config) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Read phase token from request
		tokenRaw, err := io.ReadAll(r.Body)
		if err != nil || len(tokenRaw) > 256 {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		token := strings.TrimSpace(string(tokenRaw))
		
		// In a real scenario, hash token and compare with cfg.PhaseTokenPath
		log.Printf("Local device requested auth with token len %d", len(token))

		// Construct custom payload: VERSION|CEREMONY_ID|TARGET|EXPIRES_AT
		// No JSON is used.
		expires := time.Now().Add(time.Hour).Unix()
		payload := fmt.Sprintf("1|CEREMONY_%d|S3_%s|%d", time.Now().UnixNano(), strings.ToUpper(cfg.Role), expires)
		
		// In a full implementation, we'd sign this and forward to the peer via wg-cross UDP
		// and wait for their signature.
		fmt.Fprintf(w, "PAYLOAD:%s|SIG:MOCK_SIG|PEER_SIG:MOCK_SIG", payload)
	})

	addr := fmt.Sprintf(":%s", cfg.ListenTSPort)
	log.Printf("Listening for local device on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Local device listener failed: %v", err)
	}
}

func startUnixSocketListener(cfg *Config) {
	os.Remove(cfg.SocketPath) // Cleanup stale socket
	listener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		log.Fatalf("Failed to listen on unix socket %s: %v", cfg.SocketPath, err)
	}
	defer listener.Close()

	// Secure the socket permissions
	os.Chmod(cfg.SocketPath, 0600)

	log.Printf("Process B listening on Unix Socket %s", cfg.SocketPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Socket accept error: %v", err)
			continue
		}
		go handleUnixConnection(conn)
	}
}

func handleUnixConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	rawPacket := buf[:n]

	// MANUAL FIXED-LENGTH/DELIMITER PARSING (No JSON)
	// Expected format: PAYLOAD_BYTES|PEER_SIGNATURE_HEX
	parts := bytes.SplitN(rawPacket, []byte("|"), 2)
	if len(parts) != 2 {
		log.Printf("SECURITY: Dropping malformed packet (missing delimiter)")
		return
	}

	payloadRaw := parts[0]
	peerSigHex := parts[1]

	peerSig, err := hex.DecodeString(string(peerSigHex))
	if err != nil || len(peerSig) != ed25519.SignatureSize {
		log.Printf("SECURITY: Invalid signature format or length")
		return
	}

	// Verify signature using ed25519.Verify(peerKey, payloadRaw, peerSig)
	// (Skipped in mock until keys are loaded)
	log.Printf("Received valid structured packet. Payload: %s", string(payloadRaw))
	
	// Send mock response
	conn.Write([]byte("ACK"))
}
