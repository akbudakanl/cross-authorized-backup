package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

// RunListener represents Process A: The unprivileged listener inside gVisor.
// It listens on the wg-cross IP/Port, receives decrypted raw packets from the wg tunnel,
// and proxies them to the Unix socket (Process B) without parsing.
func RunListener(cfg *Config) {
	if cfg.PeerWgIP == "" || cfg.ListenWgPort == "" {
		log.Fatal("Listener mode requires PEER_WG_IP and LISTEN_WG_PORT")
	}

	// Bind strictly to the wg-cross interface IP (derived from configuration, or 0.0.0.0 if handled by gVisor netns)
	// For simplicity, we bind to all interfaces since the gVisor sandbox isolates networking to just the wg tun.
	addr := fmt.Sprintf(":%s", cfg.ListenWgPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP %s: %v", addr, err)
	}
	defer conn.Close()
	log.Printf("Process A (Listener) started on UDP %s, proxying to %s", addr, cfg.SocketPath)

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading UDP: %v", err)
			continue
		}

		// Security: IP Whitelist check. We only accept packets from the authorized peer wg-cross IP.
		if remoteAddr.IP.String() != cfg.PeerWgIP {
			log.Printf("SECURITY: Dropping packet from unauthorized IP %s (expected %s)", remoteAddr.IP.String(), cfg.PeerWgIP)
			continue
		}

		// Proxy raw bytes to Process B via Unix socket
		if err := proxyToSocket(cfg.SocketPath, buf[:n]); err != nil {
			log.Printf("Failed to proxy to socket: %v", err)
		}
	}
}

func proxyToSocket(socketPath string, data []byte) error {
	unixConn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial unix failed: %v", err)
	}
	defer unixConn.Close()

	// Write raw bytes directly. No JSON, no serialization.
	_, err = unixConn.Write(data)
	if err != nil {
		return fmt.Errorf("write unix failed: %v", err)
	}
	
	// Optionally wait for a simple OK/ERR response, but UDP is connectionless.
	// We'll just read up to 256 bytes for logging.
	respBuf := make([]byte, 256)
	n, _ := unixConn.Read(respBuf)
	if n > 0 {
		log.Printf("Process B replied: %s", string(respBuf[:n]))
	}

	return nil
}
