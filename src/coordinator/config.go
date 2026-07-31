package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Role            string
	PeerWgIP        string
	ListenWgPort    string
	ListenTSPort    string
	SocketPath      string
	PhaseTokenPath  string
	SigningKeyPath  string
	PeerKeyPath     string
}

// LoadConfig parses a simple .env file manually without external dependencies.
func LoadConfig(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat config file: %v", err)
	}

	// Security: check if file permissions are too open.
	// We expect 0640, 0600, or 0400. If other users can write to it, fail.
	perm := info.Mode().Perm()
	if perm&0022 != 0 {
		return nil, fmt.Errorf("security violation: config file %s is writable by group or others (perms: %04o)", path, perm)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "VAULT_ROLE":
			cfg.Role = val
		case "PEER_WG_IP":
			cfg.PeerWgIP = val
		case "LISTEN_WG_PORT":
			cfg.ListenWgPort = val
		case "LISTEN_TS_PORT":
			cfg.ListenTSPort = val
		case "SOCKET_PATH":
			cfg.SocketPath = val
		case "PHASE_TOKEN_PATH":
			cfg.PhaseTokenPath = val
		case "SIGNING_KEY_PATH":
			cfg.SigningKeyPath = val
		case "PEER_KEY_PATH":
			cfg.PeerKeyPath = val
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if cfg.Role == "" || cfg.SocketPath == "" {
		return nil, errors.New("missing essential configuration (VAULT_ROLE or SOCKET_PATH)")
	}

	return cfg, nil
}
