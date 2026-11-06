package relay

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"mmft.dev/mmft/internal/relayticket"
)

// DefaultListen is the relay's default listen address.
const DefaultListen = ":7445"

// FromEnv reads a relay's settings as `mmft-relay serve` takes them:
// MMFT_RELAY_DIR holds its identity, MMFT_CONNECTION_CA is the path to the
// orchestrator's connection CA certificate, MMFT_RELAY_TICKET_KEY is the
// ticket public key in hex, and MMFT_RELAY_LISTEN the listen address. It
// returns the configuration and the address.
func FromEnv(getenv func(string) string) (Config, string, error) {
	dir := getenv("MMFT_RELAY_DIR")
	if dir == "" {
		return Config{}, "", errors.New("MMFT_RELAY_DIR is not set")
	}
	identity, err := LoadIdentity(dir)
	if err != nil {
		return Config{}, "", err
	}
	ca, err := connectionCA(getenv("MMFT_CONNECTION_CA"))
	if err != nil {
		return Config{}, "", err
	}
	key, err := relayticket.ParsePublicKey(getenv("MMFT_RELAY_TICKET_KEY"))
	if err != nil {
		return Config{}, "", errors.New("MMFT_RELAY_TICKET_KEY must be the 64 hex character key from `mmft-orchestrator ca relay-settings`")
	}
	addr := getenv("MMFT_RELAY_LISTEN")
	if addr == "" {
		addr = DefaultListen
	}
	return Config{Identity: identity, ConnectionCA: ca, TicketKey: key}, addr, nil
}

func connectionCA(path string) (*x509.Certificate, error) {
	if path == "" {
		return nil, errors.New("MMFT_CONNECTION_CA is not set")
	}
	data, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // the operator sets this path
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("MMFT_CONNECTION_CA does not hold a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return nil, errors.New("MMFT_CONNECTION_CA does not hold a CA certificate")
	}
	return cert, nil
}
