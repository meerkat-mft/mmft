// Command mmft-orchestrator runs the orchestrator. Settings come from the
// environment: MMFT_DATABASE_URL, MMFT_CA_DIR, MMFT_SERVER_NAMES (comma separated),
// MMFT_ADMIN_TOKEN_SHA256, MMFT_GRPC_LISTEN, MMFT_API_LISTEN, and
// MMFT_CONNECTION_LIFETIME, a Go duration that only the lab sets short.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/db"
	"mmft.dev/mmft/internal/relayticket"
	"mmft.dev/mmft/internal/server"
	"mmft.dev/mmft/internal/version"
)

const migrateTimeout = 2 * time.Minute

func main() {
	os.Exit(run(os.Args[1:], os.Getenv("MMFT_DATABASE_URL"), os.Stdout, os.Stderr))
}

func run(args []string, url string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "migrate" {
		if err := migrate(url, stdout); err != nil {
			_ = json.NewEncoder(stderr).Encode(map[string]string{"error": err.Error()})
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "ca" && args[1] == "init" {
		if err := caInit(stdout); err != nil {
			_ = json.NewEncoder(stderr).Encode(map[string]string{"error": err.Error()})
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "ca" && args[1] == "relay-settings" {
		if err := relaySettings(stdout); err != nil {
			_ = json.NewEncoder(stderr).Encode(map[string]string{"error": err.Error()})
			return 1
		}
		return 0
	}
	if len(args) == 1 && args[0] == "serve" {
		if err := serve(); err != nil {
			_ = json.NewEncoder(stderr).Encode(map[string]string{"error": err.Error()})
			return 1
		}
		return 0
	}
	if len(args) == 0 || (len(args) == 1 && args[0] == "version") {
		_, _ = fmt.Fprintln(stdout, version.String("mmft-orchestrator"))
		return 0
	}
	_, _ = io.WriteString(stderr, "usage: mmft-orchestrator [version | migrate | ca init | ca relay-settings | serve]\n")
	return 2
}

func migrate(url string, stdout io.Writer) error {
	if url == "" {
		return errors.New("MMFT_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), migrateTimeout)
	defer cancel()
	pool, err := db.Open(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := db.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]int{"applied": applied})
}

func caInit(stdout io.Writer) error {
	dir := os.Getenv("MMFT_CA_DIR")
	if dir == "" {
		return errors.New("MMFT_CA_DIR is not set")
	}
	ca, err := connca.Create(dir, time.Now())
	if err != nil {
		return err
	}
	key, err := relayticket.LoadOrCreateKey(dir)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{
		"ca_fingerprint":   ca.Fingerprint(),
		"relay_ticket_key": relayticket.PublicKey(key),
	})
}

// relaySettings prints what a relay needs to check agents and their tickets:
// the connection CA certificate and the ticket public key. Neither is secret.
// It creates the ticket key if the CA predates it.
func relaySettings(stdout io.Writer) error {
	dir := os.Getenv("MMFT_CA_DIR")
	if dir == "" {
		return errors.New("MMFT_CA_DIR is not set")
	}
	ca, err := connca.Load(dir)
	if err != nil {
		return err
	}
	key, err := relayticket.LoadOrCreateKey(dir)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{
		"connection_ca":    string(ca.CertificatePEM()),
		"relay_ticket_key": relayticket.PublicKey(key),
	})
}

func listenAddress(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// connectionLifetime reads MMFT_CONNECTION_LIFETIME. Unset means the default.
func connectionLifetime(v string) (time.Duration, error) {
	if v == "" {
		return connca.ConnectionLifetime, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < connca.MinConnectionLifetime || d > connca.ConnectionLifetime {
		return 0, fmt.Errorf("MMFT_CONNECTION_LIFETIME must be a duration from %v to %v", connca.MinConnectionLifetime, connca.ConnectionLifetime)
	}
	return d, nil
}

func serve() error {
	ca, err := connca.Load(os.Getenv("MMFT_CA_DIR"))
	if err != nil {
		return err
	}
	url := os.Getenv("MMFT_DATABASE_URL")
	if url == "" {
		return errors.New("MMFT_DATABASE_URL is not set")
	}
	open, cancel := context.WithTimeout(context.Background(), migrateTimeout)
	defer cancel()
	pool, err := db.Open(open, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	lifetime, err := connectionLifetime(os.Getenv("MMFT_CONNECTION_LIFETIME"))
	if err != nil {
		return err
	}
	srv, err := server.New(server.Config{
		Authority:          ca,
		DB:                 pool,
		Names:              strings.Split(os.Getenv("MMFT_SERVER_NAMES"), ","),
		AdminTokenSHA256:   os.Getenv("MMFT_ADMIN_TOKEN_SHA256"),
		ConnectionLifetime: lifetime,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var lc net.ListenConfig
	grpcListener, err := lc.Listen(ctx, "tcp", listenAddress("MMFT_GRPC_LISTEN", ":7443"))
	if err != nil {
		return err
	}
	apiListener, err := lc.Listen(ctx, "tcp", listenAddress("MMFT_API_LISTEN", ":7444"))
	if err != nil {
		return err
	}
	return srv.Serve(ctx, grpcListener, apiListener)
}
