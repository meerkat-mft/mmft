// Command mmft-relay runs the blind relay, which forwards sealed files between
// agents that have no direct path. Settings come from the environment:
// MMFT_RELAY_DIR holds the relay's TLS key and certificate, MMFT_RELAY_LISTEN
// is the listen address, MMFT_CONNECTION_CA is the path to the orchestrator's
// connection CA certificate, and MMFT_RELAY_TICKET_KEY is the orchestrator's
// relay ticket public key in hex. `mmft-orchestrator ca relay-settings` prints
// the last two.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mmft.dev/mmft/internal/relay"
	"mmft.dev/mmft/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var err error
	switch {
	case len(args) == 0 || (len(args) == 1 && args[0] == "version"):
		_, _ = fmt.Fprintln(stdout, version.String("mmft-relay"))
		return 0
	case len(args) == 1 && args[0] == "init":
		err = initIdentity(stdout)
	case len(args) == 1 && args[0] == "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = serve(ctx, stdout)
	default:
		_, _ = io.WriteString(stderr, "usage: mmft-relay [version | init | serve]\n")
		return 2
	}
	if err != nil {
		_ = json.NewEncoder(stderr).Encode(map[string]string{"error": err.Error()})
		return 1
	}
	return 0
}

func relayDir() (string, error) {
	dir := os.Getenv("MMFT_RELAY_DIR")
	if dir == "" {
		return "", errors.New("MMFT_RELAY_DIR is not set")
	}
	return dir, nil
}

// initIdentity creates the relay's key and certificate, and prints the
// certificate's SHA-256, which the orchestrator gives agents with each ticket.
func initIdentity(stdout io.Writer) error {
	dir, err := relayDir()
	if err != nil {
		return err
	}
	fp, err := relay.CreateIdentity(dir, time.Now())
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{"relay_certificate_sha256": hex.EncodeToString(fp)})
}

func serve(ctx context.Context, stdout io.Writer) error {
	cfg, addr, err := relay.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	cfg.Log = stdout
	s, err := relay.New(cfg)
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = json.NewEncoder(stdout).Encode(map[string]string{
		"time":                     time.Now().UTC().Format(time.RFC3339),
		"event":                    "started",
		"address":                  lis.Addr().String(),
		"relay_certificate_sha256": hex.EncodeToString(relay.Fingerprint(cfg.Identity)),
	})
	return s.Serve(ctx, lis)
}
