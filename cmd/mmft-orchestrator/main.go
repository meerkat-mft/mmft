// Command mmft-orchestrator runs the orchestrator. Settings come from the
// environment: MMFT_DATABASE_URL, MMFT_CA_DIR, MMFT_SERVER_NAMES (comma separated),
// MMFT_ADMIN_TOKEN_SHA256, MMFT_GRPC_LISTEN, and MMFT_API_LISTEN.
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
	_, _ = io.WriteString(stderr, "usage: mmft-orchestrator [version | migrate | ca init | serve]\n")
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
	return json.NewEncoder(stdout).Encode(map[string]string{"ca_fingerprint": ca.Fingerprint()})
}

func listenAddress(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func serve() error {
	ca, err := connca.Load(os.Getenv("MMFT_CA_DIR"))
	if err != nil {
		return err
	}
	srv, err := server.New(server.Config{
		Authority:        ca,
		Names:            strings.Split(os.Getenv("MMFT_SERVER_NAMES"), ","),
		AdminTokenSHA256: os.Getenv("MMFT_ADMIN_TOKEN_SHA256"),
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
