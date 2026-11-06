// Command mmft-testrelay is the lab's test relay. Never use it outside the lab.
//
// By default it runs the real relay with the settings `mmft-relay serve` takes,
// and also writes every byte it forwards to MMFT_RELAY_CAPTURE_DIR, one file
// per delivery, so the lab can check that the relay sees only sealed bytes.
// The real relay stores nothing.
//
// With MMFT_RELAY_TAMPER=on it plays a hostile relay instead, which alters,
// truncates, or swaps sealed files as the tamper-mode file in MMFT_RELAY_DIR
// says, for failure tests T1 to T3.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"mmft.dev/mmft/internal/relay"
	"mmft.dev/mmft/internal/trust"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"error": err.Error()})
		os.Exit(1)
	}
}

func serve(ctx context.Context) error {
	if os.Getenv("MMFT_RELAY_TAMPER") == "on" {
		return serveTamperer(ctx)
	}
	capture := os.Getenv("MMFT_RELAY_CAPTURE_DIR")
	if capture == "" {
		return errors.New("MMFT_RELAY_CAPTURE_DIR is not set")
	}
	if err := os.MkdirAll(capture, 0o700); err != nil { //nolint:gosec // the lab sets this path
		return err
	}
	cfg, addr, err := relay.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	cfg.Log = os.Stdout
	var mu sync.Mutex
	cfg.Tap = func(delivery string, offset uint64, chunk []byte) {
		// The relay checked the ticket, so the ID is a UUID and safe as a name.
		if !trust.ValidAgentID(delivery) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(filepath.Join(capture, delivery+".sealed"), os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // the name is a checked UUID
		if err != nil {
			return
		}
		defer func() { _ = f.Close() }()
		_, _ = f.WriteAt(chunk, int64(offset)) //nolint:gosec // offsets are below the sealed size
	}
	s, err := relay.New(cfg)
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"event": "started", "address": lis.Addr().String()})
	return s.Serve(ctx, lis)
}
