package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/relayticket"
)

func TestRun(t *testing.T) {
	t.Setenv("MMFT_RELAY_DIR", "")
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"default", nil, 0, "mmft-relay "},
		{"version", []string{"version"}, 0, "mmft-relay "},
		{"unknown", []string{"unknown"}, 2, ""},
		{"extra argument", []string{"init", "extra"}, 2, ""},
		{"no directory", []string{"init"}, 1, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, &out, &errOut); code != tt.code {
				t.Fatalf("code = %d, stderr = %q", code, errOut.String())
			}
			if !strings.HasPrefix(out.String(), tt.want) {
				t.Fatalf("stdout = %q", out.String())
			}
		})
	}
}

func TestInitThenServe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	t.Setenv("MMFT_RELAY_DIR", dir)
	var out, errOut bytes.Buffer
	if code := run([]string{"init"}, &out, &errOut); code != 0 {
		t.Fatalf("init: code %d, stderr %q", code, errOut.String())
	}
	var created struct {
		Fingerprint string `json:"relay_certificate_sha256"`
	}
	if err := json.Unmarshal(out.Bytes(), &created); err != nil || len(created.Fingerprint) != 64 {
		t.Fatalf("init printed %q", out.String())
	}
	if code := run([]string{"init"}, &out, &errOut); code != 1 {
		t.Fatal("a second init replaced the identity")
	}

	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, ca.CertificatePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("MMFT_CONNECTION_CA", caFile)
	t.Setenv("MMFT_RELAY_TICKET_KEY", relayticket.PublicKey(key))
	t.Setenv("MMFT_RELAY_LISTEN", "127.0.0.1:0")

	ctx, cancel := context.WithCancel(context.Background())
	var log bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- serve(ctx, &log) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	var started map[string]string
	if err := json.Unmarshal([]byte(strings.SplitN(log.String(), "\n", 2)[0]), &started); err != nil {
		t.Fatalf("log %q: %v", log.String(), err)
	}
	if started["event"] != "started" || started["relay_certificate_sha256"] != created.Fingerprint {
		t.Fatalf("started = %v", started)
	}
}

func TestServeNeedsItsSettings(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	t.Setenv("MMFT_RELAY_DIR", dir)
	var out, errOut bytes.Buffer
	if code := run([]string{"init"}, &out, &errOut); code != 0 {
		t.Fatal(errOut.String())
	}
	notCA := filepath.Join(t.TempDir(), "x.pem")
	if err := os.WriteFile(notCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, ca.CertificatePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(make([]byte, 32))
	for name, env := range map[string][2]string{
		"no CA":          {"", key},
		"damaged CA":     {notCA, key},
		"no ticket key":  {caFile, ""},
		"bad ticket key": {caFile, "abcd"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MMFT_CONNECTION_CA", env[0])
			t.Setenv("MMFT_RELAY_TICKET_KEY", env[1])
			if err := serve(context.Background(), &out); err == nil {
				t.Fatal("serve started")
			}
		})
	}
}
