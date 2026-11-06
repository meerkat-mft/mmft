package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/relayticket"
	"mmft.dev/mmft/internal/server"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		url  string
		code int
		want string
	}{
		{"default", nil, "", 0, "mmft-orchestrator "},
		{"version", []string{"version"}, "", 0, "mmft-orchestrator "},
		{"unknown", []string{"unknown"}, "", 2, ""},
		{"extra argument", []string{"migrate", "extra"}, "", 2, ""},
		{"no URL", []string{"migrate"}, "", 1, ""},
		{"bad URL", []string{"migrate"}, "postgres://u:hunter2@host:notaport/db", 1, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, tt.url, &out, &errOut); code != tt.code {
				t.Fatalf("code = %d, stderr = %q", code, errOut.String())
			}
			if !strings.HasPrefix(out.String(), tt.want) {
				t.Fatalf("stdout = %q", out.String())
			}
			if strings.Contains(errOut.String(), "hunter2") {
				t.Fatalf("stderr leaks the password: %q", errOut.String())
			}
		})
	}
}

func TestConnectionLifetime(t *testing.T) {
	for v, want := range map[string]time.Duration{"": connca.ConnectionLifetime, "2m": 2 * time.Minute, "24h": 24 * time.Hour} {
		if got, err := connectionLifetime(v); err != nil || got != want {
			t.Errorf("%q = %v, %v", v, got, err)
		}
	}
	for _, v := range []string{"1m", "25h", "soon", "-5m"} {
		if _, err := connectionLifetime(v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestCASettingsForTheRelay(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	t.Setenv("MMFT_CA_DIR", dir)
	var out, errOut bytes.Buffer
	if code := run([]string{"ca", "init"}, "", &out, &errOut); code != 0 {
		t.Fatalf("ca init: code %d, stderr %q", code, errOut.String())
	}
	var initOut struct {
		Fingerprint string `json:"ca_fingerprint"`
		TicketKey   string `json:"relay_ticket_key"`
	}
	if err := json.Unmarshal(out.Bytes(), &initOut); err != nil {
		t.Fatal(err)
	}
	key, err := relayticket.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if initOut.TicketKey != relayticket.PublicKey(key) {
		t.Fatal("ca init printed a different ticket key")
	}

	// A CA from before relay tickets gets its key on first use.
	if err := os.Remove(filepath.Join(dir, relayticket.KeyFile)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"ca", "relay-settings"}, "", &out, &errOut); code != 0 {
		t.Fatalf("relay-settings: code %d, stderr %q", code, errOut.String())
	}
	var settings struct {
		CA        string `json:"connection_ca"`
		TicketKey string `json:"relay_ticket_key"`
	}
	if err := json.Unmarshal(out.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	ca, err := connca.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if settings.CA != string(ca.CertificatePEM()) {
		t.Fatal("relay-settings printed a different CA")
	}
	key, err = relayticket.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if settings.TicketKey != relayticket.PublicKey(key) || settings.TicketKey == initOut.TicketKey {
		t.Fatal("relay-settings did not print the new ticket key")
	}
}

func TestRelaySettingsFromEnv(t *testing.T) {
	dir := t.TempDir()
	var cfg server.Config
	if err := relaySettingsFromEnv(&cfg, dir, "", ""); err != nil || cfg.RelayAddress != "" {
		t.Fatalf("no address: %v, %+v", err, cfg)
	}
	for _, fp := range []string{"", "abcd", strings.Repeat("zz", 32)} {
		if err := relaySettingsFromEnv(&cfg, dir, "relay:7445", fp); err == nil {
			t.Errorf("fingerprint %q accepted", fp)
		}
	}
	fp := strings.Repeat("ab", 32)
	if err := relaySettingsFromEnv(&cfg, dir, "relay:7445", fp); err != nil {
		t.Fatal(err)
	}
	key, err := relayticket.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RelayAddress != "relay:7445" || len(cfg.RelayCertificateSHA256) != 32 || !cfg.TicketKey.Equal(key) {
		t.Fatalf("settings %+v", cfg)
	}
}
