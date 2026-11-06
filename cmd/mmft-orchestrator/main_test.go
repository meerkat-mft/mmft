package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"mmft.dev/mmft/internal/connca"
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
