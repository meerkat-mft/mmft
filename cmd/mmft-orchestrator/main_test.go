package main

import (
	"bytes"
	"strings"
	"testing"
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
