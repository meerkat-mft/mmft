//go:build !windows

// These tests store private keys, which Windows refuses until its access
// control lists are checked. See perm_windows.go.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cli(t *testing.T, at time.Time, args ...string) (int, map[string]string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut, func() time.Time { return at })
	var parsed map[string]string
	if code == exitOK && out.Len() > 0 && strings.HasPrefix(out.String(), "{") {
		if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not JSON: %q", out.String())
		}
	}
	return code, parsed, errOut.String()
}

type setup struct {
	passFile, rootDir, adminDir, cert string
	rootFP, adminFP                   string
	now                               time.Time
}

func newSetup(t *testing.T) setup {
	t.Helper()
	dir := t.TempDir()
	s := setup{
		passFile: filepath.Join(dir, "pass"),
		rootDir:  filepath.Join(dir, "root"),
		adminDir: filepath.Join(dir, "admin"),
		cert:     filepath.Join(dir, "admin.cert.json"),
		now:      time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
	}
	if err := os.WriteFile(s.passFile, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, root, errOut := cli(t, s.now, "trust", "init", "--dir", s.rootDir, "--passphrase-file", s.passFile)
	if code != exitOK {
		t.Fatalf("trust init: %d %s", code, errOut)
	}
	code, admin, errOut := cli(t, s.now, "admin", "init", "--dir", s.adminDir, "--owner", "sam.lee", "--passphrase-file", s.passFile)
	if code != exitOK {
		t.Fatalf("admin init: %d %s", code, errOut)
	}
	s.rootFP, s.adminFP = root["fingerprint"], admin["fingerprint"]
	return s
}

func (s setup) certify(t *testing.T, rootFP, adminFP string, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{
		"trust", "certify-admin", "--root-dir", s.rootDir, "--root-fingerprint", rootFP, "--passphrase-file", s.passFile,
		"--request", filepath.Join(s.adminDir, "administrator.pub.json"), "--admin-fingerprint", adminFP, "--out", s.cert,
	}, extra...)
	code, _, errOut := cli(t, s.now, args...)
	return code, errOut
}

func TestAdministratorSetupFromAScript(t *testing.T) {
	s := newSetup(t)
	if code, errOut := s.certify(t, s.rootFP, s.adminFP, "--days", "30"); code != exitOK {
		t.Fatalf("certify-admin: %d %s", code, errOut)
	}
	verify := func(at time.Time, fingerprint string) (int, map[string]string, string) {
		return cli(t, at, "trust", "verify-admin", "--root-public", filepath.Join(s.rootDir, "root.pub.json"),
			"--root-fingerprint", fingerprint, "--certificate", s.cert)
	}
	code, got, errOut := verify(s.now, s.rootFP)
	if code != exitOK {
		t.Fatalf("verify-admin: %d %s", code, errOut)
	}
	if got["owner"] != "sam.lee" || got["fingerprint"] != s.adminFP {
		t.Fatalf("verify-admin = %v", got)
	}
	if code, _, _ := verify(s.now.Add(31*24*time.Hour), s.rootFP); code != exitFailure {
		t.Fatalf("expired certificate: %d", code)
	}
	if code, _, _ := verify(s.now, strings.Repeat("0", 64)); code != exitFailure {
		t.Fatalf("wrong pin: %d", code)
	}
}

func TestCertifyRefusesUnconfirmedKeys(t *testing.T) {
	s := newSetup(t)
	wrong := strings.Repeat("0", 64)
	if code, errOut := s.certify(t, wrong, s.adminFP); code != exitFailure || !strings.Contains(errOut, "pinned fingerprint") {
		t.Fatalf("wrong root: %d %s", code, errOut)
	}
	if code, errOut := s.certify(t, s.rootFP, wrong); code != exitFailure || !strings.Contains(errOut, "expected fingerprint") {
		t.Fatalf("swapped request: %d %s", code, errOut)
	}
	if _, err := os.Stat(s.cert); !os.IsNotExist(err) {
		t.Fatalf("certificate written: %v", err)
	}
}

func TestCertifyDays(t *testing.T) {
	s := newSetup(t)
	for _, days := range []string{"0", "-1", "366", "213504"} {
		if code, _ := s.certify(t, s.rootFP, s.adminFP, "--days", days); code != exitUsage {
			t.Errorf("--days %s: code = %d", days, code)
		}
	}
	if code, errOut := s.certify(t, s.rootFP, s.adminFP, "--days", "365"); code != exitOK {
		t.Fatalf("--days 365: %d %s", code, errOut)
	}
}

func TestSafeRepeatRuns(t *testing.T) {
	s := newSetup(t)
	code, _, errOut := cli(t, s.now, "trust", "init", "--dir", s.rootDir, "--passphrase-file", s.passFile)
	if code != exitExists {
		t.Fatalf("repeat init: %d %s", code, errOut)
	}
	code, got, errOut := cli(t, s.now, "trust", "fingerprint", "--public", filepath.Join(s.rootDir, "root.pub.json"))
	if code != exitOK || got["fingerprint"] != s.rootFP {
		t.Fatalf("fingerprint: %d %v %s", code, got, errOut)
	}
}

func TestErrorsAreJSON(t *testing.T) {
	_, _, errOut := cli(t, time.Now(), "trust", "init", "--dir", t.TempDir(), "--passphrase-file", "/no/such/file")
	var parsed map[string]string
	if err := json.Unmarshal([]byte(errOut), &parsed); err != nil || parsed["error"] == "" {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	now := time.Now()
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"trust"},
		{"trust", "unknown"},
		{"trust", "init"},
		{"trust", "init", "--dir", "x"},
		{"trust", "init", "--dir", "x", "--passphrase-file", "y", "stray"},
		{"trust", "init", "--unknown", "x"},
		{"trust", "fingerprint"},
		{"trust", "certify-admin", "--root-dir", "x", "--passphrase-file", "y", "--request", "z", "--out", "o"},
		{"admin", "init", "--dir", "x", "--passphrase-file", "y"},
		{"agent", "approve", "--api", "localhost:1"},
		{"agent", "approve", "--api", "localhost:1", "--ca-fingerprint", "x", "--token-file", "x", "--admin-dir", "x",
			"--passphrase-file", "x", "--certificate", "x", "--root-public", "x", "--root-fingerprint", "x",
			"--fingerprints", "x", "--days", "366"},
	} {
		if code, _, _ := cli(t, now, args...); code != exitUsage {
			t.Errorf("%v: code = %d", args, code)
		}
	}
}

func TestPassphraseFileMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte("correct horse battery staple"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(passFile, 0o640); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := cli(t, time.Now(), "trust", "init", "--dir", filepath.Join(dir, "root"), "--passphrase-file", passFile)
	if code != exitFailure || !strings.Contains(errOut, "not private") {
		t.Fatalf("code = %d, stderr = %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "root")); !os.IsNotExist(err) {
		t.Fatalf("root directory created: %v", err)
	}
}

func TestOutputNeverIncludesSecrets(t *testing.T) {
	dir := t.TempDir()
	secret := "correct horse battery staple"
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"trust", "init", "--dir", filepath.Join(dir, "root"), "--passphrase-file", passFile}, &out, &errOut, time.Now); code != exitOK {
		t.Fatalf("code = %d: %s", code, errOut.String())
	}
	combined := out.String() + errOut.String()
	if strings.Contains(combined, secret) || strings.Contains(combined, "seed") {
		t.Fatalf("output = %q", combined)
	}

	// A passphrase passed where a path belongs must not be echoed.
	errOut.Reset()
	run([]string{"trust", "init", "--dir", dir, "--passphrase-file", secret}, &out, &errOut, time.Now)
	if strings.Contains(errOut.String(), secret) {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut, time.Now); code != exitOK {
		t.Fatalf("code = %d", code)
	}
	if !strings.HasPrefix(out.String(), "mmft ") {
		t.Fatalf("output = %q", out.String())
	}
}
