package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"mmft.dev/mmft/internal/server/servertest"
)

const rootPin = "1111111111111111111111111111111111111111111111111111111111111111"

func install(o servertest.Orchestrator, token, name string) Install {
	return Install{Orchestrator: o.GRPC, Token: token, AgentName: name, CAFingerprint: o.CA.Fingerprint(), RootFingerprint: rootPin}
}

func enroll(t *testing.T, dir string, in Install) (State, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Enroll(ctx, dir, in, time.Now)
}

func agentDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "agent")
}

func TestEnrollSavesKeysAndState(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	s, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Fingerprint() != keys.Public().Fingerprint() || s.Fingerprint() == "" {
		t.Fatal("state fingerprint differs from the keys")
	}
	saved, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.AgentID != s.AgentID || saved.AgentName != "agent-a" || saved.RootFingerprint != rootPin || saved.CAFingerprint != o.CA.Fingerprint() {
		t.Fatalf("saved state = %+v", saved)
	}
	if _, err := os.Stat(filepath.Join(dir, CertFile)); err != nil {
		t.Fatal(err)
	}

	state, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "seed") || strings.Contains(string(state), "AGE-SECRET-KEY") {
		t.Fatal("the state file holds private keys")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, KeyFile))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode = %v", info.Mode().Perm())
		}
	}
}

func TestRepeatInstallChangesNothing(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	first, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a"))
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	again, err := enroll(t, dir, install(o, "a-different-token", "agent-a"))
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("repeat: %v", err)
	}
	keyAfter, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	if again.AgentID != first.AgentID || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("a repeat install changed the agent")
	}
}

func TestWrongCAPinFailsAndKeepsTheToken(t *testing.T) {
	o, other := servertest.Start(t), servertest.Start(t)
	dir := agentDir(t)
	token := o.Token(t, "lab", "agent-a")
	in := install(o, token, "agent-a")
	in.CAFingerprint = other.CA.Fingerprint()
	// Dial only the bound IPv4 address so an IPv6 connection refusal cannot
	// mask the CA-pin error. The wrong CA is rejected before name verification.
	_, port, err := net.SplitHostPort(in.Orchestrator)
	if err != nil {
		t.Fatal(err)
	}
	in.Orchestrator = net.JoinHostPort("127.0.0.1", port)
	if _, err := enroll(t, dir, in); err == nil || !strings.Contains(err.Error(), "pinned CA") || strings.Contains(err.Error(), "x509:") {
		t.Fatalf("other CA pin: %v", err)
	}
	keys, err := LoadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A retry with the right pin reuses the keys and the unused token.
	s, err := enroll(t, dir, install(o, token, "agent-a"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Fingerprint() != keys.Public().Fingerprint() {
		t.Fatal("the retry generated new keys")
	}
}

func TestUsedTokenIsRefused(t *testing.T) {
	o := servertest.Start(t)
	token := o.Token(t, "lab", "agent-a")
	if _, err := enroll(t, agentDir(t), install(o, token, "agent-a")); err != nil {
		t.Fatal(err)
	}
	dir := agentDir(t)
	if _, err := enroll(t, dir, install(o, token, "agent-a")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("used token: %v", err)
	}
	if _, err := ReadState(dir); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("state after refusal: %v", err)
	}
}

func TestInvalidInstallSettings(t *testing.T) {
	good := Install{Orchestrator: "orchestrator:7443", Token: "t", AgentName: "agent-a", CAFingerprint: rootPin, RootFingerprint: rootPin}
	for name, change := range map[string]func(*Install){
		"no port":        func(i *Install) { i.Orchestrator = "orchestrator" },
		"no token":       func(i *Install) { i.Token = "" },
		"bad name":       func(i *Install) { i.AgentName = "../a" },
		"short pin":      func(i *Install) { i.CAFingerprint = "abcd" },
		"upper-case pin": func(i *Install) { i.RootFingerprint = strings.ToUpper(strings.Repeat("ab", 32)) },
	} {
		in := good
		change(&in)
		dir := agentDir(t)
		if _, err := enroll(t, dir, in); !errors.Is(err, ErrInvalidInstall) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: created the directory", name)
		}
	}
}

func TestKeysReadableByOthersAreRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows access control lists aren't checked yet")
	}
	dir := agentDir(t)
	if _, err := LoadOrCreateKeys(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(dir); err == nil {
		t.Fatal("a readable key file was accepted")
	}
}

func TestDamagedFilesAreRefused(t *testing.T) {
	dir := agentDir(t)
	if _, err := LoadOrCreateKeys(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, StateFile), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(dir); !errors.Is(err, ErrDamaged) {
		t.Fatalf("state: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, KeyFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte(`{"version":1,"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(dir); !errors.Is(err, ErrDamaged) {
		t.Fatalf("keys: %v", err)
	}
}
