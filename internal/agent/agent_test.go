package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/server/servertest"
	"mmft.dev/mmft/internal/trust"
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

// enrollDirectly enrolls with dir's keys but saves nothing, as when the
// orchestrator commits and the response is lost on the way back.
func enrollDirectly(t *testing.T, dir string, o servertest.Orchestrator, token, name string) string {
	t.Helper()
	keys, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub := keys.Public()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, keys.Connection)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := trust.ProveEnrollment(keys.Signer, token, name, pub.Recipient, csr)
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, _ := json.Marshal(proof)
	host, _, _ := net.SplitHostPort(o.GRPC)
	conn, err := grpc.NewClient(o.GRPC, grpc.WithTransportCredentials(credentials.NewTLS(connca.PinnedClient(o.CA.Fingerprint(), host, time.Now))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := agentv1.NewEnrollmentServiceClient(conn).Enroll(ctx, &agentv1.EnrollRequest{
		Token: token, AgentName: name, Ed25519PublicKey: pub.Ed25519, Mldsa65PublicKey: pub.MLDSA65,
		EncryptionRecipient: pub.Recipient, CertificateRequest: csr, ProofStatement: proofBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.GetAgentId()
}

func TestRetryAfterALostResponseGetsTheSameAgent(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	token := o.Token(t, "lab", "agent-a")
	id := enrollDirectly(t, dir, o, token, "agent-a")
	s, err := enroll(t, dir, install(o, token, "agent-a"))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if s.AgentID != id {
		t.Fatalf("retry enrolled %q, want %q", s.AgentID, id)
	}
	// The used token still refuses an agent with other keys.
	if _, err := enroll(t, agentDir(t), install(o, token, "agent-a")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other keys: %v", err)
	}
}

func TestRetryAfterAFailedSaveGetsTheSameAgent(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	if _, err := LoadOrCreateKeys(dir); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory in the certificate's place makes saving fail after
	// the orchestrator has committed the enrollment.
	blocker := filepath.Join(dir, CertFile)
	if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	token := o.Token(t, "lab", "agent-a")
	if _, err := enroll(t, dir, install(o, token, "agent-a")); err == nil {
		t.Fatal("enrollment saved over a directory")
	}
	if _, err := ReadState(dir); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("state after a failed save: %v", err)
	}
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	first, err := enroll(t, dir, install(o, token, "agent-a"))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if again, err := ReadState(dir); err != nil || again.AgentID != first.AgentID {
		t.Fatalf("saved state: %+v, %v", again, err)
	}
}

func TestConcurrentInstallsAgree(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	names := []string{"agent-a", "agent-b"}
	type result struct {
		s   State
		err error
	}
	results := make(chan result, len(names))
	for _, name := range names {
		in := install(o, o.Token(t, "lab", name), name)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s, err := Enroll(ctx, dir, in, time.Now)
			results <- result{s, err}
		}()
	}
	var enrolled, existed []State
	for range names {
		r := <-results
		switch {
		case r.err == nil:
			enrolled = append(enrolled, r.s)
		case errors.Is(r.err, os.ErrExist):
			existed = append(existed, r.s)
		default:
			t.Fatalf("install: %v", r.err)
		}
	}
	if len(enrolled) != 1 || len(existed) != 1 || existed[0].AgentID != enrolled[0].AgentID {
		t.Fatalf("enrolled %+v, existed %+v", enrolled, existed)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := connca.AgentID(cert); err != nil || id != enrolled[0].AgentID {
		t.Fatalf("certificate names %q, state names %q", id, enrolled[0].AgentID)
	}
}

// An install waiting behind a stalled one gives up at its own deadline.
func TestInstallWaitingForTheLockHonorsItsDeadline(t *testing.T) {
	if !keyStorageSupported {
		t.Skip("no key storage on this platform")
	}
	o := servertest.Start(t)
	dir := agentDir(t)
	if err := trust.PrepareDir(dir); err != nil {
		t.Fatal(err)
	}
	unlock, err := lock(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	in := install(o, o.Token(t, "lab", "agent-a"), "agent-a")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Enroll(ctx, dir, in, time.Now); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting install: %v", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("waited %v past a 300ms deadline", waited)
	}
	unlock()
	if _, err := enroll(t, dir, in); err != nil {
		t.Fatalf("after the lock was released: %v", err)
	}
}

func TestIncompleteStateIsRefused(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	if _, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, StateFile)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"orchestrator", "ca_fingerprint", "root_fingerprint", "agent_id", "agent_name"} {
		for name, value := range map[string]any{"missing": nil, "invalid": "../x"} {
			var m map[string]any
			if err := json.Unmarshal(good, &m); err != nil {
				t.Fatal(err)
			}
			if value == nil {
				delete(m, field)
			} else {
				m[field] = value
			}
			data, _ := json.Marshal(m)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadState(dir); !errors.Is(err, ErrDamaged) {
				t.Errorf("%s %s: %v", name, field, err)
			}
		}
	}
}

func fetch(t *testing.T, dir string) (trust.IdentityClaim, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return FetchIdentity(ctx, dir, time.Now)
}

func TestFetchIdentityVerifiesAndSaves(t *testing.T) {
	o := servertest.Start(t)
	ap := servertest.NewApprover(t)
	dir := agentDir(t)
	in := install(o, o.Token(t, "lab", "agent-a"), "agent-a")
	in.RootFingerprint = ap.RootFingerprint()
	s, err := enroll(t, dir, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetch(t, dir); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("before approval: err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, IdentityFile)); !os.IsNotExist(err) {
		t.Fatalf("identity saved before approval: %v", err)
	}
	identity := ap.Sign(t, s.AgentID, "lab", "agent-a", s.Keys())
	if code := o.PutIdentity(t, s.AgentID, identity); code != 204 {
		t.Fatalf("put identity: %d", code)
	}
	claim, err := fetch(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if claim.AgentID != s.AgentID || claim.Workspace != "lab" {
		t.Fatalf("claim = %+v", claim)
	}
	saved, err := os.ReadFile(filepath.Join(dir, IdentityFile))
	if err != nil || !bytes.Equal(saved, identity) {
		t.Fatalf("saved identity differs: %v", err)
	}
	if _, err := fetch(t, dir); err != nil {
		t.Fatalf("repeat fetch: %v", err)
	}
}

func TestIdentityFromAnotherRootIsRefused(t *testing.T) {
	o := servertest.Start(t)
	pinned, other := servertest.NewApprover(t), servertest.NewApprover(t)
	dir := agentDir(t)
	in := install(o, o.Token(t, "lab", "agent-a"), "agent-a")
	in.RootFingerprint = pinned.RootFingerprint()
	s, err := enroll(t, dir, in)
	if err != nil {
		t.Fatal(err)
	}
	// A compromised orchestrator can store an identity signed under its own root.
	if code := o.PutIdentity(t, s.AgentID, other.Sign(t, s.AgentID, "lab", "agent-a", s.Keys())); code != 204 {
		t.Fatalf("put identity: %d", code)
	}
	if _, err := fetch(t, dir); !errors.Is(err, trust.ErrWrongRoot) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, IdentityFile)); !os.IsNotExist(err) {
		t.Fatalf("unverified identity saved: %v", err)
	}
}

func TestVerifyIdentityRequiresThisAgent(t *testing.T) {
	ap := servertest.NewApprover(t)
	o := servertest.Start(t)
	dir := agentDir(t)
	in := install(o, o.Token(t, "lab", "agent-a"), "agent-a")
	in.RootFingerprint = ap.RootFingerprint()
	s, err := enroll(t, dir, in)
	if err != nil {
		t.Fatal(err)
	}
	otherDir := agentDir(t)
	other, err := LoadOrCreateKeys(otherDir)
	if err != nil {
		t.Fatal(err)
	}
	for name, identity := range map[string][]byte{
		"other keys":     ap.Sign(t, s.AgentID, "lab", "agent-a", other.Public()),
		"other agent ID": ap.Sign(t, "019a3f2e-7c11-7d3e-9f7b-000000000000", "lab", "agent-a", s.Keys()),
		"other name":     ap.Sign(t, s.AgentID, "lab", "agent-b", s.Keys()),
	} {
		if _, err := VerifyIdentity(s, identity, time.Now()); !errors.Is(err, ErrWrongIdentity) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := VerifyIdentity(s, ap.Sign(t, s.AgentID, "lab", "agent-a", s.Keys()), time.Now()); err != nil {
		t.Fatal(err)
	}
}
