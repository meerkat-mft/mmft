package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	return Install{Orchestrator: o.GRPC, Token: token, Workspace: "lab", AgentName: name, CAFingerprint: o.CA.Fingerprint(), RootFingerprint: rootPin}
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
	// Only public fields are saved, and no private key appears in any form.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(state, &fields); err != nil {
		t.Fatal(err)
	}
	var names []string
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "agent_id,agent_name,ca_fingerprint,ed25519,encryption_recipient,mldsa65,orchestrator,root_fingerprint,version,workspace" {
		t.Fatalf("state fields = %s", got)
	}
	edSeed, mlSeed := keys.Signer.Seeds()
	for name, secret := range map[string]string{
		"ed25519 seed":        base64.StdEncoding.EncodeToString(edSeed),
		"ml-dsa seed":         base64.StdEncoding.EncodeToString(mlSeed),
		"connection seed":     base64.StdEncoding.EncodeToString(keys.Connection.Seed()),
		"encryption identity": keys.Encryption.String(),
	} {
		if strings.Contains(string(state), secret) {
			t.Fatalf("the state file holds the %s", name)
		}
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
	if !errors.Is(err, ErrAlreadyEnrolled) {
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
	good := Install{Orchestrator: "orchestrator:7443", Token: "t", Workspace: "lab", AgentName: "agent-a", CAFingerprint: rootPin, RootFingerprint: rootPin}
	for name, change := range map[string]func(*Install){
		"no port":        func(i *Install) { i.Orchestrator = "orchestrator" },
		"no token":       func(i *Install) { i.Token = "" },
		"bad name":       func(i *Install) { i.AgentName = "../a" },
		"no workspace":   func(i *Install) { i.Workspace = "" },
		"bad workspace":  func(i *Install) { i.Workspace = "../w" },
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
	proof, err := trust.ProveEnrollment(keys.Signer, token, "lab", name, pub.Recipient, csr)
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
		Token: token, AgentId: pub.AgentID(), Workspace: "lab", AgentName: name, Ed25519PublicKey: pub.Ed25519, Mldsa65PublicKey: pub.MLDSA65,
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
		case errors.Is(r.err, ErrOtherSettings):
			// The two installs name different agents, so the loser is told
			// the directory holds another agent, never that it's a safe repeat.
			existed = append(existed, r.s)
		default:
			t.Fatalf("install: %v", r.err)
		}
	}
	if len(enrolled) != 1 || len(existed) != 1 {
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
	for _, field := range []string{"orchestrator", "ca_fingerprint", "root_fingerprint", "agent_id", "workspace", "agent_name"} {
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
		"another agent":   ap.Sign(t, other.Public().AgentID(), "lab", "agent-a", other.Public()),
		"other workspace": ap.Sign(t, s.AgentID, "prod", "agent-a", s.Keys()),
		"other name":      ap.Sign(t, s.AgentID, "lab", "agent-b", s.Keys()),
	} {
		if _, err := VerifyIdentity(s, identity, time.Now()); !errors.Is(err, ErrWrongIdentity) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := VerifyIdentity(s, ap.Sign(t, s.AgentID, "lab", "agent-a", s.Keys()), time.Now()); err != nil {
		t.Fatal(err)
	}
}

// An ID that is a valid UUID but not the one derived from the keys is refused,
// both from the orchestrator and in saved state.
func TestAgentIDMustComeFromTheKeys(t *testing.T) {
	keys, err := LoadOrCreateKeys(agentDir(t))
	if err != nil {
		t.Fatal(err)
	}
	// A valid certificate for this agent's connection key, naming an ID the
	// orchestrator chose. Only the derived-ID check can refuse it.
	const other = "019a3f2e-7c11-7d3e-9f7b-000000000000"
	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, keys.Connection)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.SignAgent(csr, other, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp := &agentv1.EnrollResponse{AgentId: other, ConnectionCertificate: der}
	if err := checkCertificate(resp, keys.Connection, other); err != nil {
		t.Fatalf("the certificate itself must be valid: %v", err)
	}
	if err := checkCertificate(resp, keys.Connection, keys.Public().AgentID()); !errors.Is(err, ErrBadCertificate) {
		t.Fatalf("orchestrator's own ID: %v", err)
	}

	o := servertest.Start(t)
	dir := agentDir(t)
	if _, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, StateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["agent_id"] = other
	changed, _ := json.Marshal(m)
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(dir); !errors.Is(err, ErrDamaged) {
		t.Fatalf("saved ID not from the keys: %v", err)
	}
}

// A repeat install is a safe repeat only with the same settings, the keys,
// and a current certificate in place. An expired certificate re-enrolls with
// a new token and the same keys.
func TestRepeatInstallChecksEverything(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	first, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a"))
	if err != nil {
		t.Fatal(err)
	}
	good := install(o, "", "agent-a")
	if _, err := CheckInstalled(dir, good, time.Now()); err != nil {
		t.Fatalf("healthy agent: %v", err)
	}
	for name, change := range map[string]func(*Install){
		"other name":         func(i *Install) { i.AgentName = "agent-b" },
		"other workspace":    func(i *Install) { i.Workspace = "prod" },
		"other orchestrator": func(i *Install) { i.Orchestrator = "elsewhere:7443" },
		"other CA pin":       func(i *Install) { i.CAFingerprint = rootPin },
		"other root pin":     func(i *Install) { i.RootFingerprint = o.CA.Fingerprint() },
	} {
		in := good
		change(&in)
		if _, err := CheckInstalled(dir, in, time.Now()); !errors.Is(err, ErrOtherSettings) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The certificate expires after 24 hours, for example while approval waits.
	later := time.Now().Add(25 * time.Hour)
	if _, err := CheckInstalled(dir, good, later); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("expired certificate: %v", err)
	}
	if _, err := FetchIdentity(context.Background(), dir, func() time.Time { return later }); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("identity with an expired certificate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before, err := readCertificate(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	in := install(o, o.Token(t, "lab", "agent-a"), "agent-a")
	again, err := Enroll(ctx, dir, in, func() time.Time { return later })
	if err != nil {
		t.Fatalf("re-enrollment: %v", err)
	}
	if again.AgentID != first.AgentID {
		t.Fatalf("re-enrolled as %q, want %q", again.AgentID, first.AgentID)
	}
	// Only the agent's clock moved, so the old certificate would still pass a
	// check at the real time. Require a new one.
	after, err := readCertificate(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	if after.SerialNumber.Cmp(before.SerialNumber) == 0 || bytes.Equal(after.Raw, before.Raw) {
		t.Fatal("re-enrollment kept the old certificate")
	}
	if _, err := CheckInstalled(dir, good, time.Now()); err != nil {
		t.Fatalf("after re-enrollment: %v", err)
	}

	// Missing files are damage, never a safe repeat.
	for _, file := range []string{CertFile, KeyFile} {
		if err := os.Rename(filepath.Join(dir, file), filepath.Join(dir, file+".gone")); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckInstalled(dir, good, time.Now()); !errors.Is(err, ErrDamaged) {
			t.Errorf("missing %s: %v", file, err)
		}
		if err := os.Rename(filepath.Join(dir, file+".gone"), filepath.Join(dir, file)); err != nil {
			t.Fatal(err)
		}
	}
}

// The saved certificate must carry a valid signature from the CA pinned at
// enrollment, not just parse with the right key and ID.
func TestRepeatInstallChecksTheCertificateSignature(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	if _, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a")); err != nil {
		t.Fatal(err)
	}
	good := install(o, "", "agent-a")
	certPath, caPath := filepath.Join(dir, CertFile), filepath.Join(dir, CAFile)
	certPEM, _ := os.ReadFile(certPath)
	caPEM, _ := os.ReadFile(caPath)

	block, _ := pem.Decode(certPEM)
	corrupt := bytes.Clone(block.Bytes)
	corrupt[len(corrupt)-1] ^= 0xff // The signature is the last field.
	if _, err := x509.ParseCertificate(corrupt); err != nil {
		t.Fatalf("the corrupted certificate must still parse: %v", err)
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: corrupt}))
	if _, err := CheckInstalled(dir, good, time.Now()); !errors.Is(err, ErrDamaged) {
		t.Fatalf("corrupted signature: %v", err)
	}
	write(certPath, certPEM)

	otherDir := filepath.Join(t.TempDir(), "ca")
	if _, err := connca.Create(otherDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	otherCA, err := os.ReadFile(filepath.Join(otherDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	write(caPath, otherCA)
	if _, err := CheckInstalled(dir, good, time.Now()); !errors.Is(err, ErrDamaged) {
		t.Fatalf("another CA: %v", err)
	}
	if err := os.Remove(caPath); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckInstalled(dir, good, time.Now()); !errors.Is(err, ErrDamaged) {
		t.Fatalf("missing CA: %v", err)
	}
	write(caPath, caPEM)
	if _, err := CheckInstalled(dir, good, time.Now()); err != nil {
		t.Fatalf("restored: %v", err)
	}
}

// A re-enrollment that can't save its new certificate keeps the old one, so
// the agent stays recoverable instead of damaged.
func TestFailedReenrollmentKeepsTheOldCertificate(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs directory permissions that apply to this user")
	}
	o := servertest.Start(t)
	dir := agentDir(t)
	if _, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a")); err != nil {
		t.Fatal(err)
	}
	later := func() time.Time { return time.Now().Add(25 * time.Hour) }
	token := o.Token(t, "lab", "agent-a")
	// A directory nobody can write to makes every replacement fail.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Enroll(ctx, dir, install(o, token, "agent-a"), later)
	if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	if !errors.Is(err, ErrSaveFailed) {
		t.Fatalf("re-enrollment into a read-only directory: %v", err)
	}
	if _, err := CheckInstalled(dir, install(o, "", "agent-a"), later()); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("after the failed save: %v", err)
	}
	if _, err := Enroll(ctx, dir, install(o, token, "agent-a"), later); err != nil {
		t.Fatalf("retry with the same token: %v", err)
	}
}
