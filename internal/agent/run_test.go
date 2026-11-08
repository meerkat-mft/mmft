package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/allowlist"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/server/servertest"
)

// events collects the JSON lines Run logs.
type events struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	seen []string
}

func (e *events) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.buf.Write(p)
	sc := bufio.NewScanner(bytes.NewReader(p))
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			event, _ := m["event"].(string)
			e.seen = append(e.seen, event)
		}
	}
	return len(p), nil
}

func (e *events) count(event string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, s := range e.seen {
		if s == event {
			n++
		}
	}
	return n
}

// waitFor waits until event has been logged n times.
func (e *events) waitFor(t *testing.T, event string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for e.count(event) < n {
		if time.Now().After(deadline) {
			e.mu.Lock()
			defer e.mu.Unlock()
			t.Fatalf("no %d %q events in:\n%s", n, event, e.buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// proxy forwards TCP connections to an orchestrator and can drop them all, as
// a network failure or a restart would.
type proxy struct {
	addr  string
	mu    sync.Mutex
	conns []net.Conn
}

func startProxy(t *testing.T, target string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p := &proxy{addr: net.JoinHostPort("localhost", port)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
	t.Cleanup(p.drop)
	return p
}

func (p *proxy) drop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

// running is an agent running in the background.
type running struct {
	events *events
	cancel context.CancelFunc
	// done closes when Run returns, and err is then its result.
	done chan struct{}
	err  error
}

// wait waits for Run to return.
func (r *running) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-r.done:
		return r.err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

// runAgent runs an agent in the background until the test ends.
func runAgent(t *testing.T, dir string, now func() time.Time) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{events: &events{}, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		r.err = Run(ctx, dir, RunConfig{Heartbeat: 20 * time.Millisecond, MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond, Log: r.events, Now: now})
	}()
	t.Cleanup(func() {
		cancel()
		_ = r.wait(t)
	})
	return r
}

func TestRunReconnectsAfterTheConnectionDrops(t *testing.T) {
	o := servertest.Start(t)
	p := startProxy(t, o.GRPC)
	dir := agentDir(t)
	in := install(o, o.Token(t, "lab", "agent-a"), "agent-a")
	in.Orchestrator = p.addr
	if _, err := enroll(t, dir, in); err != nil {
		t.Fatal(err)
	}
	r := runAgent(t, dir, time.Now)
	r.events.waitFor(t, "connected", 1)
	p.drop()
	r.events.waitFor(t, "disconnected", 1)
	r.events.waitFor(t, "connected", 2)
	r.cancel()
	if err := r.wait(t); err != nil {
		t.Fatalf("Run = %v", err)
	}
}

func TestRunRenewsPastHalfLife(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	if _, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a")); err != nil {
		t.Fatal(err)
	}
	before, err := readCertificate(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	// Before half its lifetime, the certificate is kept.
	r := runAgent(t, dir, func() time.Time { return time.Now().Add(11 * time.Hour) })
	r.events.waitFor(t, "connected", 1)
	time.Sleep(200 * time.Millisecond)
	r.cancel()
	_ = r.wait(t)
	if n := r.events.count("renewed"); n != 0 {
		t.Fatalf("renewed %d times before half its lifetime", n)
	}

	later := func() time.Time { return time.Now().Add(13 * time.Hour) }
	runAgent(t, dir, later).events.waitFor(t, "renewed", 1)
	after, err := readCertificate(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	if after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Fatal("the certificate was not replaced")
	}
	s, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertificate(dir, s, keys, later()); err != nil {
		t.Fatalf("renewed certificate: %v", err)
	}
}

func TestRunStopsWhenTheCertificateHasExpired(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	if _, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a")); err != nil {
		t.Fatal(err)
	}
	r := runAgent(t, dir, func() time.Time { return time.Now().Add(connca.ConnectionLifetime + time.Minute) })
	if err := r.wait(t); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("Run = %v", err)
	}
	if r.events.count("stopped") != 1 {
		t.Fatal("the failure was not logged")
	}
}

func TestRunNeedsAnEnrolledAgent(t *testing.T) {
	if err := Run(context.Background(), agentDir(t), RunConfig{}); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Run = %v", err)
	}
}

func TestRenewedCertificateIsChecked(t *testing.T) {
	ca := testCA(t)
	other := testCA(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const id = "019a3f2e-7c11-7d3e-9f7b-2c1d4e5f6a7b"
	now := time.Now()
	sign := func(a *connca.Authority, k ed25519.PrivateKey, agentID string, at time.Time, lifetime time.Duration) []byte {
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		if err != nil {
			t.Fatal(err)
		}
		der, err := a.SignAgent(csr, agentID, at, lifetime)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	caCert := caCertificate(t, ca)
	current, err := x509.ParseCertificate(sign(ca, key, id, now.Add(-12*time.Hour), connca.ConnectionLifetime))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkRenewed(sign(ca, key, id, now, connca.ConnectionLifetime), current, caCert, id, key, now); err != nil {
		t.Fatalf("good certificate: %v", err)
	}
	for name, der := range map[string][]byte{
		"another key":          sign(ca, otherKey, id, now, connca.ConnectionLifetime),
		"another agent":        sign(ca, key, "019a3f2e-7c11-7d3e-9f7b-000000000000", now, connca.ConnectionLifetime),
		"another CA":           sign(other, key, id, now, connca.ConnectionLifetime),
		"shorter than current": sign(ca, key, id, now, connca.MinConnectionLifetime),
		"already expired":      sign(ca, key, id, now.Add(-25*time.Hour), connca.ConnectionLifetime),
		"not yet valid":        sign(ca, key, id, now.Add(time.Hour), connca.ConnectionLifetime),
		"not a certificate":    []byte("x"),
	} {
		if _, err := checkRenewed(der, current, caCert, id, key, now); !errors.Is(err, ErrBadCertificate) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func testCA(t *testing.T) *connca.Authority {
	t.Helper()
	a, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// caCertificate returns the CA's own certificate, which a server sends after
// its leaf.
func caCertificate(t *testing.T, a *connca.Authority) *x509.Certificate {
	t.Helper()
	c, err := a.ServerCertificate([]string{"x"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(c.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// badRenewal is an orchestrator that welcomes the agent and answers every
// renewal with the certificate cert returns.
type badRenewal struct {
	agentv1.UnimplementedAgentServiceServer
	cert func() []byte
}

func (b badRenewal) Connect(stream agentv1.AgentService_ConnectServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{Message: &agentv1.ConnectResponse_Welcome{Welcome: &agentv1.Welcome{ProtocolVersion: ProtocolVersion}}}); err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
	}
}

func (b badRenewal) RenewCertificate(context.Context, *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
	return &agentv1.RenewCertificateResponse{ConnectionCertificate: b.cert()}, nil
}

// serveBadRenewal runs badRenewal with a server certificate from ca, and
// returns its address under the name localhost.
func serveBadRenewal(t *testing.T, ca *connca.Authority, cert func() []byte) string {
	t.Helper()
	serverCert, err := ca.ServerCertificate([]string{"localhost"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	creds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    ca.Pool(),
	})
	srv := grpc.NewServer(grpc.Creds(creds))
	agentv1.RegisterAgentServiceServer(srv, badRenewal{cert: cert})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return net.JoinHostPort("localhost", port)
}

// pointAt changes the orchestrator address in the agent's saved state.
func pointAt(t *testing.T, dir, addr string) {
	t.Helper()
	path := filepath.Join(dir, StateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["orchestrator"] = addr
	if data, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A renewal that returns an unusable certificate must leave the working one
// in place, so the agent can still reconnect.
func TestBadRenewalKeepsTheCurrentCertificate(t *testing.T) {
	o := servertest.Start(t)
	dir := agentDir(t)
	if _, err := enroll(t, dir, install(o, o.Token(t, "lab", "agent-a"), "agent-a")); err != nil {
		t.Fatal(err)
	}
	s, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	// Signed by the pinned CA for this agent's ID, but for another key.
	wrongKey, err := o.CA.SignAgent(csr, s.AgentID, time.Now(), connca.ConnectionLifetime)
	if err != nil {
		t.Fatal(err)
	}
	pointAt(t, dir, serveBadRenewal(t, o.CA, func() []byte { return wrongKey }))
	before, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}

	r := runAgent(t, dir, func() time.Time { return time.Now().Add(13 * time.Hour) })
	r.events.waitFor(t, "renewal failed", 2)
	r.cancel()
	_ = r.wait(t)
	if n := r.events.count("renewed"); n != 0 {
		t.Fatalf("accepted %d bad renewals", n)
	}
	after, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a bad renewal replaced the saved certificate")
	}
}

func TestHelloReportsTheAllowlistHash(t *testing.T) {
	doc := "version: 1\napprovals: 1\nsend_to: [{workspace: lab}]\n"
	for name, a := range map[string]*allowlist.Allowlist{"none": nil, "a file": allow(t, doc)} {
		r := newRunner(t.TempDir(), RunConfig{Allowlist: a}, State{}, nil)
		want := a.Hash()
		if got := r.hello().GetHello().GetAllowlistHash(); !bytes.Equal(got, want[:]) {
			t.Errorf("%s: hello has %x, want %x", name, got, want)
		}
	}
	if none := (*allowlist.Allowlist)(nil).Hash(); none != sha256.Sum256(nil) {
		t.Error("a missing allowlist doesn't hash as no bytes")
	}
}

func TestAChangedAllowlistIsLogged(t *testing.T) {
	dir := t.TempDir()
	start := func(a *allowlist.Allowlist) *events {
		t.Helper()
		log := &events{}
		cfg := RunConfig{Allowlist: a, Log: log}
		cfg.defaults()
		if err := newRunner(dir, cfg, State{}, nil).noteAllowlist(); err != nil {
			t.Fatal(err)
		}
		return log
	}
	first := allow(t, "")
	second := allow(t, "version: 1\napprovals: 1\nsend_to: [{workspace: lab}]\n")
	if log := start(first); len(lines(t, log)) != 0 {
		t.Fatalf("the first start logged %v", lines(t, log))
	}
	if log := start(first); len(lines(t, log)) != 0 {
		t.Fatalf("an unchanged allowlist logged %v", lines(t, log))
	}
	log := start(second)
	got := lines(t, log)
	h1, h2 := first.Hash(), second.Hash()
	if len(got) != 1 || got[0]["event"] != "allowlist changed" ||
		got[0]["previous_sha256"] != hex.EncodeToString(h1[:]) || got[0]["sha256"] != hex.EncodeToString(h2[:]) {
		t.Fatalf("logged %v", got)
	}
	saved, err := os.ReadFile(filepath.Join(dir, AllowlistHashFile))
	if err != nil || string(saved) != hex.EncodeToString(h2[:]) {
		t.Fatalf("saved %q, %v", saved, err)
	}
}

// lines decodes every line logged so far.
func lines(t *testing.T, e *events) []map[string]any {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(e.buf.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}
