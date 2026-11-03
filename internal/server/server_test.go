package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/db/dbtest"
)

const (
	adminToken = "bootstrap-token-for-tests-only"
	agentID    = "019a3f2e-7c11-7d3e-9f7b-2c1d4e5f6a7b"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harness struct {
	clock    *clock
	ca       *connca.Authority
	db       *pgxpool.Pool
	grpcAddr string
	apiAddr  string
	pool     *x509.CertPool
}

func start(t *testing.T) harness {
	t.Helper()
	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(adminToken))
	pool := dbtest.Pool(t)
	c := &clock{t: time.Now()}
	s, err := New(Config{Authority: ca, DB: pool, Names: []string{"orchestrator.test"}, AdminTokenSHA256: hex.EncodeToString(sum[:]), Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	g, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, g, a) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	})
	return harness{clock: c, ca: ca, db: pool, grpcAddr: g.Addr().String(), apiAddr: a.Addr().String(), pool: ca.Pool()}
}

func clientCert(t *testing.T, ca *connca.Authority, id string) tls.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.SignAgent(csr, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (h harness) dial(t *testing.T, certs ...tls.Certificate) *grpc.ClientConn {
	t.Helper()
	cfg := &tls.Config{RootCAs: h.pool, ServerName: "orchestrator.test", MinVersion: tls.VersionTLS13, Certificates: certs}
	conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func callConnect(t *testing.T, conn *grpc.ClientConn) codes.Code {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := agentv1.NewAgentServiceClient(conn).Connect(ctx)
	if err == nil {
		_, err = stream.Recv()
	}
	return status.Code(err)
}

func TestEnrollmentNeedsNoCertificate(t *testing.T) {
	h := start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := agentv1.NewEnrollmentServiceClient(h.dial(t)).Enroll(ctx, &agentv1.EnrollRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v", err)
	}
}

func TestAgentServiceRequiresACertificate(t *testing.T) {
	h := start(t)
	if got := callConnect(t, h.dial(t)); got != codes.Unauthenticated {
		t.Fatalf("no certificate: %v", got)
	}
	if got := callConnect(t, h.dial(t, clientCert(t, h.ca, agentID))); got != codes.Unimplemented {
		t.Fatalf("valid certificate: %v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := agentv1.NewAgentServiceClient(h.dial(t)).RenewCertificate(ctx, &agentv1.RenewCertificateRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unary without a certificate: %v", err)
	}
}

func TestCertificateFromAnotherCAIsRefused(t *testing.T) {
	h := start(t)
	other, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := callConnect(t, h.dial(t, clientCert(t, other, agentID))); got == codes.Unimplemented {
		t.Fatal("foreign certificate reached the service")
	}
}

func TestServerCertificateCannotActAsAnAgent(t *testing.T) {
	h := start(t)
	c, err := h.ca.ServerCertificate([]string{"x"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := callConnect(t, h.dial(t, *c)); got == codes.Unimplemented {
		t.Fatal("server certificate reached the service")
	}
}

func TestOldTLSIsRefused(t *testing.T) {
	h := start(t)
	for _, addr := range []string{h.grpcAddr, h.apiAddr} {
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: h.pool, ServerName: "orchestrator.test", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
		if err == nil {
			_ = conn.Close()
			t.Fatalf("TLS 1.2 accepted on %s", addr)
		}
	}
}

func (h harness) status(t *testing.T, path, token string) int {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.pool, ServerName: "orchestrator.test", MinVersion: tls.VersionTLS13}}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+h.apiAddr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestAPIAuthentication(t *testing.T) {
	h := start(t)
	tests := []struct {
		name, path, token string
		want              int
	}{
		{"health is open", "/api/v1/health", "", 200},
		{"no token", "/api/v1/agents", "", 401},
		{"wrong token", "/api/v1/agents", "wrong", 401},
		{"hash used as token", "/api/v1/agents", strings.Repeat("0", 64), 401},
		{"right token", "/api/v1/agents", adminToken, 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.status(t, tt.path, tt.token); got != tt.want {
				t.Fatalf("status = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNewValidatesConfig(t *testing.T) {
	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	good := strings.Repeat("a", 64)
	pool := dbtest.Pool(t)
	for name, cfg := range map[string]Config{
		"no CA":       {DB: pool, Names: []string{"x"}, AdminTokenSHA256: good},
		"no database": {Authority: ca, Names: []string{"x"}, AdminTokenSHA256: good},
		"no names":    {Authority: ca, DB: pool, AdminTokenSHA256: good},
		"no hash":     {Authority: ca, DB: pool, Names: []string{"x"}},
		"short hash":  {Authority: ca, DB: pool, Names: []string{"x"}, AdminTokenSHA256: "abcd"},
		"not hex":     {Authority: ca, DB: pool, Names: []string{"x"}, AdminTokenSHA256: strings.Repeat("z", 64)},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestServerCertificateIsReplaced(t *testing.T) {
	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s, err := New(Config{Authority: ca, DB: dbtest.Pool(t), Names: []string{"x"}, AdminTokenSHA256: strings.Repeat("a", 64), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.certificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := s.certificate(nil)
	if again != first {
		t.Fatal("fresh certificate was replaced")
	}
	now = now.Add(connca.ServerLifetime/2 + time.Hour)
	later, _ := s.certificate(nil)
	if later == first {
		t.Fatal("ageing certificate was kept")
	}
}
