package connca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const agentID = "019a3f2e-7c11-7d3e-9f7b-2c1d4e5f6a7b"

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func authority(t *testing.T) *Authority {
	t.Helper()
	a, err := Create(filepath.Join(t.TempDir(), "ca"), now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func request(t *testing.T, template *x509.CertificateRequest) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCreateAndLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	a, err := Create(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint() != a.Fingerprint() || len(a.Fingerprint()) != 64 {
		t.Fatalf("fingerprints: %s, %s", a.Fingerprint(), loaded.Fingerprint())
	}
	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}
	if _, err := Create(dir, now); !errors.Is(err, os.ErrExist) {
		t.Fatalf("replaced a CA: %v", err)
	}
}

func TestLoadRejectsMismatchedKey(t *testing.T) {
	dirA, dirB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	if _, err := Create(dirA, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dirB, now); err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(filepath.Join(dirB, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirA, caKeyFile), other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dirA); err == nil {
		t.Fatal("mismatched key accepted")
	}
}

func TestSignAgent(t *testing.T) {
	a := authority(t)
	der, err := a.SignAgent(request(t, &x509.CertificateRequest{}), agentID, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := AgentID(cert); err != nil || got != agentID {
		t.Fatalf("agent ID = %q, %v", got, err)
	}
	if got := cert.NotAfter.Sub(now); got != ConnectionLifetime {
		t.Fatalf("lifetime = %v", got)
	}
	if cert.IsCA {
		t.Fatal("agent certificate is a CA")
	}
	opts := x509.VerifyOptions{Roots: a.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatal(err)
	}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, err := cert.Verify(opts); err == nil {
		t.Fatal("agent certificate works as a server")
	}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	opts.CurrentTime = now.Add(ConnectionLifetime + time.Second)
	if _, err := cert.Verify(opts); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestRequestCannotChooseItsOwnIdentity(t *testing.T) {
	a := authority(t)
	spoofed, err := url.Parse(agentURI + "019a3f2e-0000-7d3e-9f7b-2c1d4e5f6a7b")
	if err != nil {
		t.Fatal(err)
	}
	der, err := a.SignAgent(request(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "orchestrator"},
		DNSNames: []string{"orchestrator"},
		URIs:     []*url.URL{spoofed},
	}), agentID, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := AgentID(cert); got != agentID {
		t.Fatalf("agent ID = %q", got)
	}
	if len(cert.DNSNames) != 0 || cert.Subject.CommonName == "orchestrator" {
		t.Fatalf("request set names: %v %s", cert.DNSNames, cert.Subject.CommonName)
	}
}

func TestSignAgentRejects(t *testing.T) {
	a := authority(t)
	good := request(t, &x509.CertificateRequest{})
	if _, err := a.SignAgent(good, "not-a-uuid", now); !errors.Is(err, ErrInvalidAgentID) {
		t.Fatalf("bad ID: %v", err)
	}
	if _, err := a.SignAgent(good[:20], agentID, now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("damaged request: %v", err)
	}
	if _, err := a.SignAgent(make([]byte, maxCSRBytes+1), agentID, now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("large request: %v", err)
	}
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 1
	if _, err := a.SignAgent(tampered, agentID, now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad signature: %v", err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SignAgent(der, agentID, now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("wrong key type: %v", err)
	}
}

func TestServerCertificateIsNotAClientCertificate(t *testing.T) {
	a := authority(t)
	c, err := a.ServerCertificate([]string{"orchestrator"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AgentID(c.Leaf); !errors.Is(err, ErrNotAnAgent) {
		t.Fatalf("err = %v", err)
	}
	opts := x509.VerifyOptions{Roots: a.Pool(), CurrentTime: now, DNSName: "orchestrator", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := c.Leaf.Verify(opts); err != nil {
		t.Fatal(err)
	}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if _, err := c.Leaf.Verify(opts); err == nil {
		t.Fatal("server certificate works as a client")
	}
}

func TestAgentIDRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"other scheme": "https://example.com/" + agentID,
		"bad ID":       agentURI + "nope",
		"extra path":   agentURI + agentID + "/x",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AgentID(&x509.Certificate{URIs: []*url.URL{u}}); !errors.Is(err, ErrNotAnAgent) {
			t.Errorf("%s: %v", name, err)
		}
	}
	u, _ := url.Parse(agentURI + agentID)
	if _, err := AgentID(&x509.Certificate{URIs: []*url.URL{u, u}}); !errors.Is(err, ErrNotAnAgent) {
		t.Errorf("two URIs: %v", err)
	}
}
