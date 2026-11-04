package connca

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// handshake runs one TLS handshake between a server presenting cert and a
// pinned client, and returns the client's error.
func handshake(t *testing.T, cert *tls.Certificate, pin, name string) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.(*tls.Conn).Handshake()
		_ = c.Close()
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := tls.Client(conn, PinnedClient(pin, name, func() time.Time { return now }))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	return client.Handshake()
}

func TestPinnedClientTrustsOnlyThePinnedCA(t *testing.T) {
	a, other := authority(t), authority(t)
	cert, err := a.ServerCertificate([]string{"orchestrator"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, cert, a.Fingerprint(), "orchestrator"); err != nil {
		t.Fatalf("pinned CA: %v", err)
	}
	if err := handshake(t, cert, other.Fingerprint(), "orchestrator"); !errors.Is(err, ErrWrongServer) {
		t.Errorf("other pin: %v", err)
	}
	if err := handshake(t, cert, a.Fingerprint(), "elsewhere"); !errors.Is(err, ErrWrongServer) {
		t.Errorf("other name: %v", err)
	}
	if err := handshake(t, cert, "", "orchestrator"); !errors.Is(err, ErrWrongServer) {
		t.Errorf("no pin: %v", err)
	}

	leafOnly := *cert
	leafOnly.Certificate = cert.Certificate[:1]
	if err := handshake(t, &leafOnly, a.Fingerprint(), "orchestrator"); !errors.Is(err, ErrWrongServer) {
		t.Errorf("no CA in chain: %v", err)
	}

	// A server holding another CA's certificate can send the pinned CA's
	// certificate too, but its own certificate must still be issued by it.
	forged, err := other.ServerCertificate([]string{"orchestrator"}, now)
	if err != nil {
		t.Fatal(err)
	}
	forged.Certificate = [][]byte{forged.Certificate[0], a.cert.Raw}
	if err := handshake(t, forged, a.Fingerprint(), "orchestrator"); !errors.Is(err, ErrWrongServer) {
		t.Errorf("forged chain: %v", err)
	}
}

func TestPinnedClientRejectsExpiredServers(t *testing.T) {
	a := authority(t)
	cert, err := a.ServerCertificate([]string{"orchestrator"}, now.Add(-2*ServerLifetime))
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, cert, a.Fingerprint(), "orchestrator"); !errors.Is(err, ErrWrongServer) {
		t.Errorf("expired: %v", err)
	}
}
