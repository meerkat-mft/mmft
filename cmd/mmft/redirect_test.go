package main

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mmft.dev/mmft/internal/connca"
)

// The API never redirects, so a redirect must not carry the token anywhere,
// least of all to plain HTTP on the same host.
func TestAPIClientRefusesRedirects(t *testing.T) {
	var leaked atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer plain.Close()

	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	target := strings.Replace(plain.URL, "127.0.0.1", "localhost", 1) + "/api/v1/agents"
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	}))
	api.TLS = &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return ca.ServerCertificate([]string{"localhost"}, time.Now())
	}}
	api.StartTLS()
	defer api.Close()

	client, err := newAPIClient(strings.Replace(api.Listener.Addr().String(), "127.0.0.1", "localhost", 1), ca.Fingerprint(), "secret-token", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.do(http.MethodGet, "/agents", nil, http.StatusOK, nil); !errors.Is(err, errRedirect) {
		t.Fatalf("err = %v", err)
	}
	if leaked.Load() {
		t.Fatal("the token was sent over plain HTTP")
	}
}
