package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"mmft.dev/mmft/internal/connca"
)

// These tests hold connections open without ever reaching the database, so
// they run without MMFT_TEST_DATABASE_URL. The pool points at a closed port and
// never connects.
func startWithLimits(t *testing.T, l limits) harness {
	t.Helper()
	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), "postgres://x:y@127.0.0.1:1/x?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sum := sha256.Sum256([]byte(adminToken))
	saved := defaultLimits
	defaultLimits = l
	t.Cleanup(func() { defaultLimits = saved })
	s, err := New(Config{Authority: ca, DB: pool, Names: []string{"orchestrator.test"}, AdminTokenSHA256: hex.EncodeToString(sum[:])})
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
	return harness{ca: ca, grpcAddr: g.Addr().String(), apiAddr: a.Addr().String(), pool: ca.Pool()}
}

func fastLimits() limits {
	return limits{
		maxConnections: 1024,
		maxStreams:     2,
		connectionIdle: 5 * time.Minute,
		readTimeout:    300 * time.Millisecond,
		writeTimeout:   300 * time.Millisecond,
		idleTimeout:    300 * time.Millisecond,
	}
}

func (h harness) tlsDial(t *testing.T, addr string, protos ...string) *tls.Conn {
	t.Helper()
	d := &tls.Dialer{Config: &tls.Config{RootCAs: h.pool, ServerName: "orchestrator.test", MinVersion: tls.VersionTLS13, NextProtos: protos}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*tls.Conn)
}

// drain reads until the server ends the connection and fails if that takes
// longer than the deadline.
func drain(t *testing.T, c net.Conn, within time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within))
	got, err := io.ReadAll(c)
	if err == nil {
		return got
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the server kept the connection open for %v", within)
	}
	return got
}

func TestAPIDropsARequestWhoseBodyNeverArrives(t *testing.T) {
	h := startWithLimits(t, fastLimits())
	c := h.tlsDial(t, h.apiAddr)
	_, err := io.WriteString(c, "POST /api/v1/agents/enrollment-tokens HTTP/1.1\r\nHost: orchestrator.test\r\nContent-Length: 10\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	drain(t, c, 3*time.Second)
}

func TestAPIClosesAnIdleConnection(t *testing.T) {
	h := startWithLimits(t, fastLimits())
	c := h.tlsDial(t, h.apiAddr)
	if _, err := io.WriteString(c, "GET /api/v1/health HTTP/1.1\r\nHost: orchestrator.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	got := drain(t, c, 3*time.Second)
	if !bytes.HasPrefix(got, []byte("HTTP/1.1 200")) {
		t.Fatalf("health reply: %q", got)
	}
}

func TestListenersCapConnections(t *testing.T) {
	l := fastLimits()
	l.maxConnections = 1
	h := startWithLimits(t, l)
	first := h.tlsDial(t, h.apiAddr)

	d := &tls.Dialer{Config: &tls.Config{RootCAs: h.pool, ServerName: "orchestrator.test", MinVersion: tls.VersionTLS13}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if c, err := d.DialContext(ctx, "tcp", h.apiAddr); err == nil {
		_ = c.Close()
		t.Fatal("a second connection was accepted past the cap")
	}
	_ = first.Close()
	h.tlsDial(t, h.apiAddr).Close()
}

// TestGRPCCapsStreamsPerConnection speaks raw HTTP/2 so a stream can be opened
// and left without a body, which the gRPC client library never does.
func TestGRPCCapsStreamsPerConnection(t *testing.T) {
	l := fastLimits()
	h := startWithLimits(t, l)
	c := h.tlsDial(t, h.grpcAddr, "h2")
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(c, c)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var advertised uint32
	for advertised == 0 {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			if v, ok := sf.Value(http2.SettingMaxConcurrentStreams); ok {
				advertised = v
			}
		}
	}
	if advertised != l.maxStreams {
		t.Fatalf("advertised %d concurrent streams, want %d", advertised, l.maxStreams)
	}

	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/mmft.agent.v1.EnrollmentService/Enroll"},
		{Name: ":authority", Value: "orchestrator.test"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	} {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	// Open one stream more than allowed, none with a body.
	last := uint32(2*l.maxStreams + 1)
	for id := uint32(1); id <= last; id += 2 {
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: buf.Bytes(), EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(fmt.Errorf("waiting for the refused stream: %w", err))
		}
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			if rst.StreamID != last || rst.ErrCode != http2.ErrCodeRefusedStream {
				t.Fatalf("stream %d reset with %v; want stream %d refused", rst.StreamID, rst.ErrCode, last)
			}
			return
		}
	}
}
