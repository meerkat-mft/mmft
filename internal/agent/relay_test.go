package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/relay"
	"mmft.dev/mmft/internal/relayticket"
	"mmft.dev/mmft/internal/server/servertest"
)

// relayLab is an orchestrator, a relay that trusts its CA, and two enrolled
// agents with no other path between them.
type relayLab struct {
	o          servertest.Orchestrator
	relayAddr  string
	relayFP    []byte
	ticketKey  ed25519.PrivateKey
	a, b       string
	aID, bID   string
	relayEvent func() string
}

func startRelayLab(t *testing.T) *relayLab {
	t.Helper()
	o := servertest.Start(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "relay")
	fp, err := relay.CreateIdentity(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := relay.LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(o.CA.CertificatePEM())
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	log := &events{}
	s, err := relay.New(relay.Config{Identity: identity, ConnectionCA: caCert, TicketKey: key.Public().(ed25519.PublicKey), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("relay: %v", err)
		}
	})
	l := &relayLab{o: o, relayAddr: lis.Addr().String(), relayFP: fp, ticketKey: key, relayEvent: func() string {
		log.mu.Lock()
		defer log.mu.Unlock()
		return log.buf.String()
	}}
	l.a, l.aID = l.enroll(t, "agent-a")
	l.b, l.bID = l.enroll(t, "agent-b")
	return l
}

func (l *relayLab) enroll(t *testing.T, name string) (dir, id string) {
	t.Helper()
	dir = agentDir(t)
	s, err := enroll(t, dir, install(l.o, l.o.Token(t, "lab", name), name))
	if err != nil {
		t.Fatal(err)
	}
	return dir, s.AgentID
}

// tickets returns the send ticket for a and the receive ticket for b, both
// pointing at addr.
func (l *relayLab) tickets(t *testing.T, addr string, expires time.Time) (send, receive *agentv1.RelayTicket) {
	t.Helper()
	delivery := "0190a0b0-0000-7000-8000-000000000001"
	issue := func(role relayticket.Role, holder, peer string) *agentv1.RelayTicket {
		data, err := relayticket.Issue(l.ticketKey, relayticket.Ticket{DeliveryID: delivery, Role: role, Holder: holder, Peer: peer, ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
		return &agentv1.RelayTicket{DeliveryId: delivery, Ticket: data, RelayAddress: addr, RelayCertificateSha256: l.relayFP}
	}
	return issue(relayticket.Send, l.aID, l.bID), issue(relayticket.Receive, l.bID, l.aID)
}

var fastRetry = RelayConfig{MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}

// background runs f until the test ends and returns its result channel.
func background(t *testing.T, f func(context.Context) error) <-chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	got := make(chan error, 1)
	go func() { got <- f(ctx) }()
	return got
}

func sealedFile(t *testing.T, size int) (string, []byte) {
	t.Helper()
	data := make([]byte, size)
	_, _ = rand.Read(data)
	path := filepath.Join(t.TempDir(), "sealed")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

// slowProxy forwards TCP connections to target at a limited rate, so a test
// can cut a delivery partway through, and can drop every connection.
type slowProxy struct {
	addr  string
	mu    sync.Mutex
	conns []net.Conn
}

func startSlowProxy(t *testing.T, target string) *slowProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &slowProxy{addr: ln.Addr().String()}
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 16<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if err != nil {
				break
			}
		}
		_ = dst.Close()
	}
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
			go pipe(up, c)
			go pipe(c, up)
		}
	}()
	t.Cleanup(p.drop)
	return p
}

func (p *slowProxy) drop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

func waitForSize(t *testing.T, path string, atLeast int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if info, err := os.Stat(path); err == nil && info.Size() >= atLeast {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached %d bytes", path, atLeast)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRelayResumesAfterTheConnectionDrops(t *testing.T) {
	l := startRelayLab(t)
	p := startSlowProxy(t, l.relayAddr)
	// The proxy is slow on purpose, so keep the file small enough for a busy
	// machine running every package under the race detector.
	src, data := sealedFile(t, 2<<20)
	dst := filepath.Join(t.TempDir(), "spool")
	send, receive := l.tickets(t, p.addr, time.Now().Add(relayticket.Lifetime))
	received := background(t, func(ctx context.Context) error {
		return ReceiveFile(ctx, l.b, receive, dst, uint64(len(data)), fastRetry)
	})
	sent := background(t, func(ctx context.Context) error { return SendFile(ctx, l.a, send, src, fastRetry) })

	waitForSize(t, dst, 256<<10)
	p.drop()
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() >= int64(len(data)) {
		t.Fatal("the file arrived before the connection dropped")
	}

	if err := <-received; err != nil {
		t.Fatalf("ReceiveFile: %v", err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("SendFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("received %d bytes that differ from the %d sent", len(got), len(data))
	}
	log := l.relayEvent()
	if !strings.Contains(log, `"event":"forwarding failed"`) || !strings.Contains(log, `"event":"delivery forwarded"`) {
		t.Fatalf("the relay did not log a failure and then the delivery:\n%s", log)
	}
}

func TestReceiveFileResumesAPartialFile(t *testing.T) {
	l := startRelayLab(t)
	src, data := sealedFile(t, 600<<10)
	dst := filepath.Join(t.TempDir(), "spool")
	// The partial file differs from the source, so a fresh download would
	// show: only bytes after it may arrive.
	partial := bytes.Repeat([]byte{0xAA}, 100<<10)
	if err := os.WriteFile(dst, partial, 0o600); err != nil {
		t.Fatal(err)
	}
	send, receive := l.tickets(t, l.relayAddr, time.Now().Add(relayticket.Lifetime))
	received := background(t, func(ctx context.Context) error {
		return ReceiveFile(ctx, l.b, receive, dst, uint64(len(data)), fastRetry)
	})
	sent := background(t, func(ctx context.Context) error { return SendFile(ctx, l.a, send, src, fastRetry) })
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Clone(partial), data[len(partial):]...)
	if !bytes.Equal(got, want) {
		t.Fatal("the receiver did not resume from its partial file")
	}
}

func TestAgentsRefuseTheWrongRelayByItsTicket(t *testing.T) {
	l := startRelayLab(t)
	src, _ := sealedFile(t, 1024)
	dst := filepath.Join(t.TempDir(), "spool")
	send, receive := l.tickets(t, l.relayAddr, time.Now().Add(relayticket.Lifetime))
	send.RelayCertificateSha256 = bytes.Clone(l.relayFP)
	send.RelayCertificateSha256[0] ^= 1
	received := background(t, func(ctx context.Context) error { return ReceiveFile(ctx, l.b, receive, dst, 1024, fastRetry) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := SendFile(ctx, l.a, send, src, fastRetry); !errors.Is(err, relay.ErrWrongRelay) {
		t.Fatalf("SendFile = %v, want %v", err, relay.ErrWrongRelay)
	}
	select {
	case err := <-received:
		t.Fatalf("ReceiveFile returned %v with no sender", err)
	default:
	}
	if info, err := os.Stat(dst); err != nil || info.Size() != 0 {
		t.Fatalf("the spool file has data: %v", err)
	}
}

func TestExpiredTicketStopsTheAgent(t *testing.T) {
	l := startRelayLab(t)
	src, _ := sealedFile(t, 1024)
	send, _ := l.tickets(t, l.relayAddr, time.Now().Add(-time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := SendFile(ctx, l.a, send, src, fastRetry)
	if status.Code(err) != codes.PermissionDenied || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SendFile = %v, want PermissionDenied at once", err)
	}
}

func TestReceiveFileTakesNoMoreThanTheSealedSize(t *testing.T) {
	l := startRelayLab(t)
	// The sender offers more than the manifest's size, as a bad relay could.
	src, _ := sealedFile(t, 600<<10)
	dst := filepath.Join(t.TempDir(), "spool")
	send, receive := l.tickets(t, l.relayAddr, time.Now().Add(relayticket.Lifetime))
	size := uint64(100 << 10)
	_ = background(t, func(ctx context.Context) error { return SendFile(ctx, l.a, send, src, fastRetry) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ReceiveFile(ctx, l.b, receive, dst, size, fastRetry); !errors.Is(err, ErrBadRelay) {
		t.Fatalf("ReceiveFile = %v, want ErrBadRelay", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > int64(size) {
		t.Fatalf("the spool file grew to %d bytes, past %d", info.Size(), size)
	}
}

func TestReceiveFileRefusesASpoolFileLongerThanTheSealedSize(t *testing.T) {
	l := startRelayLab(t)
	dst := filepath.Join(t.TempDir(), "spool")
	if err := os.WriteFile(dst, make([]byte, 20), 0o600); err != nil {
		t.Fatal(err)
	}
	_, receive := l.tickets(t, l.relayAddr, time.Now().Add(relayticket.Lifetime))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ReceiveFile(ctx, l.b, receive, dst, 10, fastRetry); !errors.Is(err, ErrSpoolTooLong) {
		t.Fatalf("ReceiveFile = %v, want ErrSpoolTooLong", err)
	}
}
