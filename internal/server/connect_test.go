package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/connca"
)

// startWithSilence starts a server that closes a silent stream after d.
func startWithSilence(t *testing.T, d time.Duration) harness {
	t.Helper()
	saved := defaultLimits
	defaultLimits.streamSilence = d
	t.Cleanup(func() { defaultLimits = saved })
	return start(t)
}

// openStream connects as the agent and returns the stream and the first
// reply's error, after sending first.
func (h harness) openStream(t *testing.T, a enrolled, first *agentv1.ConnectRequest) (agentv1.AgentService_ConnectClient, *agentv1.ConnectResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentServiceClient(h.dial(t, a.cert)).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A refused stream can fail the send with io.EOF. The status comes from
	// the receive either way.
	_ = stream.Send(first)
	resp, err := stream.Recv()
	return stream, resp, err
}

func heartbeat() *agentv1.ConnectRequest {
	return &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}
}

func TestConnectNeedsAHelloFirst(t *testing.T) {
	h := start(t)
	a := h.enrollAgent(t, "lab", "agent-a")
	if _, _, err := h.openStream(t, a, heartbeat()); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("heartbeat first: %v", err)
	}
	if _, _, err := h.openStream(t, a, hello(ProtocolVersion+1)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("other protocol: %v", err)
	}
	for _, v := range []string{"", "1.0\n", string(make([]byte, 65))} {
		bad := &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{ProtocolVersion: ProtocolVersion, AgentVersion: v}}}
		if _, _, err := h.openStream(t, a, bad); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("agent version %q: %v", v, err)
		}
	}
	stream, resp, err := h.openStream(t, a, hello(ProtocolVersion))
	if err != nil || resp.GetWelcome().GetProtocolVersion() != ProtocolVersion {
		t.Fatalf("welcome = %v, %v", resp, err)
	}
	if err := stream.Send(hello(ProtocolVersion)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("second hello: %v", err)
	}
}

type presence struct {
	AgentVersion *string    `json:"agent_version"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
}

func (h harness) presence(t *testing.T, id string) presence {
	t.Helper()
	code, body := h.do(t, http.MethodGet, "/api/v1/agents/"+id, nil)
	if code != http.StatusOK {
		t.Fatalf("get agent: %d %s", code, body)
	}
	var p presence
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// waitSeen waits for the server to record the agent as seen at want.
func (h harness) waitSeen(t *testing.T, id string, want time.Time) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p := h.presence(t, id)
		if p.LastSeenAt != nil && p.LastSeenAt.Equal(want.Truncate(time.Microsecond)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("last_seen_at = %v, want %v", p.LastSeenAt, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestConnectRecordsPresence(t *testing.T) {
	h := start(t)
	a := h.enrollAgent(t, "lab", "agent-a")
	if p := h.presence(t, a.id); p.AgentVersion != nil || p.LastSeenAt != nil {
		t.Fatalf("presence before connecting: %+v", p)
	}
	stream, _, err := h.openStream(t, a, hello(ProtocolVersion))
	if err != nil {
		t.Fatal(err)
	}
	h.waitSeen(t, a.id, h.clock.now())
	if p := h.presence(t, a.id); p.AgentVersion == nil || *p.AgentVersion != "test" {
		t.Fatalf("agent version = %v", p.AgentVersion)
	}
	h.clock.advance(time.Minute)
	if err := stream.Send(heartbeat()); err != nil {
		t.Fatal(err)
	}
	h.waitSeen(t, a.id, h.clock.now())
}

// A certificate lasts a day, so a revoked agent's open stream must not.
func TestRevokedAgentsStreamEndsAtItsNextHeartbeat(t *testing.T) {
	h := start(t)
	a := h.enrollAgent(t, "lab", "agent-a")
	stream, _, err := h.openStream(t, a, hello(ProtocolVersion))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(context.Background(), `UPDATE agents SET status = 'revoked' WHERE id = $1`, a.id); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(heartbeat()); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("after revocation: %v", err)
	}
}

func TestSilentStreamIsClosed(t *testing.T) {
	h := startWithSilence(t, 300*time.Millisecond)
	a := h.enrollAgent(t, "lab", "agent-a")
	stream, _, err := h.openStream(t, a, hello(ProtocolVersion))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := stream.Recv(); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("silent stream: %v", err)
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("closed after %v", waited)
	}
}

func TestHeartbeatsKeepAStreamOpen(t *testing.T) {
	h := startWithSilence(t, 500*time.Millisecond)
	a := h.enrollAgent(t, "lab", "agent-a")
	stream, _, err := h.openStream(t, a, hello(ProtocolVersion))
	if err != nil {
		t.Fatal(err)
	}
	for range 15 {
		if err := stream.Send(heartbeat()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The stream outlived its silence limit three times over, and ends
	// cleanly when the agent closes its side.
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("after heartbeats: %v", err)
	}
}

func (h harness) renew(t *testing.T, a enrolled, csr []byte) (*agentv1.RenewCertificateResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return agentv1.NewAgentServiceClient(h.dial(t, a.cert)).RenewCertificate(ctx, &agentv1.RenewCertificateRequest{CertificateRequest: csr})
}

func TestRenewalKeepsTheConnectionKey(t *testing.T) {
	h := start(t)
	a := h.enrollAgent(t, "lab", "agent-a")
	key := a.cert.PrivateKey.(ed25519.PrivateKey)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.advance(time.Hour)
	resp, err := h.renew(t, a, csr)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(resp.GetConnectionCertificate())
	if err != nil {
		t.Fatal(err)
	}
	if id, err := connca.AgentID(cert); err != nil || id != a.id {
		t.Fatalf("renewed ID = %q, %v", id, err)
	}
	if !key.Public().(ed25519.PublicKey).Equal(cert.PublicKey) {
		t.Fatal("renewal changed the key")
	}
	// Certificates hold whole seconds.
	if got := cert.NotAfter.Sub(h.clock.now()); got <= connca.ConnectionLifetime-time.Second || got > connca.ConnectionLifetime {
		t.Fatalf("lifetime = %v", got)
	}

	// A pending agent renews too, so a slow approval doesn't strand it.
	if p := h.list(t, ""); len(p.Items) != 1 || p.Items[0].Status != "pending_approval" {
		t.Fatalf("agents = %+v", p.Items)
	}

	if _, err := h.renew(t, a, csrFor(t)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another key: %v", err)
	}
	if _, err := h.renew(t, a, []byte("not a request")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad request: %v", err)
	}
}
