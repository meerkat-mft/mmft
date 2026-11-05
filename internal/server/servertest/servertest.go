// Package servertest runs a real orchestrator on a migrated test database, for
// tests in other packages. Set MMFT_TEST_DATABASE_URL to run them.
package servertest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/db/dbtest"
	"mmft.dev/mmft/internal/server"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// AdminToken is the bootstrap token the test orchestrator accepts.
const AdminToken = "bootstrap-token-for-tests-only"

// Orchestrator is a running test orchestrator. It is reachable as localhost, so
// the pinned CA's name check applies.
type Orchestrator struct {
	CA *connca.Authority
	// GRPC and API are host:port addresses that use the name localhost.
	GRPC string
	API  string
}

// Start runs an orchestrator until the test ends.
func Start(t testing.TB) Orchestrator {
	t.Helper()
	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(AdminToken))
	s, err := server.New(server.Config{Authority: ca, DB: dbtest.Pool(t), Names: []string{"localhost"}, AdminTokenSHA256: hex.EncodeToString(sum[:])})
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
	return Orchestrator{CA: ca, GRPC: byName(g.Addr()), API: byName(a.Addr())}
}

func byName(addr net.Addr) string {
	_, port, _ := net.SplitHostPort(addr.String())
	return net.JoinHostPort("localhost", port)
}

func (o Orchestrator) client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: connca.PinnedClient(o.CA.Fingerprint(), "localhost", time.Now)}}
}

// Token creates an enrollment token through the REST API.
func (o Orchestrator) Token(t testing.TB, workspace, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"agent_name": name, "workspace": workspace})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+o.API+"/api/v1/agents/enrollment-tokens", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+AdminToken)
	resp, err := o.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: %d %v", resp.StatusCode, err)
	}
	return out.Token
}

// PutIdentity stores an identity statement through the REST API and returns
// the HTTP status.
func (o Orchestrator) PutIdentity(t testing.TB, agentID string, identity []byte) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, "https://"+o.API+"/api/v1/agents/"+agentID+"/identity", bytes.NewReader(identity))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+AdminToken)
	resp, err := o.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// Approver signs agent identities with a fresh trust root and administrator
// key, held in memory.
type Approver struct {
	Root        *statement.Signer
	Admin       *statement.Signer
	Certificate []byte
}

// NewApprover creates a root and an administrator key certified for a day.
func NewApprover(t testing.TB) Approver {
	t.Helper()
	root, err := statement.GenerateSigner(statement.RoleRoot)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := statement.GenerateSigner(statement.RoleAdministrator)
	if err != nil {
		t.Fatal(err)
	}
	ed, ml := admin.Public().Bytes()
	e, err := trust.CertifyAdministrator(root, root.Public().Fingerprint(),
		trust.PublicRecord{Version: 1, Owner: "sam.lee", Ed25519: ed, MLDSA65: ml}, admin.Public().Fingerprint(), time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return Approver{Root: root, Admin: admin, Certificate: cert}
}

// RootFingerprint is the fingerprint agents pin.
func (a Approver) RootFingerprint() string {
	return a.Root.Public().Fingerprint()
}

// Sign signs an identity for an agent, valid for an hour.
func (a Approver) Sign(t testing.TB, agentID, workspace, name string, keys trust.AgentKeys) []byte {
	t.Helper()
	e, err := trust.CertifyAgent(a.Admin, a.Certificate, a.Root.Public(), a.RootFingerprint(), trust.AgentRequest{
		AgentID: agentID, Workspace: workspace, AgentName: name, Keys: keys,
		ExpectedFingerprint: keys.Fingerprint(), ExpectedID: agentID, ExpectedWorkspace: workspace, ExpectedName: name,
	}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
