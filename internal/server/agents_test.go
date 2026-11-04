package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

func (h harness) do(t *testing.T, method, path string, body []byte) (int, []byte) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.pool, ServerName: "orchestrator.test", MinVersion: tls.VersionTLS13}}}
	req, err := http.NewRequestWithContext(context.Background(), method, "https://"+h.apiAddr+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

type listed struct {
	Items      []agentItem `json:"items"`
	NextCursor string      `json:"next_cursor"`
}

func (h harness) list(t *testing.T, query string) listed {
	t.Helper()
	code, data := h.do(t, http.MethodGet, "/api/v1/agents"+query, nil)
	if code != http.StatusOK {
		t.Fatalf("list %q: %d %s", query, code, data)
	}
	var page listed
	if err := json.Unmarshal(data, &page); err != nil {
		t.Fatal(err)
	}
	return page
}

// approver signs identities with a fresh root and administrator key.
type approver struct {
	root  *statement.Signer
	admin *statement.Signer
	cert  []byte
}

func newApprover(t *testing.T) approver {
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
	cert, _ := json.Marshal(e)
	return approver{root: root, admin: admin, cert: cert}
}

func (a approver) sign(t *testing.T, id, workspace, name string, keys trust.AgentKeys) []byte {
	t.Helper()
	e, err := trust.CertifyAgent(a.admin, a.cert, a.root.Public(), a.root.Public().Fingerprint(), trust.AgentRequest{
		AgentID: id, Workspace: workspace, AgentName: name, Keys: keys,
		ExpectedFingerprint: keys.Fingerprint(), ExpectedID: id, ExpectedName: name,
	}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	return b
}

type enrolled struct {
	id   string
	keys trust.AgentKeys
	cert tls.Certificate
}

// enrollAgent enrolls an agent and keeps its connection key, so it can call
// the agent service.
func (h harness) enrollAgent(t *testing.T, workspace, name string) enrolled {
	t.Helper()
	_, connKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, connKey)
	if err != nil {
		t.Fatal(err)
	}
	req := newAgentWithCSR(t, h.token(t, workspace, name), name, csr)
	resp, err := h.enroll(t, req)
	if err != nil {
		t.Fatal(err)
	}
	return enrolled{
		id:   resp.GetAgentId(),
		keys: trust.AgentKeys{Ed25519: req.GetEd25519PublicKey(), MLDSA65: req.GetMldsa65PublicKey(), Recipient: req.GetEncryptionRecipient()},
		cert: tls.Certificate{Certificate: [][]byte{resp.GetConnectionCertificate()}, PrivateKey: connKey},
	}
}

func (h harness) getIdentity(t *testing.T, a enrolled) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := agentv1.NewAgentServiceClient(h.dial(t, a.cert)).GetIdentity(ctx, &agentv1.GetIdentityRequest{})
	return resp.GetIdentityStatement(), err
}

func TestListAgentsShowsPendingKeys(t *testing.T) {
	h := start(t)
	a := h.enrollAgent(t, "lab", "agent-a")
	page := h.list(t, "?status=pending_approval")
	if len(page.Items) != 1 || page.NextCursor != "" {
		t.Fatalf("page = %+v", page)
	}
	got := page.Items[0]
	if got.ID != a.id || got.Name != "agent-a" || got.Workspace != "lab" || got.Status != "pending_approval" || got.IdentityExpiresAt != nil {
		t.Fatalf("item = %+v", got)
	}
	if got.PublicKeys == nil || (trust.AgentKeys{Ed25519: got.PublicKeys.Ed25519, MLDSA65: got.PublicKeys.MLDSA65, Recipient: got.PublicKeys.Recipient}).Fingerprint() != a.keys.Fingerprint() {
		t.Fatal("listed keys differ from the enrolled keys")
	}
	if page := h.list(t, "?status=approved"); len(page.Items) != 0 {
		t.Fatalf("approved = %+v", page)
	}
}

func TestListAgentsPages(t *testing.T) {
	h := start(t)
	for _, name := range []string{"agent-a", "agent-b", "agent-c"} {
		h.enrollAgent(t, "lab", name)
	}
	var names []string
	query := "?limit=2"
	for range 3 {
		page := h.list(t, query)
		for _, item := range page.Items {
			names = append(names, item.Name)
		}
		if page.NextCursor == "" {
			break
		}
		query = "?limit=2&cursor=" + page.NextCursor
	}
	if len(names) != 3 || names[0] != "agent-a" || names[2] != "agent-c" {
		t.Fatalf("names = %v", names)
	}
	for _, q := range []string{"?status=online", "?limit=0", "?limit=201", "?cursor=nope"} {
		if code, _ := h.do(t, http.MethodGet, "/api/v1/agents"+q, nil); code != http.StatusBadRequest {
			t.Errorf("%s: code = %d", q, code)
		}
	}
}

func TestStoredIdentityApprovesTheAgent(t *testing.T) {
	h := start(t)
	ap := newApprover(t)
	a := h.enrollAgent(t, "lab", "agent-a")
	if _, err := h.getIdentity(t, a); status.Code(err) != codes.NotFound {
		t.Fatalf("before approval: err = %v", err)
	}
	identity := ap.sign(t, a.id, "lab", "agent-a", a.keys)
	path := "/api/v1/agents/" + a.id + "/identity"
	if code, data := h.do(t, http.MethodPut, path, identity); code != http.StatusNoContent {
		t.Fatalf("put: %d %s", code, data)
	}
	got, err := h.getIdentity(t, a)
	if err != nil || !bytes.Equal(got, identity) {
		t.Fatalf("identity = %d bytes, %v", len(got), err)
	}
	page := h.list(t, "?status=approved")
	if len(page.Items) != 1 || page.Items[0].IdentityExpiresAt == nil {
		t.Fatalf("approved = %+v", page)
	}

	// The same statement again is a safe repeat, even with its signatures
	// reordered and its JSON reformatted, and a different one is refused.
	if code, _ := h.do(t, http.MethodPut, path, identity); code != http.StatusNoContent {
		t.Fatalf("repeat: %d", code)
	}
	var e statement.Envelope
	if err := json.Unmarshal(identity, &e); err != nil {
		t.Fatal(err)
	}
	e.Signatures[0], e.Signatures[1] = e.Signatures[1], e.Signatures[0]
	reordered, _ := json.MarshalIndent(e, "", "  ")
	if code, data := h.do(t, http.MethodPut, path, reordered); code != http.StatusNoContent {
		t.Fatalf("reordered repeat: %d %s", code, data)
	}
	if got, err := h.getIdentity(t, a); err != nil || !bytes.Equal(got, identity) {
		t.Fatalf("stored bytes changed: %v", err)
	}
	if code, _ := h.do(t, http.MethodPut, path, ap.sign(t, a.id, "lab", "agent-a", a.keys)); code != http.StatusConflict {
		t.Fatalf("second identity: %d", code)
	}
}

func TestIdentityMustMatchTheAgent(t *testing.T) {
	h := start(t)
	ap := newApprover(t)
	a := h.enrollAgent(t, "lab", "agent-a")
	b := h.enrollAgent(t, "lab", "agent-b")
	path := "/api/v1/agents/" + a.id + "/identity"
	cases := map[string]struct {
		path     string
		identity []byte
		want     int
	}{
		"other agent's keys": {path, ap.sign(t, a.id, "lab", "agent-a", b.keys), http.StatusBadRequest},
		"other workspace":    {path, ap.sign(t, a.id, "other", "agent-a", a.keys), http.StatusBadRequest},
		"other name":         {path, ap.sign(t, a.id, "lab", "agent-x", a.keys), http.StatusBadRequest},
		"other agent's path": {"/api/v1/agents/" + b.id + "/identity", ap.sign(t, a.id, "lab", "agent-a", a.keys), http.StatusBadRequest},
		"unknown agent":      {"/api/v1/agents/" + agentID + "/identity", ap.sign(t, agentID, "lab", "agent-a", a.keys), http.StatusNotFound},
		"not a statement":    {path, []byte(`{"payload":"x"}`), http.StatusBadRequest},
		"malformed agent ID": {"/api/v1/agents/nope/identity", ap.sign(t, a.id, "lab", "agent-a", a.keys), http.StatusNotFound},
	}
	for name, c := range cases {
		if code, data := h.do(t, http.MethodPut, c.path, c.identity); code != c.want {
			t.Errorf("%s: %d %s", name, code, data)
		}
	}
	if page := h.list(t, "?status=pending_approval"); len(page.Items) != 2 {
		t.Fatalf("pending = %+v", page)
	}
	var stored int
	if err := h.db.QueryRow(context.Background(), `SELECT count(*) FROM signed_statements`).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("stored statements = %d, %v", stored, err)
	}
}

func TestRevokedAgentGetsNoIdentity(t *testing.T) {
	h := start(t)
	a := h.enrollAgent(t, "lab", "agent-a")
	if _, err := h.db.Exec(context.Background(), `UPDATE agents SET status = 'revoked' WHERE id = $1`, a.id); err != nil {
		t.Fatal(err)
	}
	identity := newApprover(t).sign(t, a.id, "lab", "agent-a", a.keys)
	if code, _ := h.do(t, http.MethodPut, "/api/v1/agents/"+a.id+"/identity", identity); code != http.StatusConflict {
		t.Fatalf("code = %d", code)
	}
}
