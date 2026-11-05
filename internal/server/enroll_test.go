package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"filippo.io/age"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

func (h harness) post(t *testing.T, path, token string, body any) (int, map[string]string) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.pool, ServerName: "orchestrator.test", MinVersion: tls.VersionTLS13}}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+h.apiAddr+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	flat := map[string]string{}
	for k, v := range out {
		if s, ok := v.(string); ok {
			flat[k] = s
		}
	}
	return resp.StatusCode, flat
}

func (h harness) token(t *testing.T, workspace, name string) string {
	t.Helper()
	code, body := h.post(t, "/api/v1/agents/enrollment-tokens", adminToken, map[string]string{"agent_name": name, "workspace": workspace})
	if code != http.StatusCreated || body["token"] == "" {
		t.Fatalf("create token: %d %v", code, body)
	}
	return body["token"]
}

// newAgent builds a complete, valid enrollment request for a token in the
// lab workspace.
func newAgent(t *testing.T, token, name string) *agentv1.EnrollRequest {
	t.Helper()
	_, connKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, connKey)
	if err != nil {
		t.Fatal(err)
	}
	return newAgentWithCSR(t, token, "lab", name, csr)
}

// newAgentWithCSR builds a request with a valid proof over any CSR bytes.
func newAgentWithCSR(t *testing.T, token, workspace, name string, csr []byte) *agentv1.EnrollRequest {
	t.Helper()
	signer, err := statement.GenerateSigner(statement.RoleAgent)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipient := enc.Recipient().String()
	proof, err := trust.ProveEnrollment(signer, token, workspace, name, recipient, csr)
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, _ := json.Marshal(proof)
	ed, ml := signer.Public().Bytes()
	keys := trust.AgentKeys{Ed25519: ed, MLDSA65: ml, Recipient: recipient}
	return &agentv1.EnrollRequest{
		Token: token, AgentId: keys.AgentID(), Workspace: workspace, AgentName: name, Ed25519PublicKey: ed, Mldsa65PublicKey: ml,
		EncryptionRecipient: recipient, CertificateRequest: csr, ProofStatement: proofBytes,
	}
}

func (h harness) enroll(t *testing.T, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return agentv1.NewEnrollmentServiceClient(h.dial(t)).Enroll(ctx, req)
}

func TestEnrollCreatesAPendingAgent(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")
	req := newAgent(t, token, "agent-a")
	resp, err := h.enroll(t, req)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(resp.GetConnectionCertificate())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: h.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if id, err := connca.AgentID(cert); err != nil || id != resp.GetAgentId() {
		t.Fatalf("certificate names %q, %v; want %q", id, err, resp.GetAgentId())
	}

	ctx := context.Background()
	var agentStatus, workspace, recipient string
	var ed, ml []byte
	if err := h.db.QueryRow(ctx, `
		SELECT a.status, w.name, i.ed25519_public_key, i.mldsa65_public_key, i.encryption_recipient
		FROM agents a JOIN workspaces w ON w.id = a.workspace_id JOIN agent_identities i ON i.agent_id = a.id
		WHERE a.id = $1`, resp.GetAgentId()).Scan(&agentStatus, &workspace, &ed, &ml, &recipient); err != nil {
		t.Fatal(err)
	}
	if agentStatus != "pending_approval" || workspace != "lab" {
		t.Fatalf("status %q in workspace %q", agentStatus, workspace)
	}
	if !bytes.Equal(ed, req.GetEd25519PublicKey()) || !bytes.Equal(ml, req.GetMldsa65PublicKey()) || recipient != req.GetEncryptionRecipient() {
		t.Fatal("stored keys differ from the request")
	}
}

func TestTokensAreStoredOnlyAsHashes(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")
	sum := sha256.Sum256([]byte(token))
	var n int
	if err := h.db.QueryRow(context.Background(), `SELECT count(*) FROM enrollment_tokens WHERE token_sha256 = $1`, sum[:]).Scan(&n); err != nil || n != 1 {
		t.Fatalf("count = %d, %v", n, err)
	}
	var dump string
	if err := h.db.QueryRow(context.Background(), `SELECT string_agg(t::text, ',') FROM enrollment_tokens t`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(dump), []byte(token)) {
		t.Fatal("the token is stored in the clear")
	}
}

func TestUsedTokenFails(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")
	if _, err := h.enroll(t, newAgent(t, token, "agent-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.enroll(t, newAgent(t, token, "agent-a")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("second use: %v", err)
	}
}

// An agent whose response was lost can repeat its request with the same keys,
// even after the token expires, and gets the same agent.
func TestSameAgentCanRepeatEnrollment(t *testing.T) {
	h := start(t)
	req := newAgent(t, h.token(t, "lab", "agent-a"), "agent-a")
	first, err := h.enroll(t, req)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.advance(TokenLifetime)
	again, err := h.enroll(t, req)
	if err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if again.GetAgentId() != first.GetAgentId() || len(again.GetConnectionCertificate()) == 0 {
		t.Fatalf("repeat gave agent %q, want %q", again.GetAgentId(), first.GetAgentId())
	}
	var agents int
	if err := h.db.QueryRow(context.Background(), `SELECT count(*) FROM agents`).Scan(&agents); err != nil || agents != 1 {
		t.Fatalf("agents = %d, %v", agents, err)
	}

	if _, err := h.db.Exec(context.Background(), `UPDATE agent_identities SET revoked_at = now() WHERE agent_id = $1`, first.GetAgentId()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.enroll(t, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked identity: %v", err)
	}
	if _, err := h.db.Exec(context.Background(), `UPDATE agents SET status = 'revoked' WHERE id = $1`, first.GetAgentId()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.enroll(t, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked agent: %v", err)
	}
}

func TestExpiredTokenFails(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")
	h.clock.advance(TokenLifetime)
	if _, err := h.enroll(t, newAgent(t, token, "agent-a")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expired: %v", err)
	}
}

// A token that expires while Enroll waits for its row lock must be refused.
func TestTokenExpiringDuringLockWaitFails(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")
	sum := sha256.Sum256([]byte(token))
	ctx := context.Background()
	holder, err := h.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT 1 FROM enrollment_tokens WHERE token_sha256 = $1 FOR UPDATE`, sum[:]); err != nil {
		t.Fatal(err)
	}

	req := newAgent(t, token, "agent-a")
	client := agentv1.NewEnrollmentServiceClient(h.dial(t))
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := client.Enroll(ctx, req)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := h.db.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE '%FROM enrollment_tokens t JOIN workspaces%FOR UPDATE%'
				AND pid <> pg_backend_pid()`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Enroll never waited for the token's lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.clock.advance(TokenLifetime)
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expired during lock wait: %v", err)
	}
}

func TestTokenIsBoundToItsAgentName(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")
	if _, err := h.enroll(t, newAgent(t, token, "agent-b")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other name: %v", err)
	}
	if _, err := h.enroll(t, newAgent(t, "unknown-token", "agent-a")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestBadRequestsDoNotUseUpTheToken(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")
	other := newAgent(t, token, "agent-a")
	bad := map[string]func(*agentv1.EnrollRequest){
		"proof from other keys": func(r *agentv1.EnrollRequest) { r.ProofStatement = other.GetProofStatement() },
		"swapped recipient":     func(r *agentv1.EnrollRequest) { r.EncryptionRecipient = other.GetEncryptionRecipient() },
		"swapped csr":           func(r *agentv1.EnrollRequest) { r.CertificateRequest = other.GetCertificateRequest() },
		"no proof":              func(r *agentv1.EnrollRequest) { r.ProofStatement = nil },
		"no keys":               func(r *agentv1.EnrollRequest) { r.Mldsa65PublicKey = nil },
	}
	for name, change := range bad {
		req := newAgent(t, token, "agent-a")
		change(req)
		if _, err := h.enroll(t, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.enroll(t, newAgent(t, token, "agent-a")); err != nil {
		t.Fatalf("token was used up: %v", err)
	}
}

// A request that passes the proof check but fails inside the transaction must
// leave nothing behind and keep the token usable.
func TestFailureInsideTheTransactionRollsBack(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")
	if _, err := h.enroll(t, newAgentWithCSR(t, token, "lab", "agent-a", []byte("not a certificate request"))); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed CSR: %v", err)
	}

	ctx := context.Background()
	sum := sha256.Sum256([]byte(token))
	var agents, identities int
	var used bool
	if err := h.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM agents), (SELECT count(*) FROM agent_identities),
		(SELECT used_at IS NOT NULL FROM enrollment_tokens WHERE token_sha256 = $1)`, sum[:]).Scan(&agents, &identities, &used); err != nil {
		t.Fatal(err)
	}
	if agents != 0 || identities != 0 || used {
		t.Fatalf("left %d agents, %d identities, token used %v", agents, identities, used)
	}
	if _, err := h.enroll(t, newAgent(t, token, "agent-a")); err != nil {
		t.Fatalf("token was used up: %v", err)
	}
}

func TestCreateTokenValidates(t *testing.T) {
	h := start(t)
	path := "/api/v1/agents/enrollment-tokens"
	for name, body := range map[string]any{
		"bad name":      map[string]string{"agent_name": "../x", "workspace": "lab"},
		"no workspace":  map[string]string{"agent_name": "agent-a"},
		"unknown field": map[string]string{"agent_name": "agent-a", "workspace": "lab", "extra": "x"},
		"not an object": []string{"agent-a"},
	} {
		if code, _ := h.post(t, path, adminToken, body); code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, code)
		}
	}
	if code, _ := h.post(t, path, "wrong", map[string]string{"agent_name": "agent-a", "workspace": "lab"}); code != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d", code)
	}

	if _, err := h.enroll(t, newAgent(t, h.token(t, "lab", "agent-a"), "agent-a")); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.post(t, path, adminToken, map[string]string{"agent_name": "agent-a", "workspace": "lab"}); code != http.StatusConflict {
		t.Errorf("existing agent: status %d", code)
	}
	h.token(t, "other", "agent-a")
}

// ADR 0019: the orchestrator never chooses an agent's ID or workspace.
func TestEnrollUsesTheHostsIDAndWorkspace(t *testing.T) {
	h := start(t)
	token := h.token(t, "lab", "agent-a")

	other := newAgent(t, token, "agent-a")
	wrongID := newAgent(t, token, "agent-a")
	wrongID.AgentId = other.GetAgentId()
	if _, err := h.enroll(t, wrongID); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ID not from the keys: %v", err)
	}
	if _, err := h.enroll(t, newAgentWithCSR(t, token, "prod", "agent-a", csrFor(t))); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("workspace other than the token's: %v", err)
	}

	req := newAgent(t, token, "agent-a")
	resp, err := h.enroll(t, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetAgentId() != req.GetAgentId() {
		t.Fatalf("stored as %q, asked for %q", resp.GetAgentId(), req.GetAgentId())
	}

	// The same keys can't become a second agent under another name.
	again := newAgentWithCSR(t, h.token(t, "lab", "agent-b"), "lab", "agent-b", csrFor(t))
	again.Ed25519PublicKey, again.Mldsa65PublicKey, again.EncryptionRecipient = req.GetEd25519PublicKey(), req.GetMldsa65PublicKey(), req.GetEncryptionRecipient()
	again.AgentId = req.GetAgentId()
	if _, err := h.enroll(t, again); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("reused keys without their private half: %v", err)
	}
}

func csrFor(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}
