package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"mmft.dev/mmft/internal/flow"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// flowLab is a server with two approved agents in one workspace.
type flowLab struct {
	harness
	approver
	a, b *runAgentFor
}

func newFlowLab(t *testing.T) flowLab {
	t.Helper()
	h := start(t)
	ap := newApprover(t)
	return flowLab{harness: h, approver: ap, a: h.approvedAgent(t, ap, "lab", "agent-a"), b: h.approvedAgent(t, ap, "lab", "agent-b")}
}

func (l flowLab) jsonCall(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return l.do(t, method, path, data)
}

func (l flowLab) createFlow(t *testing.T, name string) flowItem {
	t.Helper()
	code, data := l.jsonCall(t, http.MethodPost, "/api/v1/flows", map[string]string{"name": name, "workspace": "lab"})
	if code != http.StatusCreated {
		t.Fatalf("create flow: %d %s", code, data)
	}
	var f flowItem
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// cards is a source on from and one destination on to.
func cards(from, to, path string) []map[string]any {
	return []map[string]any{
		{"id": "pickup", "type": "source", "agent": from, "path": "/srv/outbox"},
		{"id": "ledger", "type": "destination", "parent": "pickup", "agent": to, "path": path},
	}
}

func (l flowLab) saveDraft(t *testing.T, flowID string, c []map[string]any) (int, []byte) {
	t.Helper()
	return l.jsonCall(t, http.MethodPost, "/api/v1/flows/"+flowID+"/versions", map[string]any{"schema_version": 1, "cards": c})
}

func (l flowLab) draft(t *testing.T, flowID, path string) flowVersionItem {
	t.Helper()
	code, data := l.saveDraft(t, flowID, cards(l.a.id, l.b.id, path))
	if code != http.StatusCreated {
		t.Fatalf("save draft: %d %s", code, data)
	}
	var v flowVersionItem
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (l flowLab) version(t *testing.T, flowID string, n int) flowVersionItem {
	t.Helper()
	code, data := l.do(t, http.MethodGet, "/api/v1/flows/"+flowID+"/versions/"+strconv.Itoa(n), nil)
	if code != http.StatusOK {
		t.Fatalf("get version %d: %d %s", n, code, data)
	}
	var v flowVersionItem
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// bundle packs a signed statement with certificates and the approver's root.
func (a approver) bundle(t *testing.T, e *statement.Envelope, certs ...[]byte) []byte {
	t.Helper()
	signed, _ := json.Marshal(e)
	raw := make([]json.RawMessage, len(certs))
	for i, c := range certs {
		raw[i] = c
	}
	ed, ml := a.root.Public().Bytes()
	data, err := json.Marshal(trust.Approval{Statement: signed, AdministratorCertificates: raw, RootEd25519: ed, RootMLDSA65: ml})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// approve signs payload as the approver's administrator and bundles it.
func (a approver) approve(t *testing.T, payload []byte) []byte {
	t.Helper()
	e, err := statement.Sign(statement.TypeFlowVersion, payload, a.admin)
	if err != nil {
		t.Fatal(err)
	}
	return a.bundle(t, e, a.cert)
}

func (l flowLab) putApproval(t *testing.T, flowID string, n int, body []byte) (int, []byte) {
	t.Helper()
	return l.do(t, http.MethodPut, "/api/v1/flows/"+flowID+"/versions/"+strconv.Itoa(n)+"/approval", body)
}

func TestCreateFlow(t *testing.T) {
	l := newFlowLab(t)
	f := l.createFlow(t, "invoices-daily")
	if !trust.ValidAgentID(f.ID) || f.Workspace != "lab" || f.LatestVersion != nil {
		t.Errorf("created %+v", f)
	}
	if code, _ := l.jsonCall(t, http.MethodPost, "/api/v1/flows", map[string]string{"name": "invoices-daily", "workspace": "lab"}); code != http.StatusConflict {
		t.Errorf("same name: %d", code)
	}
	if code, _ := l.jsonCall(t, http.MethodPost, "/api/v1/flows", map[string]string{"name": "x", "workspace": "nowhere"}); code != http.StatusBadRequest {
		t.Errorf("unknown workspace: %d", code)
	}
	if code, _ := l.jsonCall(t, http.MethodPost, "/api/v1/flows", map[string]string{"name": "bad name", "workspace": "lab"}); code != http.StatusBadRequest {
		t.Errorf("invalid name: %d", code)
	}
}

func TestDraftsAreNumberedAndCarryTheirPayload(t *testing.T) {
	l := newFlowLab(t)
	f := l.createFlow(t, "invoices-daily")
	v1 := l.draft(t, f.ID, "/srv/inbox")
	v2 := l.draft(t, f.ID, "/srv/inbox-2")
	if v1.Version != 1 || v2.Version != 2 || v1.Status != "draft" {
		t.Fatalf("versions %d %d, status %s", v1.Version, v2.Version, v1.Status)
	}
	parsed, err := flow.Parse(v1.Payload)
	if err != nil {
		t.Fatalf("stored payload doesn't parse: %v", err)
	}
	sum := sha256.Sum256(v1.Payload)
	if v1.PayloadSHA256 != hex.EncodeToString(sum[:]) {
		t.Error("payload_sha256 doesn't match the payload")
	}
	if parsed.FlowID != f.ID || parsed.Workspace != "lab" || parsed.FlowVersion != 1 || len(parsed.Agents) != 2 {
		t.Errorf("payload %+v", parsed)
	}
	got := l.version(t, f.ID, 1)
	if string(got.Payload) != string(v1.Payload) || len(got.Definition.Cards) != 2 || got.Approval != nil {
		t.Errorf("read back %+v", got)
	}
	if code, _ := l.do(t, http.MethodGet, "/api/v1/flows/"+f.ID+"/versions/9", nil); code != http.StatusNotFound {
		t.Errorf("missing version: %d", code)
	}
}

func TestInvalidDraftsAreRefused(t *testing.T) {
	l := newFlowLab(t)
	f := l.createFlow(t, "invoices-daily")
	pending := l.approvedAgent(t, approver{}, "lab", "agent-p")
	elsewhere := l.approvedAgent(t, l.approver, "other", "agent-x")
	badParent := cards(l.a.id, l.b.id, "/srv/inbox")
	badParent[1]["parent"] = "pickup2"
	for name, tc := range map[string]struct {
		cards []map[string]any
		want  string
	}{
		"unknown parent":             {badParent, `cards[1].parent: no card \"pickup2\"`},
		"path with ..":               {cards(l.a.id, l.b.id, "/srv/inbox/../etc"), `cards[1].path`},
		"agent not approved":         {cards(l.a.id, pending.id, "/srv/inbox"), "must be approved"},
		"agent in another workspace": {cards(l.a.id, elsewhere.id, "/srv/inbox"), "must be approved"},
	} {
		t.Run(name, func(t *testing.T) {
			code, data := l.saveDraft(t, f.ID, tc.cards)
			if code != http.StatusBadRequest || !strings.Contains(string(data), tc.want) {
				t.Errorf("%d %s, want 400 containing %s", code, data, tc.want)
			}
		})
	}
	code, data := l.do(t, http.MethodPost, "/api/v1/flows/"+f.ID+"/versions", []byte(`{"schema_version":2,"cards":[]}`))
	if code != http.StatusBadRequest {
		t.Errorf("schema_version 2: %d %s", code, data)
	}
	if code, _ := l.saveDraft(t, "0190f9c3-2b7d-7e01-8000-0000000000ff", cards(l.a.id, l.b.id, "/srv/inbox")); code != http.StatusNotFound {
		t.Errorf("unknown flow: %d", code)
	}
	var stored int
	if err := l.db.QueryRow(t.Context(), `SELECT count(*) FROM flow_versions`).Scan(&stored); err != nil || stored != 0 {
		t.Errorf("stored %d versions, err %v", stored, err)
	}
}

func TestApprovalApprovesExactlyTheDraft(t *testing.T) {
	l := newFlowLab(t)
	f := l.createFlow(t, "invoices-daily")
	v1 := l.draft(t, f.ID, "/srv/inbox")
	v2 := l.draft(t, f.ID, "/srv/inbox-2")

	first := l.approve(t, v1.Payload)
	if code, data := l.putApproval(t, f.ID, 1, first); code != http.StatusNoContent {
		t.Fatalf("approve v1: %d %s", code, data)
	}
	if got := l.version(t, f.ID, 1); got.Status != "approved" || string(got.Approval) != string(first) {
		t.Errorf("v1 after approval: %s", got.Status)
	}
	if code, data := l.putApproval(t, f.ID, 1, first); code != http.StatusNoContent {
		t.Errorf("same approval again: %d %s", code, data)
	}
	// Signed again, it is the same statement, and the first approval stays.
	if code, _ := l.putApproval(t, f.ID, 1, l.approve(t, v1.Payload)); code != http.StatusNoContent {
		t.Errorf("v1 signed again: %d", code)
	}
	if got := l.version(t, f.ID, 1); string(got.Approval) != string(first) {
		t.Error("a second approval replaced the first")
	}

	if code, data := l.putApproval(t, f.ID, 2, l.approve(t, v2.Payload)); code != http.StatusNoContent {
		t.Fatalf("approve v2: %d %s", code, data)
	}
	if got := l.version(t, f.ID, 1); got.Status != "superseded" {
		t.Errorf("v1 after v2 is approved: %s", got.Status)
	}
	if code, _ := l.putApproval(t, f.ID, 1, first); code != http.StatusConflict {
		t.Errorf("approving the superseded v1: %d", code)
	}
	code, data := l.do(t, http.MethodGet, "/api/v1/flows", nil)
	if code != http.StatusOK || !strings.Contains(string(data), `"approved_version":2`) || !strings.Contains(string(data), `"latest_version":2`) {
		t.Errorf("list: %d %s", code, data)
	}
}

func TestForgedApprovalsAreRefused(t *testing.T) {
	l := newFlowLab(t)
	other := newApprover(t)
	f := l.createFlow(t, "invoices-daily")
	v1 := l.draft(t, f.ID, "/srv/inbox")
	v2 := l.draft(t, f.ID, "/srv/inbox-2")

	byOther, err := statement.Sign(statement.TypeFlowVersion, v1.Payload, other.admin)
	if err != nil {
		t.Fatal(err)
	}
	tampered := l.approve(t, v1.Payload)
	var a trust.Approval
	if err := json.Unmarshal(tampered, &a); err != nil {
		t.Fatal(err)
	}
	var e statement.Envelope
	if err := json.Unmarshal(a.Statement, &e); err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
	sig[0] ^= 1
	e.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
	identity := l.sign(t, l.a.id, "lab", "agent-a", l.a.keys)

	for name, body := range map[string][]byte{
		// The signer's certificate isn't in the bundle.
		"signer without a certificate": l.bundle(t, byOther, l.cert),
		// The certificate is real, but issued by another root than the bundle's.
		"certificate from another root": l.bundle(t, byOther, other.cert),
		"tampered signature":            l.bundle(t, &e, l.cert),
		// An agent identity isn't an administrator certificate.
		"identity as a certificate": l.bundle(t, byOther, identity),
		// A valid approval of v2 can't approve v1.
		"approval of another version": l.approve(t, v2.Payload),
		"not an approval":             []byte(`{}`),
	} {
		t.Run(name, func(t *testing.T) {
			if code, data := l.putApproval(t, f.ID, 1, body); code != http.StatusBadRequest {
				t.Errorf("%d %s", code, data)
			}
		})
	}
	if got := l.version(t, f.ID, 1); got.Status != "draft" || got.Approval != nil {
		t.Errorf("v1 is %s after refused approvals", got.Status)
	}
	if code, _ := l.putApproval(t, f.ID, 7, l.approve(t, v1.Payload)); code != http.StatusNotFound {
		t.Errorf("missing version: %d", code)
	}
}
