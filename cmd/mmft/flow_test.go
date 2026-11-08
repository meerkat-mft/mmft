//go:build !windows

// These tests store private keys, which Windows refuses until its access
// control lists are checked. See perm_windows.go.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mmft.dev/mmft/internal/server/servertest"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// flowSetup is an orchestrator with two approved agents and one flow.
type flowSetup struct {
	approveSetup
	flowID, agentA, agentB string
}

func newFlowSetup(t *testing.T) flowSetup {
	t.Helper()
	a := newApproveSetup(t)
	agentA, _ := a.install(t, "agent-a")
	agentB, _ := a.install(t, "agent-b")
	if code, report, errOut := a.approve(t, collected(agentA)+collected(agentB)); code != exitOK || len(report.Approved) != 2 {
		t.Fatalf("approve agents: %d %+v %s", code, report, errOut)
	}
	code, out := a.o.Call(t, http.MethodPost, "/api/v1/flows", map[string]string{"name": "invoices-daily", "workspace": "lab"})
	if code != http.StatusCreated {
		t.Fatalf("create flow: %d %v", code, out)
	}
	return flowSetup{approveSetup: a, flowID: out["id"].(string), agentA: agentA.AgentID, agentB: agentB.AgentID}
}

// draft saves a version delivering to path on agent-b.
func (f flowSetup) draft(t *testing.T, path string) int {
	t.Helper()
	code, out := f.o.Call(t, http.MethodPost, "/api/v1/flows/"+f.flowID+"/versions", map[string]any{
		"schema_version": 1,
		"cards": []map[string]any{
			{"id": "pickup", "type": "source", "agent": f.agentA, "path": "/srv/outbox"},
			{"id": "ledger", "type": "destination", "parent": "pickup", "agent": f.agentB, "path": path},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("draft: %d %v", code, out)
	}
	return int(out["version"].(float64))
}

func (f flowSetup) status(t *testing.T, n int) string {
	t.Helper()
	_, out := f.o.Call(t, http.MethodGet, "/api/v1/flows/"+f.flowID+"/versions/"+strconv.Itoa(n), nil)
	return out["status"].(string)
}

// flow runs a flow command with the connection and trust flags filled in.
func (f flowSetup) flow(t *testing.T, verb string, extra ...string) (int, map[string]any, string) {
	t.Helper()
	args := []string{"flow", verb, "--api", f.o.API, "--ca-fingerprint", f.o.CA.Fingerprint(), "--token-file", f.tokenFile,
		"--root-public", filepath.Join(f.rootDir, "root.pub.json"), "--root-fingerprint", f.rootFP, "--flow", f.flowID}
	if verb != "diff" {
		args = append(args, "--admin-dir", f.adminDir, "--passphrase-file", f.passFile, "--certificate", f.cert)
	}
	var out, errOut bytes.Buffer
	code := run(append(args, extra...), &out, &errOut, time.Now)
	var result map[string]any
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("output is not JSON: %q", out.String())
		}
	}
	return code, result, errOut.String()
}

// diff returns the hash to approve version n by, and the changes shown.
func (f flowSetup) diff(t *testing.T, n int) (string, map[string]any) {
	t.Helper()
	code, out, errOut := f.flow(t, "diff", "--version", strconv.Itoa(n))
	if code != exitOK {
		t.Fatalf("diff v%d: %d %s", n, code, errOut)
	}
	return out["sha256"].(string), out["changes"].(map[string]any)
}

func count(changes map[string]any, key string) int {
	return len(changes[key].([]any))
}

func TestApproveByReviewedHash(t *testing.T) {
	f := newFlowSetup(t)
	v1 := f.draft(t, "/srv/inbox")
	sha, changes := f.diff(t, v1)
	if count(changes, "cards_added") != 2 || count(changes, "agents_added") != 2 {
		t.Errorf("first version: %v", changes)
	}
	code, out, errOut := f.flow(t, "approve", "--version", "1", "--sha256", sha)
	if code != exitOK || out["status"] != "approved" || out["approved_by"] != "sam.lee" {
		t.Fatalf("approve v1: %d %v %s", code, out, errOut)
	}
	if got := f.status(t, v1); got != "approved" {
		t.Fatalf("v1 is %s", got)
	}
	if code, _, _ := f.flow(t, "approve", "--version", "1", "--sha256", sha); code != exitExists {
		t.Errorf("approve v1 again: %d", code)
	}

	v2 := f.draft(t, "/srv/inbox-2")
	sha2, changes := f.diff(t, v2)
	changed := changes["cards_changed"].([]any)
	if len(changed) != 1 || changed[0].(map[string]any)["to"] != "/srv/inbox-2" || count(changes, "cards_added") != 0 {
		t.Errorf("second version: %v", changes)
	}
	// The hash of v1 doesn't approve v2.
	code, _, errOut = f.flow(t, "approve", "--version", "2", "--sha256", sha)
	if code != exitRefused || !strings.Contains(errOut, `"error"`) {
		t.Fatalf("wrong hash: %d %s", code, errOut)
	}
	if got := f.status(t, v2); got != "draft" {
		t.Fatalf("v2 is %s after a refused approval", got)
	}
	if code, _, errOut := f.flow(t, "approve", "--version", "2", "--sha256", sha2); code != exitOK {
		t.Fatalf("approve v2: %d %s", code, errOut)
	}
	if got := f.status(t, v1); got != "superseded" {
		t.Errorf("v1 is %s", got)
	}
}

func TestApproveNeedsAHash(t *testing.T) {
	f := newFlowSetup(t)
	f.draft(t, "/srv/inbox")
	for _, sha := range []string{"", "abc", strings.Repeat("A", 64)} {
		if code, _, _ := f.flow(t, "approve", "--version", "1", "--sha256", sha); code != exitUsage {
			t.Errorf("--sha256 %q: %d", sha, code)
		}
	}
}

// A baseline approved under another root can't be trusted, so diff refuses to
// compare against it.
func TestDiffRefusesABaselineFromAnotherRoot(t *testing.T) {
	f := newFlowSetup(t)
	f.draft(t, "/srv/inbox")
	_, v1 := f.o.Call(t, http.MethodGet, "/api/v1/flows/"+f.flowID+"/versions/1", nil)
	payload, err := base64.StdEncoding.DecodeString(v1["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	other := servertest.NewApprover(t)
	e, err := statement.Sign(statement.TypeFlowVersion, payload, other.Admin)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := json.Marshal(e)
	ed, ml := other.Root.Public().Bytes()
	bundle := trust.Approval{Statement: signed, AdministratorCertificates: []json.RawMessage{other.Certificate}, RootEd25519: ed, RootMLDSA65: ml}
	// The orchestrator pins no root, so it stores this approval.
	if code, out := f.o.Call(t, http.MethodPut, "/api/v1/flows/"+f.flowID+"/versions/1/approval", bundle); code != http.StatusNoContent {
		t.Fatalf("store approval: %d %v", code, out)
	}
	f.draft(t, "/srv/inbox-2")
	code, _, errOut := f.flow(t, "diff", "--version", "2")
	if code != exitRefused || !strings.Contains(errOut, "pinned root") {
		t.Errorf("diff: %d %s", code, errOut)
	}
}

func TestRetire(t *testing.T) {
	f := newFlowSetup(t)
	f.draft(t, "/srv/inbox")
	if code, _, errOut := f.flow(t, "retire", "--workspace", "other"); code != exitRefused {
		t.Errorf("wrong workspace: %d %s", code, errOut)
	}
	code, out, errOut := f.flow(t, "retire", "--workspace", "lab")
	if code != exitOK || out["status"] != "retired" {
		t.Fatalf("retire: %d %v %s", code, out, errOut)
	}
	if code, _, _ := f.flow(t, "retire", "--workspace", "lab"); code != exitExists {
		t.Errorf("retire again: %d", code)
	}
	if code, _ := f.o.Call(t, http.MethodPost, "/api/v1/flows/"+f.flowID+"/versions", map[string]any{"schema_version": 1, "cards": []any{}}); code != http.StatusConflict {
		t.Errorf("draft after retirement: %d", code)
	}
	sha, _ := f.diff(t, 1)
	if code, _, errOut := f.flow(t, "approve", "--version", "1", "--sha256", sha); code == exitOK {
		t.Errorf("approved a retired flow: %s", errOut)
	}
}
