//go:build !windows

// These tests store private keys, which Windows refuses until its access
// control lists are checked. See perm_windows.go.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mmft.dev/mmft/internal/agent"
	"mmft.dev/mmft/internal/server/servertest"
)

type approveSetup struct {
	setup
	o         servertest.Orchestrator
	tokenFile string
}

func newApproveSetup(t *testing.T) approveSetup {
	t.Helper()
	s := newSetup(t)
	s.now = time.Now()
	if code, errOut := s.certify(t, s.rootFP, s.adminFP); code != exitOK {
		t.Fatalf("certify-admin: %d %s", code, errOut)
	}
	a := approveSetup{setup: s, o: servertest.Start(t), tokenFile: filepath.Join(t.TempDir(), "api-token")}
	if err := os.WriteFile(a.tokenFile, []byte(servertest.AdminToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return a
}

// install enrolls an agent as `mmft-agent install` does, pinning the root.
func (a approveSetup) install(t *testing.T, name string) (agent.State, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := agent.Enroll(ctx, dir, agent.Install{
		Orchestrator: a.o.GRPC, Token: a.o.Token(t, "lab", name), AgentName: name,
		CAFingerprint: a.o.CA.Fingerprint(), RootFingerprint: a.rootFP,
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func (a approveSetup) approve(t *testing.T, fingerprints string) (int, approvalReport, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fingerprints.json")
	if err := os.WriteFile(path, []byte(fingerprints), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{
		"agent", "approve", "--api", a.o.API, "--ca-fingerprint", a.o.CA.Fingerprint(), "--token-file", a.tokenFile,
		"--admin-dir", a.adminDir, "--passphrase-file", a.passFile, "--certificate", a.cert,
		"--root-public", filepath.Join(a.rootDir, "root.pub.json"), "--root-fingerprint", a.rootFP,
		"--fingerprints", path, "--days", "30",
	}, &out, &errOut, time.Now)
	var report approvalReport
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatalf("output is not JSON: %q", out.String())
		}
	}
	return code, report, errOut.String()
}

// collected is what `mmft-agent fingerprint --json` prints on the host.
func collected(s agent.State) string {
	b, _ := json.Marshal(map[string]string{"agent_id": s.AgentID, "agent_name": s.AgentName, "fingerprint": s.Fingerprint()})
	return string(b) + "\n"
}

func fetchIdentity(t *testing.T, dir string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := agent.FetchIdentity(ctx, dir, time.Now)
	return err
}

func TestUnattendedApproval(t *testing.T) {
	a := newApproveSetup(t)
	agentA, dirA := a.install(t, "agent-a")
	agentB, dirB := a.install(t, "agent-b")

	// Output from two hosts, concatenated by the deployment tool.
	code, report, errOut := a.approve(t, collected(agentA)+collected(agentB))
	if code != exitOK || len(report.Approved) != 2 || len(report.Refused) != 0 {
		t.Fatalf("approve: %d %+v %s", code, report, errOut)
	}
	for _, dir := range []string{dirA, dirB} {
		if err := fetchIdentity(t, dir); err != nil {
			t.Fatalf("agent in %s: %v", dir, err)
		}
	}

	// A repeat run changes nothing.
	code, report, errOut = a.approve(t, "["+strings.TrimSpace(collected(agentA))+","+strings.TrimSpace(collected(agentB))+"]")
	if code != exitOK || len(report.Skipped) != 2 || len(report.Approved) != 0 {
		t.Fatalf("repeat: %d %+v %s", code, report, errOut)
	}
}

func TestChangedFingerprintIsRefused(t *testing.T) {
	a := newApproveSetup(t)
	agentA, dirA := a.install(t, "agent-a")
	agentB, dirB := a.install(t, "agent-b")

	// The keys the orchestrator reports for agent-b don't match the fingerprint
	// collected from its host, as happens when an orchestrator swaps them.
	other, _ := a.install(t, "agent-x")
	swapped := agentB
	swapped.Ed25519, swapped.MLDSA65, swapped.Recipient = other.Ed25519, other.MLDSA65, other.Recipient
	code, report, errOut := a.approve(t, collected(agentA)+collected(swapped))
	if code != exitRefused || !strings.Contains(errOut, "refused") {
		t.Fatalf("approve: %d %s", code, errOut)
	}
	if len(report.Approved) != 1 || report.Approved[0].AgentID != agentA.AgentID ||
		len(report.Refused) != 1 || report.Refused[0].AgentID != agentB.AgentID {
		t.Fatalf("report = %+v", report)
	}
	if err := fetchIdentity(t, dirA); err != nil {
		t.Fatalf("agent-a: %v", err)
	}
	if err := fetchIdentity(t, dirB); !errors.Is(err, agent.ErrNotApproved) {
		t.Fatalf("agent-b: %v", err)
	}

	// An ID or name that differs from the host is refused too.
	renamed := agentB
	renamed.AgentName = "agent-y"
	if code, report, _ := a.approve(t, collected(renamed)); code != exitRefused || len(report.Refused) != 1 {
		t.Fatalf("renamed: %d %+v", code, report)
	}
	unknown := agentB
	unknown.AgentID = "019a3f2e-7c11-7d3e-9f7b-000000000000"
	if code, report, _ := a.approve(t, collected(unknown)); code != exitRefused || len(report.Refused) != 1 {
		t.Fatalf("unknown: %d %+v", code, report)
	}
}

func TestApproveChecksItsInputsFirst(t *testing.T) {
	a := newApproveSetup(t)
	agentA, _ := a.install(t, "agent-a")
	for name, input := range map[string]string{
		"empty":            "",
		"not JSON":         "agent-a 1234",
		"missing field":    `{"agent_id":"` + agentA.AgentID + `","agent_name":"agent-a"}`,
		"conflicting rows": collected(agentA) + strings.Replace(collected(agentA), agentA.Fingerprint(), strings.Repeat("0", 64), 1),
	} {
		if code, _, _ := a.approve(t, input); code != exitFailure {
			t.Errorf("%s: code = %d", name, code)
		}
	}
	if err := os.Chmod(a.tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := a.approve(t, collected(agentA)); code != exitFailure || !strings.Contains(errOut, "not private") {
		t.Errorf("shared token file: %d %s", code, errOut)
	}
}
