package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func (a approveSetup) send(t *testing.T, extra ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	args := append([]string{
		"delivery", "send", "--api", a.o.API, "--ca-fingerprint", a.o.CA.Fingerprint(), "--token-file", a.tokenFile,
		"--workspace", "lab",
	}, extra...)
	code := run(args, &out, &errOut, time.Now)
	return code, out.String(), errOut.String()
}

func TestDeliverySendChecksItsInputs(t *testing.T) {
	a := newApproveSetup(t)
	for name, args := range map[string][]string{
		"no file":       {"--from", "agent-a", "--to", "agent-b"},
		"a path":        {"--from", "agent-a", "--to", "agent-b", "--file", "../x"},
		"bad agent":     {"--from", "agent a", "--to", "agent-b", "--file", "x"},
		"bad timeout":   {"--from", "agent-a", "--to", "agent-b", "--file", "x", "--timeout", "-1s"},
		"stray operand": {"--from", "agent-a", "--to", "agent-b", "--file", "x", "extra"},
	} {
		if code, _, _ := a.send(t, args...); code != exitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, exitUsage)
		}
	}
}

func TestDeliverySendNeedsApprovedAgents(t *testing.T) {
	a := newApproveSetup(t)
	a.install(t, "agent-a")
	code, _, errOut := a.send(t, "--from", "agent-a", "--to", "agent-b", "--file", "x")
	if code != exitFailure || !strings.Contains(errOut, "not approved") {
		t.Fatalf("pending agent: exit %d %s", code, errOut)
	}
	code, _, errOut = a.send(t, "--from", "agent-z", "--to", "agent-b", "--file", "x")
	if code != exitFailure || !strings.Contains(errOut, "no agent named agent-z") {
		t.Fatalf("unknown agent: exit %d %s", code, errOut)
	}
}

func TestDeliverySendReportsTheOrchestratorsRefusal(t *testing.T) {
	a := newApproveSetup(t)
	sa, _ := a.install(t, "agent-a")
	sb, _ := a.install(t, "agent-b")
	if code, _, errOut := a.approve(t, collected(sa)+collected(sb)); code != exitOK {
		t.Fatalf("approve: %d %s", code, errOut)
	}
	// The test orchestrator has no relay and the agents aren't running.
	code, _, errOut := a.send(t, "--from", "agent-a", "--to", "agent-b", "--file", "x")
	if code != exitFailure || !strings.Contains(errOut, "409") {
		t.Fatalf("exit %d %s", code, errOut)
	}
}
