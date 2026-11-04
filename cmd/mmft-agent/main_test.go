package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"mmft.dev/mmft/internal/agent"
	"mmft.dev/mmft/internal/server/servertest"
)

const rootPin = "1111111111111111111111111111111111111111111111111111111111111111"

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut, time.Now)
	return code, out.String(), errOut.String()
}

func tokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func installArgs(o servertest.Orchestrator, dir, name, tokenPath string) []string {
	return []string{"install", "--dir", dir, "--orchestrator", o.GRPC, "--name", name, "--token-file", tokenPath,
		"--ca-fingerprint", o.CA.Fingerprint(), "--root-fingerprint", rootPin}
}

func parseJSON(t *testing.T, s string) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("output is not JSON: %q", s)
	}
	return m
}

func TestInstallAndFingerprint(t *testing.T) {
	o := servertest.Start(t)
	dir := filepath.Join(t.TempDir(), "agent")
	token := tokenFile(t, o.Token(t, "lab", "agent-a"))

	code, out, errOut := cli(t, installArgs(o, dir, "agent-a", token)...)
	if code != exitOK {
		t.Fatalf("install: %d %s", code, errOut)
	}
	installed := parseJSON(t, out)
	if installed["agent_id"] == "" || len(installed["fingerprint"]) != 64 || installed["agent_name"] != "agent-a" {
		t.Fatalf("install output = %v", installed)
	}

	code, out, errOut = cli(t, "fingerprint", "--dir", dir, "--json")
	if code != exitOK {
		t.Fatalf("fingerprint --json: %d %s", code, errOut)
	}
	if got := parseJSON(t, out); got["fingerprint"] != installed["fingerprint"] || got["agent_id"] != installed["agent_id"] {
		t.Fatalf("fingerprint = %v, install = %v", got, installed)
	}
	code, out, _ = cli(t, "fingerprint", "--dir", dir)
	if code != exitOK || !strings.Contains(out, installed["fingerprint"]) || !strings.Contains(out, "agent-a") {
		t.Fatalf("fingerprint text: %d %q", code, out)
	}

	// A repeat run is safe, says so with its own exit code, and still reports the agent.
	code, out, _ = cli(t, installArgs(o, dir, "agent-a", token)...)
	if code != exitExists || parseJSON(t, out)["agent_id"] != installed["agent_id"] {
		t.Fatalf("repeat install: %d %q", code, out)
	}

	// A deployment tool may delete the one-use token file after the first run.
	if err := os.Remove(token); err != nil {
		t.Fatal(err)
	}
	code, out, _ = cli(t, installArgs(o, dir, "agent-a", token)...)
	if code != exitExists || parseJSON(t, out)["agent_id"] != installed["agent_id"] {
		t.Fatalf("repeat install without the token file: %d %q", code, out)
	}
	token = tokenFile(t, o.Token(t, "lab", "agent-x"))
	if code, _, _ := cli(t, installArgs(o, filepath.Join(t.TempDir(), "agent"), "agent-x", token)...); code != exitOK {
		t.Fatalf("install agent-x: %d", code)
	}

	// Another host with the used token is refused with its own exit code.
	code, _, errOut = cli(t, installArgs(o, filepath.Join(t.TempDir(), "agent"), "agent-x", token)...)
	if code != exitRefused {
		t.Fatalf("used token: %d %s", code, errOut)
	}
}

// A save that fails after the orchestrator enrolled the agent must never look
// like a safe repeat run, and a later run must finish the enrollment.
func TestFailedSaveIsNotReportedAsEnrolled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no key storage on Windows yet")
	}
	o := servertest.Start(t)
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A dangling link reads as missing state, but blocks the create-only write.
	state := filepath.Join(dir, agent.StateFile)
	if err := os.Symlink(filepath.Join(dir, "nowhere"), state); err != nil {
		t.Fatal(err)
	}
	token := tokenFile(t, o.Token(t, "lab", "agent-a"))
	code, out, errOut := cli(t, installArgs(o, dir, "agent-a", token)...)
	if code != exitFailure || strings.Contains(errOut, "already enrolled") {
		t.Fatalf("failed save: exit %d, stdout %q, stderr %s", code, out, errOut)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := cli(t, installArgs(o, dir, "agent-a", token)...); code != exitOK {
		t.Fatalf("retry: %d %s", code, errOut)
	}
}

func TestUsageAndFailures(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if code, _, _ := cli(t); code != exitUsage {
		t.Errorf("no command: %d", code)
	}
	if code, _, _ := cli(t, "install", "--dir", dir); code != exitUsage {
		t.Errorf("missing flags: %d", code)
	}
	if code, _, _ := cli(t, "fingerprint", "extra"); code != exitUsage {
		t.Errorf("stray argument: %d", code)
	}
	if code, _, errOut := cli(t, "fingerprint", "--dir", dir, "--json"); code != exitFailure || !strings.Contains(errOut, "not enrolled") {
		t.Errorf("not enrolled: %d %s", code, errOut)
	}
	empty := tokenFile(t, "")
	args := []string{"install", "--dir", dir, "--orchestrator", "localhost:1", "--name", "agent-a", "--token-file", empty,
		"--ca-fingerprint", rootPin, "--root-fingerprint", rootPin}
	if code, _, errOut := cli(t, args...); code != exitFailure || !strings.Contains(errOut, "token") {
		t.Errorf("empty token file: %d %s", code, errOut)
	}
	if code, out, _ := cli(t, "version"); code != exitOK || !strings.HasPrefix(out, "mmft-agent") {
		t.Errorf("version: %d %q", code, out)
	}
}

func TestIdentityWaitsForApproval(t *testing.T) {
	o := servertest.Start(t)
	ap := servertest.NewApprover(t)
	dir := filepath.Join(t.TempDir(), "agent")
	args := installArgs(o, dir, "agent-a", tokenFile(t, o.Token(t, "lab", "agent-a")))
	args[len(args)-1] = ap.RootFingerprint()
	code, out, errOut := cli(t, args...)
	if code != exitOK {
		t.Fatalf("install: %d %s", code, errOut)
	}
	installed := parseJSON(t, out)

	code, _, errOut = cli(t, "identity", "--dir", dir)
	if code != exitPending || !strings.Contains(errOut, "not approved") {
		t.Fatalf("before approval: %d %s", code, errOut)
	}
	s, err := agent.ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if code := o.PutIdentity(t, s.AgentID, ap.Sign(t, s.AgentID, "lab", "agent-a", s.Keys())); code != 204 {
		t.Fatalf("put identity: %d", code)
	}
	code, out, errOut = cli(t, "identity", "--dir", dir)
	if code != exitOK {
		t.Fatalf("identity: %d %s", code, errOut)
	}
	got := parseJSON(t, out)
	if got["agent_id"] != installed["agent_id"] || got["fingerprint"] != installed["fingerprint"] || got["workspace"] != "lab" || got["not_after"] == "" {
		t.Fatalf("identity = %v", got)
	}
}
