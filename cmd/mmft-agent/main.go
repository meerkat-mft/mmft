// Command mmft-agent is the Meerkat MFT agent. Every command runs without prompts
// and has stable exit codes, so deployment tools can run it. Output is JSON,
// except version and the default fingerprint output, which are plain text for a
// person comparing fingerprints on the host, and usage errors. Exit codes are
// listed in docs/naming.md. `run` keeps the agent connected until it is
// stopped, and prints one JSON line per connection event.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"mmft.dev/mmft/internal/agent"
	"mmft.dev/mmft/internal/version"
)

// Exit codes. Scripts can treat exitExists as a safe repeat run.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitExists  = 3
	// exitRefused means the orchestrator refused the enrollment token.
	exitRefused = 4
	// exitPending means no administrator has approved the agent yet.
	exitPending = 5
)

const (
	defaultDir    = "/var/lib/mmft/agent"
	enrollTimeout = 30 * time.Second
	maxTokenBytes = 256
)

const usage = `usage:
  mmft-agent version
  mmft-agent install --orchestrator HOST:PORT --workspace NAME --name NAME --token-file FILE
                     --ca-fingerprint HEX --root-fingerprint HEX [--dir DIR]
  mmft-agent fingerprint [--dir DIR] [--json]
  mmft-agent identity [--dir DIR]
  mmft-agent run [--dir DIR]

exit codes: 0 done, 1 failed, 2 usage, 3 safe repeat, 4 refused, 5 waiting for approval
`

var errUsage = errors.New("incorrect usage")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

func run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	err := dispatch(args, stdout, stderr, now)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errUsage):
		_, _ = io.WriteString(stderr, usage)
		return exitUsage
	case errors.Is(err, agent.ErrAlreadyEnrolled):
		_ = output(stderr, map[string]string{"error": "already enrolled"})
		return exitExists
	case errors.Is(err, agent.ErrNotApproved):
		_ = output(stderr, map[string]string{"error": "the agent is not approved yet"})
		return exitPending
	case status.Code(err) == codes.PermissionDenied:
		_ = output(stderr, map[string]string{"error": "the orchestrator refused the enrollment token"})
		return exitRefused
	default:
		_ = output(stderr, map[string]string{"error": err.Error()})
		return exitFailure
	}
}

func dispatch(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return errUsage
	}
	rest := args[1:]
	switch args[0] {
	case "version":
		if len(rest) != 0 {
			return errUsage
		}
		_, err := fmt.Fprintln(stdout, version.String("mmft-agent"))
		return err
	case "install":
		return install(rest, stdout, stderr, now)
	case "fingerprint":
		return fingerprint(rest, stdout, stderr)
	case "identity":
		return identity(rest, stdout, stderr, now)
	case "run":
		return runAgent(rest, stdout, stderr, now)
	default:
		return errUsage
	}
}

// parse reads flags and rejects missing required ones and stray arguments.
func parse(fs *flag.FlagSet, args []string, stderr io.Writer, required ...string) error {
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	for _, name := range required {
		if fs.Lookup(name).Value.String() == "" {
			return errUsage
		}
	}
	return nil
}

func output(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// readToken reads the token from a file, so it never appears in a process list.
func readToken(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" || len(data) > maxTokenBytes {
		return "", errors.New("the token file must hold one token")
	}
	return token, nil
}

func stateJSON(s agent.State) map[string]string {
	return map[string]string{
		"agent_id":    s.AgentID,
		"workspace":   s.Workspace,
		"agent_name":  s.AgentName,
		"fingerprint": s.Fingerprint(),
	}
}

func install(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "directory for the agent's keys and state")
	orchestrator := fs.String("orchestrator", "", "host and port of the orchestrator's agent service")
	workspace := fs.String("workspace", "", "workspace the token was created for")
	name := fs.String("name", "", "agent name the token was created for")
	tokenFile := fs.String("token-file", "", "file holding the enrollment token")
	caPin := fs.String("ca-fingerprint", "", "connection CA fingerprint from the install command")
	rootPin := fs.String("root-fingerprint", "", "trust root fingerprint from the install command")
	if err := parse(fs, args, stderr, "orchestrator", "workspace", "name", "token-file", "ca-fingerprint", "root-fingerprint"); err != nil {
		return err
	}
	in := agent.Install{
		Orchestrator:    *orchestrator,
		Workspace:       *workspace,
		AgentName:       *name,
		CAFingerprint:   *caPin,
		RootFingerprint: *rootPin,
	}
	// A safe repeat is reported before the token is read, because a deployment
	// tool may have removed it after the first run. Exit 3 means the settings
	// match and the keys and a current certificate are in place.
	switch s, err := agent.CheckInstalled(*dir, in, now()); {
	case err == nil:
		_ = output(stdout, stateJSON(s))
		return agent.ErrAlreadyEnrolled
	case errors.Is(err, agent.ErrCertificateExpired), errors.Is(err, agent.ErrMissingCA), errors.Is(err, agent.ErrNotEnrolled):
		// Enroll, or re-enroll with the same keys, using the token.
	default:
		return err
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	in.Token = token
	ctx, cancel := context.WithTimeout(context.Background(), enrollTimeout)
	defer cancel()
	s, err := agent.Enroll(ctx, *dir, in, now)
	if errors.Is(err, agent.ErrAlreadyEnrolled) {
		// Print the existing agent too, so a repeat run still reports it.
		_ = output(stdout, stateJSON(s))
		return err
	}
	if err != nil {
		return err
	}
	return output(stdout, stateJSON(s))
}

func fingerprint(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "directory for the agent's keys and state")
	asJSON := fs.Bool("json", false, "print JSON for a deployment tool")
	if err := parse(fs, args, stderr); err != nil {
		return err
	}
	s, err := agent.ReadState(*dir)
	if err != nil {
		return err
	}
	if *asJSON {
		return output(stdout, stateJSON(s))
	}
	_, err = fmt.Fprintf(stdout, "agent_id     %s\nworkspace    %s\nagent_name   %s\nfingerprint  %s\n", s.AgentID, s.Workspace, s.AgentName, s.Fingerprint())
	return err
}

// identity fetches the agent's signed identity and verifies it back to the
// pinned trust root, which ADR 0011 requires before the agent accepts work.
func identity(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "directory for the agent's keys and state")
	if err := parse(fs, args, stderr); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), enrollTimeout)
	defer cancel()
	claim, err := agent.FetchIdentity(ctx, *dir, now)
	if err != nil {
		return err
	}
	return output(stdout, map[string]string{
		"agent_id":    claim.AgentID,
		"agent_name":  claim.AgentName,
		"workspace":   claim.Workspace,
		"fingerprint": claim.Keys().Fingerprint(),
		"not_after":   claim.NotAfter.Format(time.RFC3339),
	})
}

// runAgent keeps the agent connected until SIGINT or SIGTERM, which end it
// with exit 0. An expired connection certificate ends it with exit 1 and says
// how to fix it.
func runAgent(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "directory for the agent's keys and state")
	if err := parse(fs, args, stderr); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx, *dir, agent.RunConfig{Log: stdout, Now: now})
}
