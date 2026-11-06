package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"mmft.dev/mmft/internal/seal"
	"mmft.dev/mmft/internal/trust"
)

const (
	defaultWait  = 5 * time.Minute
	pollInterval = 500 * time.Millisecond
)

// errDeliveryFailed means the run ended without the file in place. The printed
// run says why.
var errDeliveryFailed = errors.New("the delivery failed, so see its error_code")

// runResult is a run as the orchestrator reports it. File names in it are
// untrusted and only printed.
type runResult struct {
	ID         string           `json:"id"`
	Status     string           `json:"status"`
	Deliveries []map[string]any `json:"deliveries"`
}

func (r runResult) ended() bool { return r.Status == "succeeded" || r.Status == "failed" }

// deliverySend starts a manual run that moves one file from the source agent's
// outbox to the destination agent's inbox, as ADR 0021 defines, and with
// --wait waits for it to end. It prints the run as JSON.
func deliverySend(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("delivery send", flag.ContinueOnError)
	api := fs.String("api", "", "host and port of the orchestrator's REST API")
	caPin := fs.String("ca-fingerprint", "", "connection CA fingerprint")
	tokenFile := fs.String("token-file", "", "file holding the API token")
	workspace := fs.String("workspace", "", "workspace of both agents")
	from := fs.String("from", "", "name of the source agent")
	to := fs.String("to", "", "name of the destination agent")
	file := fs.String("file", "", "file name in the source's outbox, also used in the destination's inbox")
	wait := fs.Bool("wait", false, "wait for the delivery to end, and exit 1 if it failed")
	timeout := fs.Duration("timeout", defaultWait, "how long --wait waits")
	if err := parse(fs, args, stderr, "api", "ca-fingerprint", "token-file", "workspace", "from", "to", "file"); err != nil {
		return err
	}
	if !trust.ValidName(*workspace) || !trust.ValidName(*from) || !trust.ValidName(*to) || !seal.ValidFileName(*file) ||
		!validFingerprint(*caPin) || *timeout <= 0 {
		return errUsage
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	client, err := newAPIClient(*api, *caPin, token, now)
	if err != nil {
		return err
	}
	agents, err := client.agents()
	if err != nil {
		return err
	}
	source, err := agentNamed(agents, *workspace, *from)
	if err != nil {
		return err
	}
	destination, err := agentNamed(agents, *workspace, *to)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"source_agent_id": source, "destination_agent_id": destination, "file_name": *file})
	if err != nil {
		return err
	}
	var run runResult
	if err := client.do(http.MethodPost, "/runs", body, http.StatusAccepted, &run); err != nil {
		return err
	}
	if !trust.ValidAgentID(run.ID) {
		return errors.New("the orchestrator returned an invalid run ID")
	}
	if *wait {
		deadline := time.Now().Add(*timeout)
		for !run.ended() {
			if time.Now().After(deadline) {
				_ = output(stdout, run)
				return fmt.Errorf("the delivery did not end within %v", *timeout)
			}
			time.Sleep(pollInterval)
			if err := client.do(http.MethodGet, "/runs/"+run.ID, nil, http.StatusOK, &run); err != nil {
				return err
			}
		}
	}
	if err := output(stdout, run); err != nil {
		return err
	}
	if run.Status == "failed" {
		return errDeliveryFailed
	}
	return nil
}

// agentNamed finds the approved agent with this name in the workspace.
func agentNamed(agents map[string]listedAgent, workspace, name string) (string, error) {
	for _, a := range agents {
		if a.Workspace == workspace && a.Name == name {
			if a.Status != "approved" {
				return "", fmt.Errorf("the agent %s is %s, not approved", name, a.Status)
			}
			return a.ID, nil
		}
	}
	return "", fmt.Errorf("no agent named %s in workspace %s", name, workspace)
}
