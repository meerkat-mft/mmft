package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

const (
	apiTimeout       = 30 * time.Second
	maxTokenBytes    = 4096
	maxResponseBytes = 8 << 20
	pageSize         = 200
)

// errRefused means at least one agent did not match what was collected from
// its host, so its identity was not signed.
var errRefused = errors.New("some agents were refused")

// hostAgent is what `mmft-agent fingerprint --json` prints on a host.
type hostAgent struct {
	AgentID     string `json:"agent_id"`
	AgentName   string `json:"agent_name"`
	Fingerprint string `json:"fingerprint"`
}

// readFingerprints reads the values collected from hosts: a sequence of JSON
// objects, or arrays of them, so that the output of several hosts can simply
// be concatenated.
func readFingerprints(path string) ([]hostAgent, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var all []hostAgent
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("the fingerprints file is not JSON: %w", err)
		}
		var batch []hostAgent
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
			if err := json.Unmarshal(raw, &batch); err != nil {
				return nil, fmt.Errorf("the fingerprints file is not valid: %w", err)
			}
		} else {
			var one hostAgent
			if err := json.Unmarshal(raw, &one); err != nil {
				return nil, fmt.Errorf("the fingerprints file is not valid: %w", err)
			}
			batch = []hostAgent{one}
		}
		all = append(all, batch...)
	}
	seen := map[string]hostAgent{}
	var unique []hostAgent
	for _, a := range all {
		if !trust.ValidAgentID(a.AgentID) || !trust.ValidName(a.AgentName) || len(a.Fingerprint) != 64 {
			return nil, errors.New("each entry in the fingerprints file needs agent_id, agent_name, and fingerprint")
		}
		if prev, ok := seen[a.AgentID]; ok {
			if prev != a {
				return nil, fmt.Errorf("the fingerprints file lists agent %s twice with different values", a.AgentID)
			}
			continue
		}
		seen[a.AgentID] = a
		unique = append(unique, a)
	}
	if len(unique) == 0 {
		return nil, errors.New("the fingerprints file lists no agents")
	}
	return unique, nil
}

// readToken reads the API token from a file private to this user, so it never
// appears in a process list. Errors never repeat the path.
func readToken(path string) (string, error) {
	data, err := trust.ReadPrivate(path)
	if errors.Is(err, trust.ErrNotPrivate) {
		return "", err
	}
	if err != nil {
		return "", errors.New("cannot read the token file")
	}
	token := strings.TrimSpace(string(data))
	if token == "" || len(data) > maxTokenBytes || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("the token file must hold one token")
	}
	return token, nil
}

// apiClient calls the orchestrator's REST API, trusting it only through the
// pinned connection CA.
type apiClient struct {
	base  string
	token string
	http  *http.Client
}

func newAPIClient(address, caPin, token string, now func() time.Time) (*apiClient, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errUsage
	}
	return &apiClient{
		base:  "https://" + address + "/api/v1",
		token: token,
		http: &http.Client{
			Timeout:   apiTimeout,
			Transport: &http.Transport{TLSClientConfig: connca.PinnedClient(caPin, host, now)},
		},
	}, nil
}

func (c *apiClient) do(method, path string, body []byte, want int, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		var p struct {
			Title string `json:"title"`
		}
		_ = json.Unmarshal(data, &p)
		return fmt.Errorf("the orchestrator answered %d: %s", resp.StatusCode, p.Title)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// listedAgent is an agent as the orchestrator reports it. Nothing in it is
// trusted: approval compares it with what was collected from the host.
type listedAgent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Workspace  string `json:"workspace"`
	Status     string `json:"status"`
	PublicKeys *struct {
		Ed25519   []byte `json:"ed25519"`
		MLDSA65   []byte `json:"mldsa65"`
		Recipient string `json:"encryption_recipient"`
	} `json:"public_keys"`
}

func (c *apiClient) agents() (map[string]listedAgent, error) {
	all := map[string]listedAgent{}
	cursor := ""
	for {
		q := url.Values{"limit": {fmt.Sprint(pageSize)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page struct {
			Items      []listedAgent `json:"items"`
			NextCursor string        `json:"next_cursor"`
		}
		if err := c.do(http.MethodGet, "/agents?"+q.Encode(), nil, http.StatusOK, &page); err != nil {
			return nil, err
		}
		for _, a := range page.Items {
			all[a.ID] = a
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

type approvalResult struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Reason    string `json:"reason,omitempty"`
}

type approvalReport struct {
	Approved []approvalResult `json:"approved"`
	Skipped  []approvalResult `json:"skipped"`
	Refused  []approvalResult `json:"refused"`
}

// agentApprove signs the identity of each pending agent in the fingerprints
// file, only if its keys, ID, and name match what was collected from its host,
// as ADR 0011 and ADR 0018 require. Agents already approved are skipped, so a
// repeat run changes nothing. It never prompts.
func agentApprove(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("agent approve", flag.ContinueOnError)
	api := fs.String("api", "", "host and port of the orchestrator's REST API")
	caPin := fs.String("ca-fingerprint", "", "connection CA fingerprint")
	tokenFile := fs.String("token-file", "", "file holding the API token")
	adminDir := fs.String("admin-dir", "", "directory holding the administrator key")
	passFile := fs.String("passphrase-file", "", "file holding the administrator key passphrase")
	certificate := fs.String("certificate", "", "administrator's certificate")
	rootPublic := fs.String("root-public", "", "trust root's public key file")
	rootPin := fs.String("root-fingerprint", "", "pinned trust root fingerprint")
	fingerprints := fs.String("fingerprints", "", "file of fingerprints collected from the hosts")
	days := fs.Int("days", 365, "identity lifetime in days, up to 365")
	if err := parse(fs, args, stderr, "api", "ca-fingerprint", "token-file", "admin-dir", "passphrase-file",
		"certificate", "root-public", "root-fingerprint", "fingerprints"); err != nil {
		return err
	}
	if *days < 1 || *days > 365 {
		return errUsage
	}

	// Everything local is checked before the orchestrator is contacted.
	expected, err := readFingerprints(*fingerprints)
	if err != nil {
		return err
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	passphrase, err := trust.ReadPassphrase(*passFile)
	if err != nil {
		return err
	}
	admin, _, err := trust.LoadKey(filepath.Join(*adminDir, trust.AdminKeyFile), passphrase, statement.RoleAdministrator)
	if err != nil {
		return err
	}
	cert, err := os.ReadFile(filepath.Clean(*certificate))
	if err != nil {
		return err
	}
	record, err := trust.ReadPublic(*rootPublic)
	if err != nil {
		return err
	}
	root, err := record.Key()
	if err != nil {
		return err
	}
	if _, _, err := trust.VerifyAdministrator(cert, root, *rootPin, now()); err != nil {
		return err
	}
	client, err := newAPIClient(*api, *caPin, token, now)
	if err != nil {
		return err
	}

	listed, err := client.agents()
	if err != nil {
		return err
	}
	report := approvalReport{Approved: []approvalResult{}, Skipped: []approvalResult{}, Refused: []approvalResult{}}
	for _, want := range expected {
		result := approvalResult{AgentID: want.AgentID, AgentName: want.AgentName}
		got, ok := listed[want.AgentID]
		switch {
		case !ok:
			result.Reason = "the orchestrator has no such agent"
			report.Refused = append(report.Refused, result)
			continue
		case got.Status == "approved":
			report.Skipped = append(report.Skipped, result)
			continue
		case got.Status != "pending_approval" || got.PublicKeys == nil:
			result.Reason = "the agent is " + got.Status
			report.Refused = append(report.Refused, result)
			continue
		}
		e, err := trust.CertifyAgent(admin, cert, root, *rootPin, trust.AgentRequest{
			AgentID:   got.ID,
			Workspace: got.Workspace,
			AgentName: got.Name,
			Keys: trust.AgentKeys{
				Ed25519: got.PublicKeys.Ed25519, MLDSA65: got.PublicKeys.MLDSA65, Recipient: got.PublicKeys.Recipient,
			},
			ExpectedFingerprint: want.Fingerprint,
			ExpectedID:          want.AgentID,
			ExpectedName:        want.AgentName,
		}, now(), time.Duration(*days)*24*time.Hour)
		if errors.Is(err, trust.ErrWrongAgent) || errors.Is(err, trust.ErrAgentSharesKey) || errors.Is(err, trust.ErrInvalidIdentity) {
			result.Reason = "the agent does not match the fingerprint, ID, or name from its host"
			report.Refused = append(report.Refused, result)
			continue
		}
		if err != nil {
			return err
		}
		identity, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := client.do(http.MethodPut, "/agents/"+got.ID+"/identity", identity, http.StatusNoContent, nil); err != nil {
			return fmt.Errorf("agent %s: %w", got.ID, err)
		}
		report.Approved = append(report.Approved, result)
	}
	if err := output(stdout, report); err != nil {
		return err
	}
	if len(report.Refused) > 0 {
		return errRefused
	}
	return nil
}
