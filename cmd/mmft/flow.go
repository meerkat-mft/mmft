package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"mmft.dev/mmft/internal/flow"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// refusal is a failed trust check, which exits with exitRefused.
type refusal struct{ msg string }

func (r refusal) Error() string { return r.msg }
func (r refusal) Unwrap() error { return errRefused }

func refused(format string, a ...any) error { return refusal{fmt.Sprintf(format, a...)} }

// flowRecord is a flow as the orchestrator lists it.
type flowRecord struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Workspace       string `json:"workspace"`
	ApprovedVersion *int   `json:"approved_version"`
	Retired         bool   `json:"retired"`
}

// versionRecord is a flow version as the orchestrator returns it. Only the
// payload and the approval are trusted, and only once checked here.
type versionRecord struct {
	Status   string          `json:"status"`
	Payload  []byte          `json:"payload"`
	Approval json.RawMessage `json:"approval"`
}

// flowFlags are the flags every flow command takes.
type flowFlags struct {
	api, caPin, tokenFile, rootPublic, rootPin, flowID *string
}

func newFlowFlags(fs *flag.FlagSet) flowFlags {
	return flowFlags{
		api:        fs.String("api", "", "host and port of the orchestrator's REST API"),
		caPin:      fs.String("ca-fingerprint", "", "connection CA fingerprint"),
		tokenFile:  fs.String("token-file", "", "file holding the API token"),
		rootPublic: fs.String("root-public", "", "trust root's public key file"),
		rootPin:    fs.String("root-fingerprint", "", "pinned trust root fingerprint"),
		flowID:     fs.String("flow", "", "ID of the flow"),
	}
}

var flowRequired = []string{"api", "ca-fingerprint", "token-file", "root-public", "root-fingerprint", "flow"}

// connect checks the local inputs and returns the pinned root and an API client.
func (f flowFlags) connect(now func() time.Time) (statement.PublicKey, *apiClient, error) {
	if !trust.ValidAgentID(*f.flowID) {
		return statement.PublicKey{}, nil, errUsage
	}
	root, err := pinnedRoot(*f.rootPublic, *f.rootPin)
	if err != nil {
		return statement.PublicKey{}, nil, err
	}
	token, err := readToken(*f.tokenFile)
	if err != nil {
		return statement.PublicKey{}, nil, err
	}
	client, err := newAPIClient(*f.api, *f.caPin, token, now)
	return root, client, err
}

// pinnedRoot reads the root's public key and requires it to match the pin.
func pinnedRoot(path, pin string) (statement.PublicKey, error) {
	record, err := trust.ReadPublic(path)
	if err != nil {
		return statement.PublicKey{}, err
	}
	root, err := record.Key()
	if err != nil {
		return statement.PublicKey{}, err
	}
	if root.Fingerprint() != pin {
		return statement.PublicKey{}, trust.ErrWrongRoot
	}
	return root, nil
}

// signer is an administrator key with its certificate, checked against the
// pinned root before anything is signed.
type signer struct {
	key   *statement.Signer
	owner string
	cert  []byte
}

func loadSigner(adminDir, passFile, certificate string, root statement.PublicKey, pin string, now time.Time) (signer, error) {
	passphrase, err := trust.ReadPassphrase(passFile)
	if err != nil {
		return signer{}, err
	}
	key, _, err := trust.LoadKey(filepath.Join(adminDir, trust.AdminKeyFile), passphrase, statement.RoleAdministrator)
	if err != nil {
		return signer{}, err
	}
	cert, err := os.ReadFile(filepath.Clean(certificate))
	if err != nil {
		return signer{}, err
	}
	v, claim, err := trust.VerifyAdministrator(cert, root, pin, now)
	if err != nil {
		return signer{}, err
	}
	if v.Key.Fingerprint() != key.Public().Fingerprint() {
		return signer{}, errors.New("the certificate is for another administrator key")
	}
	return signer{key: key, owner: claim.Owner, cert: cert}, nil
}

// sign signs payload and bundles it with the certificate and root, as ADR 0023
// defines, then checks the result as an agent would.
func (s signer) sign(t statement.Type, payload []byte, root statement.PublicKey, pin string, now time.Time) ([]byte, error) {
	e, err := statement.Sign(t, payload, s.key)
	if err != nil {
		return nil, err
	}
	signed, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	ed, ml := root.Bytes()
	bundle, err := json.Marshal(trust.Approval{
		Statement: signed, AdministratorCertificates: []json.RawMessage{bytes.TrimSpace(s.cert)}, RootEd25519: ed, RootMLDSA65: ml,
	})
	if err != nil {
		return nil, err
	}
	if _, err := trust.VerifyApproval(bundle, t, pin, 1, now); err != nil {
		return nil, err
	}
	return bundle, nil
}

func (c *apiClient) flow(id string) (flowRecord, error) {
	var f flowRecord
	err := c.do(http.MethodGet, "/flows/"+id, nil, http.StatusOK, &f)
	return f, err
}

// version fetches a flow version and parses its payload, requiring it to be
// the version asked for.
func (c *apiClient) version(flowID string, n int) (versionRecord, *flow.Version, error) {
	var v versionRecord
	if err := c.do(http.MethodGet, "/flows/"+flowID+"/versions/"+strconv.Itoa(n), nil, http.StatusOK, &v); err != nil {
		return versionRecord{}, nil, err
	}
	parsed, err := flow.Parse(v.Payload)
	if err != nil {
		return versionRecord{}, nil, err
	}
	if parsed.FlowID != flowID || parsed.FlowVersion != int64(n) {
		return versionRecord{}, nil, refused("the orchestrator returned a payload for another flow or version")
	}
	return v, parsed, nil
}

func payloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// flowDiff prints what changed from the flow's approved version to version N,
// with the payload's hash to approve it by. The approved version is used only
// once its approval verifies against the pinned root, so the orchestrator
// can't make a change look smaller than it is.
func flowDiff(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("flow diff", flag.ContinueOnError)
	ff := newFlowFlags(fs)
	n := fs.Int("version", 0, "version to review")
	if err := parse(fs, args, stderr, flowRequired...); err != nil {
		return err
	}
	if *n < 1 {
		return errUsage
	}
	_, client, err := ff.connect(now)
	if err != nil {
		return err
	}
	f, err := client.flow(*ff.flowID)
	if err != nil {
		return err
	}
	v, to, err := client.version(*ff.flowID, *n)
	if err != nil {
		return err
	}
	var base *flow.Version
	if f.ApprovedVersion != nil {
		approved, parsed, err := client.version(*ff.flowID, *f.ApprovedVersion)
		if err != nil {
			return err
		}
		got, err := trust.VerifyApproval(approved.Approval, statement.TypeFlowVersion, *ff.rootPin, 1, now())
		if err != nil || !bytes.Equal(got.Payload, approved.Payload) {
			return refused("the approved version %d has no approval that verifies against the pinned root", *f.ApprovedVersion)
		}
		base = parsed
	}
	names := map[string]string{}
	if listed, err := client.agents(); err == nil {
		for _, a := range to.Agents {
			if l, ok := listed[a]; ok {
				names[a] = l.Name
			}
		}
	}
	return output(stdout, map[string]any{
		"flow_id":          *ff.flowID,
		"version":          *n,
		"status":           v.Status,
		"sha256":           payloadSHA256(v.Payload),
		"approved_version": f.ApprovedVersion,
		"changes":          flow.Compare(base, to),
		// Names aren't in the signed payload. Only the agent IDs are approved.
		"agent_names_reported": names,
	})
}

// flowApprove signs version N, only if its payload has the SHA-256 given, which
// the administrator took from a reviewed `mmft flow diff` or a pipeline. It
// never prompts.
func flowApprove(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("flow approve", flag.ContinueOnError)
	ff := newFlowFlags(fs)
	n := fs.Int("version", 0, "version to approve")
	want := fs.String("sha256", "", "SHA-256 of the reviewed payload")
	adminDir := fs.String("admin-dir", "", "directory holding the administrator key")
	passFile := fs.String("passphrase-file", "", "file holding the administrator key passphrase")
	certificate := fs.String("certificate", "", "administrator's certificate")
	if err := parse(fs, args, stderr, append(flowRequired, "sha256", "admin-dir", "passphrase-file", "certificate")...); err != nil {
		return err
	}
	if *n < 1 || !sha256Pattern.MatchString(*want) {
		return errUsage
	}
	root, client, err := ff.connect(now)
	if err != nil {
		return err
	}
	admin, err := loadSigner(*adminDir, *passFile, *certificate, root, *ff.rootPin, now())
	if err != nil {
		return err
	}
	v, _, err := client.version(*ff.flowID, *n)
	if err != nil {
		return err
	}
	if got := payloadSHA256(v.Payload); got != *want {
		return refused("version %d has SHA-256 %s, not the %s given", *n, got, *want)
	}
	switch v.Status {
	case "approved":
		return os.ErrExist
	case "superseded":
		return errors.New("a newer version is already approved")
	}
	bundle, err := admin.sign(statement.TypeFlowVersion, v.Payload, root, *ff.rootPin, now())
	if err != nil {
		return err
	}
	if err := client.do(http.MethodPut, "/flows/"+*ff.flowID+"/versions/"+strconv.Itoa(*n)+"/approval", bundle, http.StatusNoContent, nil); err != nil {
		return err
	}
	return output(stdout, map[string]any{
		"flow_id": *ff.flowID, "version": *n, "sha256": *want, "status": "approved", "approved_by": admin.owner,
	})
}

// flowRetire signs a retirement of the flow, which must be in the workspace
// given, so the administrator states what they retire rather than trusting
// the orchestrator's report.
func flowRetire(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("flow retire", flag.ContinueOnError)
	ff := newFlowFlags(fs)
	workspace := fs.String("workspace", "", "workspace the flow is in")
	adminDir := fs.String("admin-dir", "", "directory holding the administrator key")
	passFile := fs.String("passphrase-file", "", "file holding the administrator key passphrase")
	certificate := fs.String("certificate", "", "administrator's certificate")
	if err := parse(fs, args, stderr, append(flowRequired, "workspace", "admin-dir", "passphrase-file", "certificate")...); err != nil {
		return err
	}
	if !trust.ValidName(*workspace) {
		return errUsage
	}
	root, client, err := ff.connect(now)
	if err != nil {
		return err
	}
	admin, err := loadSigner(*adminDir, *passFile, *certificate, root, *ff.rootPin, now())
	if err != nil {
		return err
	}
	f, err := client.flow(*ff.flowID)
	if err != nil {
		return err
	}
	if f.Workspace != *workspace {
		return refused("the flow is in workspace %q, not %q", f.Workspace, *workspace)
	}
	if f.Retired {
		return os.ErrExist
	}
	payload, err := json.Marshal(flow.Retirement{Version: flow.PayloadVersion, FlowID: *ff.flowID, Workspace: *workspace})
	if err != nil {
		return err
	}
	bundle, err := admin.sign(statement.TypeFlowRetirement, payload, root, *ff.rootPin, now())
	if err != nil {
		return err
	}
	if err := client.do(http.MethodPut, "/flows/"+*ff.flowID+"/retirement", bundle, http.StatusNoContent, nil); err != nil {
		return err
	}
	return output(stdout, map[string]any{"flow_id": *ff.flowID, "workspace": *workspace, "status": "retired", "retired_by": admin.owner})
}
