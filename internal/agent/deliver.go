package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"filippo.io/age"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/newfile"
	"mmft.dev/mmft/internal/seal"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// Manual deliveries, as ADR 0021 defines. The agent reads only from its outbox
// and writes only to its inbox, both set on its host. It checks the other
// agent's identity against its own pinned root, never trusting the
// orchestrator's word for whose keys they are.

// Stable error codes an agent reports for a manual delivery. They never hold
// a path, a file name, or raw error output.
const (
	codeNotConfigured     = "deliveries_not_configured"
	codeInvalidFileName   = "invalid_file_name"
	codePeerInvalid       = "peer_identity_invalid"
	codeSourceMissing     = "source_missing"
	codeSourceNotRegular  = "source_not_regular"
	codeSpoolFull         = "spool_full"
	codeSealFailed        = "seal_failed"
	codeRelayFailed       = "relay_failed"
	codeManifestInvalid   = "manifest_invalid"
	codeHashMismatch      = "hash_mismatch"
	codeDestinationExists = "destination_exists"
	codePlaceFailed       = "place_failed"
	codeInternal          = "internal_error"
)

// deliveryError carries the code to report for a failed delivery.
type deliveryError struct {
	code string
	err  error
}

func (e *deliveryError) Error() string { return e.code + ": " + e.err.Error() }
func (e *deliveryError) Unwrap() error { return e.err }

func failWith(code string, err error) error { return &deliveryError{code: code, err: err} }

var (
	errNotConfigured = errors.New("agent: this agent has no outbox or inbox for deliveries")
	errBadFileName   = errors.New("agent: the file name is not a bare file name")
	errPeerMismatch  = errors.New("agent: the identity is for another agent or workspace")
	errLinkedSource  = errors.New("agent: the source is a link or not a regular file")
)

// deliver runs this agent's side of a manual delivery and reports the result.
// It runs on its own, so a delivery outlives a dropped stream.
func (r *runner) deliver(ctx context.Context, d *agentv1.ManualDelivery) {
	id := d.GetDeliveryId()
	if !trust.ValidAgentID(id) {
		return
	}
	r.log("delivery started", nil, "delivery_id", id, "role", d.GetRole().String())
	var u *agentv1.DeliveryUpdate
	var err error
	switch d.GetRole() {
	case agentv1.DeliveryRole_DELIVERY_ROLE_SEND:
		err = r.sendSide(ctx, d)
	case agentv1.DeliveryRole_DELIVERY_ROLE_RECEIVE:
		u, err = r.receiveSide(ctx, d)
	default:
		err = failWith(codeInternal, errors.New("agent: unknown delivery role"))
	}
	if err != nil {
		code := codeInternal
		var de *deliveryError
		if errors.As(err, &de) {
			code = de.code
		}
		// Only the code goes in the log and the report, because the error can
		// name a path.
		r.log("delivery failed", nil, "delivery_id", id, "code", code)
		r.report(ctx, &agentv1.DeliveryUpdate{DeliveryId: id, State: agentv1.DeliveryState_DELIVERY_STATE_FAILED, ErrorCode: code})
		return
	}
	if u != nil {
		r.report(ctx, u)
	}
	r.log("delivery finished", nil, "delivery_id", id)
}

// report queues an update for the orchestrator. The session loop sends it on
// the current stream, or on the next one after a reconnect.
func (r *runner) report(ctx context.Context, u *agentv1.DeliveryUpdate) {
	select {
	case r.updates <- &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_DeliveryUpdate{DeliveryUpdate: u}}:
	case <-ctx.Done():
	}
}

// peer verifies the other agent's identity to this agent's pinned root, and
// requires it to be the agent the assignment names, in this agent's workspace.
func (r *runner) peer(d *agentv1.ManualDelivery) (trust.IdentityClaim, statement.Verifier, error) {
	claim, v, err := trust.VerifyAgent(d.GetPeerIdentityStatement(), r.s.RootFingerprint, r.cfg.Now())
	if err != nil {
		return claim, v, failWith(codePeerInvalid, err)
	}
	if claim.AgentID != d.GetPeerAgentId() || claim.AgentID == r.s.AgentID || claim.Workspace != r.s.Workspace {
		return claim, v, failWith(codePeerInvalid, errPeerMismatch)
	}
	return claim, v, nil
}

func (r *runner) relayConfig() RelayConfig {
	return RelayConfig{MinBackoff: r.cfg.MinBackoff, MaxBackoff: r.cfg.MaxBackoff, Now: r.cfg.Now}
}

// sendSide seals outbox/NAME to the verified destination, reports the signed
// manifest, and sends the sealed file through the relay.
func (r *runner) sendSide(ctx context.Context, d *agentv1.ManualDelivery) error {
	if r.cfg.Outbox == "" {
		return failWith(codeNotConfigured, errNotConfigured)
	}
	if !seal.ValidFileName(d.GetFileName()) {
		return failWith(codeInvalidFileName, errBadFileName)
	}
	claim, _, err := r.peer(d)
	if err != nil {
		return err
	}
	recipient, err := age.ParseHybridRecipient(claim.Recipient)
	if err != nil {
		return failWith(codePeerInvalid, err)
	}
	f, err := openSource(filepath.Join(r.cfg.Outbox, d.GetFileName()))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sealed, err := seal.File(f, r.cfg.Spool, recipient)
	switch {
	case errors.Is(err, seal.ErrNoSpace):
		return failWith(codeSpoolFull, err)
	case errors.Is(err, seal.ErrNotRegular):
		return failWith(codeSourceNotRegular, err)
	case err != nil:
		return failWith(codeSealFailed, err)
	}
	defer func() { _ = os.Remove(sealed.Path) }()

	delivery := seal.Delivery{DeliveryID: d.GetDeliveryId(), SourceAgent: r.s.AgentID, DestinationAgent: claim.AgentID}
	e, err := seal.SignManifest(delivery, sealed, r.keys.Signer)
	if err != nil {
		return failWith(codeInternal, err)
	}
	manifest, err := json.Marshal(e)
	if err != nil {
		return failWith(codeInternal, err)
	}
	r.report(ctx, &agentv1.DeliveryUpdate{
		DeliveryId:        d.GetDeliveryId(),
		State:             agentv1.DeliveryState_DELIVERY_STATE_TRANSFERRING,
		ManifestStatement: manifest,
	})
	if err := SendFile(ctx, r.dir, d.GetRelayTicket(), sealed.Path, r.relayConfig()); err != nil {
		return failWith(codeRelayFailed, err)
	}
	return nil
}

// openSource opens a file in the outbox, refusing a link: the name must be a
// regular file itself, and the file opened must be the one checked.
func openSource(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, failWith(codeSourceMissing, err)
	}
	if err != nil {
		return nil, failWith(codeSealFailed, err)
	}
	if !before.Mode().IsRegular() {
		return nil, failWith(codeSourceNotRegular, errLinkedSource)
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, failWith(codeSealFailed, err)
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, failWith(codeSourceNotRegular, errLinkedSource)
	}
	return f, nil
}

// receiveSide verifies the source and its manifest, receives the sealed file
// into the spool, checks and opens it, and places it in the inbox without ever
// replacing a file. It returns the update carrying the signed receipt.
func (r *runner) receiveSide(ctx context.Context, d *agentv1.ManualDelivery) (*agentv1.DeliveryUpdate, error) {
	if r.cfg.Inbox == "" {
		return nil, failWith(codeNotConfigured, errNotConfigured)
	}
	if !seal.ValidFileName(d.GetFileName()) {
		return nil, failWith(codeInvalidFileName, errBadFileName)
	}
	claim, source, err := r.peer(d)
	if err != nil {
		return nil, err
	}
	delivery := seal.Delivery{DeliveryID: d.GetDeliveryId(), SourceAgent: claim.AgentID, DestinationAgent: r.s.AgentID}
	m, _, err := seal.VerifyManifest(d.GetManifestStatement(), source, delivery)
	if err != nil {
		return nil, failWith(codeManifestInvalid, err)
	}
	dest := filepath.Join(r.cfg.Inbox, d.GetFileName())
	// Checked again when the file is placed. This only saves a transfer.
	if _, err := os.Lstat(dest); !errors.Is(err, fs.ErrNotExist) {
		return nil, failWith(codeDestinationExists, fs.ErrExist)
	}

	// A fixed spool name per delivery, so a retried receive resumes.
	spooled := filepath.Join(r.cfg.Spool, "receive-"+d.GetDeliveryId()+".age")
	defer func() { _ = os.Remove(spooled) }()
	if err := ReceiveFile(ctx, r.dir, d.GetRelayTicket(), spooled, uint64(m.SealedSize), r.relayConfig()); err != nil { //nolint:gosec // a verified manifest's size is positive
		return nil, failWith(codeRelayFailed, err)
	}
	opened, err := seal.Open(spooled, m, r.keys.Encryption, r.cfg.Inbox)
	switch {
	case errors.Is(err, seal.ErrHashMismatch), errors.Is(err, seal.ErrSizeMismatch):
		return nil, failWith(codeHashMismatch, err)
	case err != nil:
		return nil, failWith(codeHashMismatch, err)
	}
	defer func() { _ = os.Remove(opened) }()
	if err := place(opened, dest); err != nil {
		return nil, err
	}

	var sum [32]byte
	if _, err := hex.Decode(sum[:], []byte(m.SealedSHA256)); err != nil {
		return nil, failWith(codeInternal, err)
	}
	e, err := seal.SignReceipt(delivery, seal.Sealed{Size: m.SealedSize, SHA256: sum}, r.keys.Signer)
	if err != nil {
		return nil, failWith(codeInternal, err)
	}
	receipt, err := json.Marshal(e)
	if err != nil {
		return nil, failWith(codeInternal, err)
	}
	return &agentv1.DeliveryUpdate{
		DeliveryId:       d.GetDeliveryId(),
		State:            agentv1.DeliveryState_DELIVERY_STATE_SUCCEEDED,
		ReceiptStatement: receipt,
	}, nil
}

// place gives the opened file its final name with a hard link, which fails if
// anything, including a link, already has that name. It never replaces a file.
func place(opened, dest string) error {
	if err := os.Link(opened, dest); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return failWith(codeDestinationExists, fs.ErrExist)
		}
		return failWith(codePlaceFailed, fmt.Errorf("agent: place the file: %w", errors.Unwrap(err)))
	}
	return newfile.SyncDir(filepath.Dir(dest))
}
