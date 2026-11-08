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
	"time"

	"filippo.io/age"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/allowlist"
	"mmft.dev/mmft/internal/newfile"
	"mmft.dev/mmft/internal/seal"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// Manual deliveries, as ADR 0021 defines. The agent reads only from its outbox
// and writes only to its inbox, both set on its host, and each is checked
// against the allowlist and opened through it for every delivery (ADR 0024).
// It checks the other agent's identity against its own pinned root, never
// trusting the orchestrator's word for whose keys they are, and requires the
// allowlist to allow that agent.

// Stable error codes an agent reports for a manual delivery. They never hold
// a path, a file name, or raw error output.
const (
	codeNotConfigured     = "deliveries_not_configured"
	codePathNotAllowed    = "path_not_allowed"
	codePeerNotAllowed    = "peer_not_allowed"
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
	errNotConfigured  = errors.New("agent: this agent has no outbox or inbox for deliveries")
	errBadFileName    = errors.New("agent: the file name is not a bare file name")
	errPeerMismatch   = errors.New("agent: the identity is for another agent or workspace")
	errPeerNotAllowed = errors.New("agent: the allowlist doesn't allow the other agent")
)

// deliveryEnded runs as each delivery's goroutine ends. Tests replace it.
var deliveryEnded = func() {}

// work is one side of a delivery this agent has claimed, as ADR 0026 defines.
type work struct {
	granted bool
	// leaseSeconds is how long the lease lasts unless an update extends it.
	leaseSeconds uint32
	// cancel stops the side once it runs.
	cancel context.CancelFunc
	// unclaimed drops the claim if no assignment follows it.
	unclaimed *time.Timer
}

// offered claims the work in an offer if the agent has room for it. Claims
// waiting for an answer count toward maxDeliveries, so an orchestrator can't
// make the agent take more at once. A full agent just doesn't claim, and the
// work is offered again later.
func (r *runner) offered(ctx context.Context, o *agentv1.WorkOffer) {
	id := o.GetWorkId()
	if !trust.ValidAgentID(id) {
		return
	}
	r.deliveriesMu.Lock()
	if r.work[id] != nil || len(r.work) >= maxDeliveries {
		r.deliveriesMu.Unlock()
		return
	}
	w := &work{}
	w.unclaimed = time.AfterFunc(callTimeout, func() {
		r.deliveriesMu.Lock()
		defer r.deliveriesMu.Unlock()
		if r.work[id] == w && w.cancel == nil {
			delete(r.work, id)
		}
	})
	r.work[id] = w
	r.deliveriesMu.Unlock()
	r.queue(ctx, &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_LeaseClaim{LeaseClaim: &agentv1.LeaseClaim{WorkId: id}}})
}

// leaseResult records whether a claim was granted.
func (r *runner) leaseResult(res *agentv1.LeaseResult) {
	r.deliveriesMu.Lock()
	defer r.deliveriesMu.Unlock()
	w := r.work[res.GetWorkId()]
	if w == nil || w.granted {
		return
	}
	if !res.GetGranted() {
		w.unclaimed.Stop()
		delete(r.work, res.GetWorkId())
		return
	}
	w.granted, w.leaseSeconds = true, res.GetLeaseSeconds()
}

// cancelled stops the work a Cancel names, because its lease has ended.
func (r *runner) cancelled(c *agentv1.Cancel) {
	r.deliveriesMu.Lock()
	defer r.deliveriesMu.Unlock()
	w := r.work[c.GetWorkId()]
	switch {
	case w == nil:
	case w.cancel != nil:
		w.cancel()
	default:
		w.unclaimed.Stop()
		delete(r.work, c.GetWorkId())
	}
}

// startDelivery runs an assignment on its own, so it outlives a dropped
// stream. It runs only under a granted lease the agent holds, and a delivery
// already in progress is not started twice.
func (r *runner) startDelivery(ctx context.Context, d *agentv1.ManualDelivery) {
	id, workID := d.GetDeliveryId(), d.GetWorkId()
	r.deliveriesMu.Lock()
	defer r.deliveriesMu.Unlock()
	w := r.work[workID]
	if w == nil || !w.granted || w.cancel != nil || r.active[id] {
		return
	}
	w.unclaimed.Stop()
	ctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	r.active[id] = true
	r.deliveries.Add(1)
	go func() {
		defer r.deliveries.Done()
		defer deliveryEnded()
		defer func() {
			cancel()
			r.deliveriesMu.Lock()
			delete(r.active, id)
			delete(r.work, workID)
			r.deliveriesMu.Unlock()
		}()
		go r.progress(ctx, d, w.leaseSeconds)
		r.deliver(ctx, d)
	}()
}

// progress extends the lease at a third of its length until the side ends,
// so a long transfer keeps it.
func (r *runner) progress(ctx context.Context, d *agentv1.ManualDelivery, leaseSeconds uint32) {
	every := time.Duration(leaseSeconds) * time.Second / 3
	if every <= 0 {
		every = defaultProgress
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.report(ctx, &agentv1.DeliveryUpdate{WorkId: d.GetWorkId(), DeliveryId: d.GetDeliveryId()})
		}
	}
}

// deliver runs this agent's side of a manual delivery and reports the result.
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
		u, err = r.sendSide(ctx, d)
	case agentv1.DeliveryRole_DELIVERY_ROLE_RECEIVE:
		u, err = r.receiveSide(ctx, d)
	default:
		err = failWith(codeInternal, errors.New("agent: unknown delivery role"))
	}
	if err != nil && ctx.Err() != nil {
		// Cancelled, or the agent is stopping. The orchestrator no longer
		// takes reports under this lease.
		r.log("delivery stopped", nil, "delivery_id", id)
		return
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
		r.report(ctx, &agentv1.DeliveryUpdate{WorkId: d.GetWorkId(), DeliveryId: id, State: agentv1.DeliveryState_DELIVERY_STATE_FAILED, ErrorCode: code})
		return
	}
	r.report(ctx, u)
	r.log("delivery finished", nil, "delivery_id", id)
}

// report queues an update for the orchestrator.
func (r *runner) report(ctx context.Context, u *agentv1.DeliveryUpdate) {
	r.queue(ctx, &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_DeliveryUpdate{DeliveryUpdate: u}})
}

// queue holds a message for the orchestrator. The session loop sends it on
// the current stream, or on the next one after a reconnect.
func (r *runner) queue(ctx context.Context, m *agentv1.ConnectRequest) {
	select {
	case r.updates <- m:
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
// manifest, and sends the sealed file through the relay. It returns the update
// saying its side is done.
func (r *runner) sendSide(ctx context.Context, d *agentv1.ManualDelivery) (*agentv1.DeliveryUpdate, error) {
	if r.cfg.Outbox == "" {
		return nil, failWith(codeNotConfigured, errNotConfigured)
	}
	if !seal.ValidFileName(d.GetFileName()) {
		return nil, failWith(codeInvalidFileName, errBadFileName)
	}
	claim, _, err := r.peer(d)
	if err != nil {
		return nil, err
	}
	if !r.cfg.Allowlist.MaySendTo(claim.AgentID, claim.Workspace) {
		return nil, failWith(codePeerNotAllowed, errPeerNotAllowed)
	}
	recipient, err := age.ParseHybridRecipient(claim.Recipient)
	if err != nil {
		return nil, failWith(codePeerInvalid, err)
	}
	outbox, err := r.cfg.Allowlist.Dir(r.cfg.Outbox, allowlist.Read)
	if err != nil {
		return nil, failWith(codePathNotAllowed, err)
	}
	defer func() { _ = outbox.Close() }()
	f, err := openSource(outbox, d.GetFileName())
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sealed, err := seal.File(f, r.cfg.Spool, recipient)
	switch {
	case errors.Is(err, seal.ErrNoSpace):
		return nil, failWith(codeSpoolFull, err)
	case errors.Is(err, seal.ErrNotRegular):
		return nil, failWith(codeSourceNotRegular, err)
	case err != nil:
		return nil, failWith(codeSealFailed, err)
	}
	defer func() { _ = os.Remove(sealed.Path) }()

	delivery := seal.Delivery{DeliveryID: d.GetDeliveryId(), SourceAgent: r.s.AgentID, DestinationAgent: claim.AgentID}
	e, err := seal.SignManifest(delivery, sealed, r.keys.Signer)
	if err != nil {
		return nil, failWith(codeInternal, err)
	}
	manifest, err := json.Marshal(e)
	if err != nil {
		return nil, failWith(codeInternal, err)
	}
	r.report(ctx, &agentv1.DeliveryUpdate{
		WorkId:            d.GetWorkId(),
		DeliveryId:        d.GetDeliveryId(),
		State:             agentv1.DeliveryState_DELIVERY_STATE_TRANSFERRING,
		ManifestStatement: manifest,
	})
	if err := SendFile(ctx, r.dir, d.GetRelayTicket(), sealed.Path, r.relayConfig()); err != nil {
		return nil, failWith(codeRelayFailed, err)
	}
	return &agentv1.DeliveryUpdate{WorkId: d.GetWorkId(), DeliveryId: d.GetDeliveryId(), SideDone: true}, nil
}

// openSource opens a file in the outbox, refusing a link: the name must be a
// regular file itself, and the file opened must be the one checked.
func openSource(outbox *os.Root, name string) (*os.File, error) {
	f, err := allowlist.OpenRegular(outbox, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, failWith(codeSourceMissing, err)
	case errors.Is(err, allowlist.ErrNotRegular), errors.Is(err, allowlist.ErrSwapped):
		return nil, failWith(codeSourceNotRegular, err)
	case err != nil:
		return nil, failWith(codeSealFailed, err)
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
	if !r.cfg.Allowlist.MayReceiveFrom(claim.AgentID, claim.Workspace) {
		return nil, failWith(codePeerNotAllowed, errPeerNotAllowed)
	}
	delivery := seal.Delivery{DeliveryID: d.GetDeliveryId(), SourceAgent: claim.AgentID, DestinationAgent: r.s.AgentID}
	m, _, err := seal.VerifyManifest(d.GetManifestStatement(), source, delivery)
	if err != nil {
		return nil, failWith(codeManifestInvalid, err)
	}
	inbox, err := r.cfg.Allowlist.Dir(r.cfg.Inbox, allowlist.Write)
	if err != nil {
		return nil, failWith(codePathNotAllowed, err)
	}
	defer func() { _ = inbox.Close() }()
	name := d.GetFileName()
	// Checked again when the file is placed. This only saves a transfer.
	if _, err := inbox.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		return nil, failWith(codeDestinationExists, fs.ErrExist)
	}

	// The sealed copy goes to the spool, and the decrypted one, which is no
	// larger, to the inbox. Both must fit before any byte arrives.
	size := uint64(m.SealedSize) //nolint:gosec // a verified manifest's size is positive
	for _, dir := range []string{r.cfg.Spool, r.cfg.Inbox} {
		if err := seal.HasRoom(dir, size); err != nil {
			return nil, failWith(codeSpoolFull, err)
		}
	}

	// A fixed spool name per delivery. ReceiveFile resumes it across dropped
	// connections, and it is removed when this side ends.
	spooled := filepath.Join(r.cfg.Spool, "receive-"+d.GetDeliveryId()+".age")
	defer func() { _ = os.Remove(spooled) }()
	if err := ReceiveFile(ctx, r.dir, d.GetRelayTicket(), spooled, size, r.relayConfig()); err != nil {
		return nil, failWith(codeRelayFailed, err)
	}
	r.report(ctx, &agentv1.DeliveryUpdate{
		WorkId: d.GetWorkId(), DeliveryId: d.GetDeliveryId(), State: agentv1.DeliveryState_DELIVERY_STATE_VERIFYING,
	})
	opened, err := seal.Open(spooled, m, r.keys.Encryption, inbox)
	switch {
	case errors.Is(err, seal.ErrHashMismatch), errors.Is(err, seal.ErrSizeMismatch):
		return nil, failWith(codeHashMismatch, err)
	case err != nil:
		return nil, failWith(codeHashMismatch, err)
	}
	defer func() { _ = inbox.Remove(opened) }()
	if err := place(inbox, opened, name); err != nil {
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
		WorkId:           d.GetWorkId(),
		DeliveryId:       d.GetDeliveryId(),
		State:            agentv1.DeliveryState_DELIVERY_STATE_SUCCEEDED,
		ReceiptStatement: receipt,
	}, nil
}

// place gives the opened file its final name in dir with a hard link, which
// fails if anything, including a link, already has that name. It never
// replaces a file.
func place(dir *os.Root, opened, name string) error {
	if err := dir.Link(opened, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return failWith(codeDestinationExists, fs.ErrExist)
		}
		return failWith(codePlaceFailed, fmt.Errorf("agent: place the file: %w", errors.Unwrap(err)))
	}
	return newfile.SyncRoot(dir)
}
