package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/relayticket"
	"mmft.dev/mmft/internal/seal"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// relayHarness is a server with relay settings, and the ticket key it signs
// with.
type relayHarness struct {
	harness
	ticketKey ed25519.PrivateKey
	relayFP   []byte
}

func startWithRelay(t *testing.T) relayHarness {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256([]byte("relay certificate"))
	h := startWith(t, func(c *Config) {
		c.RelayAddress, c.RelayCertificateSHA256, c.TicketKey = "relay.test:7445", fp[:], key
	})
	return relayHarness{harness: h, ticketKey: key, relayFP: fp[:]}
}

// runAgentFor is an enrolled agent that keeps its signing key, so it can sign
// manifests and receipts.
type runAgentFor struct {
	enrolled
	signer *statement.Signer
	stream agentv1.AgentService_ConnectClient
}

// approvedAgent enrolls and approves an agent, and opens its stream.
func (h harness) approvedAgent(t *testing.T, a approver, workspace, name string) *runAgentFor {
	t.Helper()
	_, connKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, connKey)
	if err != nil {
		t.Fatal(err)
	}
	k := newTestKeys(t)
	resp, err := h.enroll(t, k.request(t, h.token(t, workspace, name), workspace, name, csr))
	if err != nil {
		t.Fatal(err)
	}
	ed, ml := k.signer.Public().Bytes()
	agent := &runAgentFor{
		enrolled: enrolled{
			id:   resp.GetAgentId(),
			keys: trust.AgentKeys{Ed25519: ed, MLDSA65: ml, Recipient: k.recipient},
			cert: tls.Certificate{Certificate: [][]byte{resp.GetConnectionCertificate()}, PrivateKey: connKey},
		},
		signer: k.signer,
	}
	if a.root != nil {
		if code, body := h.do(t, http.MethodPut, "/api/v1/agents/"+agent.id+"/identity", a.sign(t, agent.id, workspace, name, agent.keys)); code != http.StatusNoContent {
			t.Fatalf("approve %s: %d %s", name, code, body)
		}
	}
	return agent
}

func (h harness) connect(t *testing.T, a *runAgentFor) {
	t.Helper()
	stream, resp, err := h.openStream(t, a.enrolled, hello(ProtocolVersion))
	if err != nil || resp.GetWelcome() == nil {
		t.Fatalf("connect: %v", err)
	}
	a.stream = stream
}

func (h harness) startRun(t *testing.T, body map[string]string) (int, runItem) {
	t.Helper()
	data, _ := json.Marshal(body)
	code, out := h.do(t, http.MethodPost, "/api/v1/runs", data)
	var run runItem
	_ = json.Unmarshal(out, &run)
	return code, run
}

func (h harness) run(t *testing.T, id string) runItem {
	t.Helper()
	code, out := h.do(t, http.MethodGet, "/api/v1/runs/"+id, nil)
	if code != http.StatusOK {
		t.Fatalf("get run: %d %s", code, out)
	}
	var run runItem
	if err := json.Unmarshal(out, &run); err != nil {
		t.Fatal(err)
	}
	return run
}

// waitDelivery waits for the run's delivery to reach status.
func (h harness) waitDelivery(t *testing.T, runID, status string) deliveryItem {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		run := h.run(t, runID)
		if d := run.Deliveries[0]; d.Status == status {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivery is %+v, want %s", run.Deliveries[0], status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// receive returns the next message from the agent's stream that pick accepts,
// skipping others.
func receive[T any](t *testing.T, a *runAgentFor, pick func(*agentv1.ConnectResponse) T) T {
	t.Helper()
	var zero T
	for {
		resp, err := a.stream.Recv()
		if err != nil {
			t.Fatalf("waiting for a message: %v", err)
		}
		if v := pick(resp); any(v) != any(zero) {
			return v
		}
	}
}

func offer(t *testing.T, a *runAgentFor) *agentv1.WorkOffer {
	t.Helper()
	return receive(t, a, (*agentv1.ConnectResponse).GetWorkOffer)
}

func sendClaim(t *testing.T, a *runAgentFor, workID string) {
	t.Helper()
	if err := a.stream.Send(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_LeaseClaim{LeaseClaim: &agentv1.LeaseClaim{WorkId: workID}}}); err != nil {
		t.Fatal(err)
	}
}

// claim waits for an offer, claims it, and returns the assignment granted.
func claim(t *testing.T, a *runAgentFor) *agentv1.ManualDelivery {
	t.Helper()
	o := offer(t, a)
	sendClaim(t, a, o.GetWorkId())
	r := receive(t, a, (*agentv1.ConnectResponse).GetLeaseResult)
	if !r.GetGranted() || r.GetWorkId() != o.GetWorkId() || r.GetLeaseSeconds() != 60 {
		t.Fatalf("lease result %+v", r)
	}
	d := receive(t, a, (*agentv1.ConnectResponse).GetManualDelivery)
	if d.GetWorkId() != o.GetWorkId() {
		t.Fatalf("assignment for work %q, want %q", d.GetWorkId(), o.GetWorkId())
	}
	return d
}

func update(t *testing.T, a *runAgentFor, u *agentv1.DeliveryUpdate) {
	t.Helper()
	if err := a.stream.Send(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_DeliveryUpdate{DeliveryUpdate: u}}); err != nil {
		t.Fatal(err)
	}
}

var testSealed = seal.Sealed{Size: 4096, SHA256: sha256.Sum256([]byte("sealed bytes"))}

func manifestFor(t *testing.T, d seal.Delivery, s seal.Sealed, signer *statement.Signer) []byte {
	t.Helper()
	e, err := seal.SignManifest(d, s, signer)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	return b
}

func receiptFor(t *testing.T, d seal.Delivery, s seal.Sealed, signer *statement.Signer) []byte {
	t.Helper()
	e, err := seal.SignReceipt(d, s, signer)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	return b
}

// pair is two approved, connected agents in the lab workspace.
func pair(t *testing.T) (relayHarness, *runAgentFor, *runAgentFor) {
	t.Helper()
	h := startWithRelay(t)
	ap := newApprover(t)
	a, b := h.approvedAgent(t, ap, "lab", "agent-a"), h.approvedAgent(t, ap, "lab", "agent-b")
	h.connect(t, a)
	h.connect(t, b)
	return h, a, b
}

func runBody(a, b *runAgentFor) map[string]string {
	return map[string]string{"source_agent_id": a.id, "destination_agent_id": b.id, "file_name": "report.csv"}
}

// events returns a delivery's recorded status changes, as "from>to".
func (h harness) events(t *testing.T, deliveryID string) []string {
	t.Helper()
	rows, err := h.db.Query(t.Context(), `
		SELECT coalesce(from_status, '') || '>' || to_status FROM delivery_events WHERE delivery_id = $1 ORDER BY id`, deliveryID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// leaseExpiry returns when a lease expires, and whether it has ended.
func (h harness) lease(t *testing.T, workID string) (expires time.Time, endReason *string) {
	t.Helper()
	if err := h.db.QueryRow(t.Context(), `SELECT expires_at, end_reason FROM delivery_leases WHERE id = $1`, workID).
		Scan(&expires, &endReason); err != nil {
		t.Fatal(err)
	}
	return expires, endReason
}

func TestManualRunCompletesWithBothStatements(t *testing.T) {
	h, a, b := pair(t)
	code, run := h.startRun(t, runBody(a, b))
	if code != http.StatusAccepted || run.FlowID != nil || run.Status != "pending" || len(run.Deliveries) != 1 {
		t.Fatalf("start: %d %+v", code, run)
	}

	send := claim(t, a)
	if send.GetRole() != agentv1.DeliveryRole_DELIVERY_ROLE_SEND || send.GetFileName() != "report.csv" || send.GetPeerAgentId() != b.id {
		t.Fatalf("source assignment: %+v", send)
	}
	if claim, _, err := trust.CheckIdentity(send.GetPeerIdentityStatement(), time.Now()); err != nil || claim.AgentID != b.id {
		t.Fatalf("the source got another identity: %v", err)
	}
	ticket, err := relayticket.Verify(h.ticketKey.Public().(ed25519.PublicKey), send.GetRelayTicket().GetTicket(), time.Now())
	if err != nil || ticket.Role != relayticket.Send || ticket.Holder != a.id || ticket.Peer != b.id || ticket.DeliveryID != send.GetDeliveryId() {
		t.Fatalf("send ticket %+v: %v", ticket, err)
	}
	if send.GetRelayTicket().GetRelayAddress() != "relay.test:7445" || string(send.GetRelayTicket().GetRelayCertificateSha256()) != string(h.relayFP) {
		t.Fatalf("relay settings %+v", send.GetRelayTicket())
	}
	h.waitDelivery(t, run.ID, "claimed")
	if got := h.run(t, run.ID).Status; got != "running" {
		t.Fatalf("after the claim the run is %s", got)
	}

	d := seal.Delivery{DeliveryID: send.GetDeliveryId(), SourceAgent: a.id, DestinationAgent: b.id}
	manifest := manifestFor(t, d, testSealed, a.signer)
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: d.DeliveryID, State: agentv1.DeliveryState_DELIVERY_STATE_TRANSFERRING, ManifestStatement: manifest})
	got := h.waitDelivery(t, run.ID, "transferring")
	if got.Evidence != "source_only" || got.SizeBytes == nil || *got.SizeBytes != testSealed.Size {
		t.Fatalf("after the manifest: %+v", got)
	}

	receive := claim(t, b)
	if receive.GetRole() != agentv1.DeliveryRole_DELIVERY_ROLE_RECEIVE || receive.GetFileName() != "report.csv" ||
		receive.GetPeerAgentId() != a.id || string(receive.GetManifestStatement()) != string(manifest) {
		t.Fatalf("destination assignment: %+v", receive)
	}
	if claim, _, err := trust.CheckIdentity(receive.GetPeerIdentityStatement(), time.Now()); err != nil || claim.AgentID != a.id {
		t.Fatalf("the destination got another identity: %v", err)
	}
	ticket, err = relayticket.Verify(h.ticketKey.Public().(ed25519.PublicKey), receive.GetRelayTicket().GetTicket(), time.Now())
	if err != nil || ticket.Role != relayticket.Receive || ticket.Holder != b.id || ticket.Peer != a.id {
		t.Fatalf("receive ticket %+v: %v", ticket, err)
	}

	// The source is done once the relay has the file.
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: d.DeliveryID, SideDone: true})
	update(t, b, &agentv1.DeliveryUpdate{WorkId: receive.GetWorkId(), DeliveryId: d.DeliveryID, State: agentv1.DeliveryState_DELIVERY_STATE_VERIFYING})
	h.waitDelivery(t, run.ID, "verifying")
	if _, reason := h.lease(t, send.GetWorkId()); reason == nil || *reason != "released" {
		t.Fatalf("the send lease ended with %v", reason)
	}

	receipt := receiptFor(t, d, testSealed, b.signer)
	update(t, b, &agentv1.DeliveryUpdate{WorkId: receive.GetWorkId(), DeliveryId: d.DeliveryID, State: agentv1.DeliveryState_DELIVERY_STATE_SUCCEEDED, ReceiptStatement: receipt})
	got = h.waitDelivery(t, run.ID, "succeeded")
	if got.Evidence != "verified" || got.FileName == nil || *got.FileName != "report.csv" {
		t.Fatalf("after the receipt: %+v", got)
	}
	if h.run(t, run.ID).Status != "succeeded" {
		t.Fatal("the run did not succeed")
	}
	if _, reason := h.lease(t, receive.GetWorkId()); reason == nil {
		t.Fatal("the receive lease is still open")
	}
	want := []string{">pending", "pending>claimed", "claimed>transferring", "transferring>verifying", "verifying>succeeded"}
	if events := h.events(t, d.DeliveryID); strings.Join(events, " ") != strings.Join(want, " ") {
		t.Fatalf("events %v, want %v", events, want)
	}
	var leaked int
	if err := h.db.QueryRow(t.Context(), `SELECT count(*) FROM delivery_events e WHERE row_to_json(e)::text LIKE '%report.csv%'`).
		Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("%d events hold the file name: %v", leaked, err)
	}
}

func TestManualRunNeedsTwoApprovedAgents(t *testing.T) {
	h := startWithRelay(t)
	ap := newApprover(t)
	a := h.approvedAgent(t, ap, "lab", "agent-a")
	b := h.approvedAgent(t, ap, "lab", "agent-b")
	pending := h.approvedAgent(t, approver{}, "lab", "agent-p")
	other := h.approvedAgent(t, ap, "other", "agent-o")

	cases := map[string]struct {
		body map[string]string
		code int
	}{
		"pending destination": {runBody(a, pending), http.StatusConflict},
		"another workspace":   {runBody(a, other), http.StatusConflict},
		"same agent":          {runBody(a, a), http.StatusBadRequest},
		"unknown agent":       {map[string]string{"source_agent_id": a.id, "destination_agent_id": "0190a0b0-0000-7000-8000-000000000009", "file_name": "x"}, http.StatusNotFound},
		"a path":              {map[string]string{"source_agent_id": a.id, "destination_agent_id": b.id, "file_name": "../etc/passwd"}, http.StatusBadRequest},
		"no file name":        {map[string]string{"source_agent_id": a.id, "destination_agent_id": b.id}, http.StatusBadRequest},
	}
	for name, tc := range cases {
		if code, _ := h.startRun(t, tc.body); code != tc.code {
			t.Errorf("%s: %d, want %d", name, code, tc.code)
		}
	}
	var runs int
	if err := h.db.QueryRow(t.Context(), `SELECT count(*) FROM runs`).Scan(&runs); err != nil || runs != 0 {
		t.Fatalf("%d runs were created: %v", runs, err)
	}
}

func TestManualRunNeedsARelay(t *testing.T) {
	h := start(t)
	ap := newApprover(t)
	a, b := h.approvedAgent(t, ap, "lab", "agent-a"), h.approvedAgent(t, ap, "lab", "agent-b")
	if code, _ := h.startRun(t, runBody(a, b)); code != http.StatusConflict {
		t.Fatalf("got %d, want 409", code)
	}
}

func TestADeliveryToAnOfflineAgentWaits(t *testing.T) {
	h := startWithRelay(t)
	ap := newApprover(t)
	a, b := h.approvedAgent(t, ap, "lab", "agent-a"), h.approvedAgent(t, ap, "lab", "agent-b")
	code, run := h.startRun(t, runBody(a, b))
	if code != http.StatusAccepted || run.Status != "pending" || run.Deliveries[0].Status != "pending" {
		t.Fatalf("start with both offline: %d %+v", code, run)
	}
	// With only the source connected, nothing is offered: it would seal for a
	// destination that isn't there.
	h.connect(t, a)
	time.Sleep(200 * time.Millisecond)
	h.srv.offerWork(t.Context(), "", "")
	var leases int
	if err := h.db.QueryRow(t.Context(), `SELECT count(*) FROM delivery_leases`).Scan(&leases); err != nil || leases != 0 {
		t.Fatalf("%d leases were offered: %v", leases, err)
	}
	if got := h.run(t, run.ID); got.Status != "pending" || got.Deliveries[0].Status != "pending" {
		t.Fatalf("the waiting run changed: %+v", got)
	}
	// Once the destination connects, the source gets the work.
	h.connect(t, b)
	if d := claim(t, a); d.GetDeliveryId() != run.Deliveries[0].ID {
		t.Fatalf("claimed %s", d.GetDeliveryId())
	}
	h.waitDelivery(t, run.ID, "claimed")
}

func TestOnlyOneClaimIsGranted(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	o := offer(t, a)
	// Another agent can't claim work offered to this one.
	h.srv.claim(t.Context(), b.id, &agentv1.LeaseClaim{WorkId: o.GetWorkId()})
	if r := receive(t, b, (*agentv1.ConnectResponse).GetLeaseResult); r.GetGranted() {
		t.Fatal("the other agent's claim was granted")
	}
	const claims = 8
	var wg sync.WaitGroup
	for range claims {
		wg.Go(func() { h.srv.claim(t.Context(), a.id, &agentv1.LeaseClaim{WorkId: o.GetWorkId()}) })
	}
	wg.Wait()
	granted, refused := 0, 0
	for granted+refused < claims {
		resp, err := a.stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if r := resp.GetLeaseResult(); r != nil {
			if r.GetGranted() {
				granted++
			} else {
				refused++
			}
		}
	}
	if granted != 1 {
		t.Fatalf("%d claims were granted", granted)
	}
	h.waitDelivery(t, run.ID, "claimed")
}

func TestUpdatesWithoutTheLeaseAreIgnored(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	send := claim(t, a)
	id := send.GetDeliveryId()
	d := seal.Delivery{DeliveryID: id, SourceAgent: a.id, DestinationAgent: b.id}

	// The destination can't use the source's lease, nor the source act
	// without one.
	update(t, b, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: id, ManifestStatement: manifestFor(t, d, testSealed, b.signer)})
	update(t, a, &agentv1.DeliveryUpdate{DeliveryId: id, ManifestStatement: manifestFor(t, d, testSealed, a.signer)})
	update(t, a, &agentv1.DeliveryUpdate{WorkId: "0190a0b0-0000-7000-8000-00000000000e", DeliveryId: id, State: agentv1.DeliveryState_DELIVERY_STATE_FAILED, ErrorCode: "spool_full"})
	// The source can't send the receipt.
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: id, ReceiptStatement: receiptFor(t, d, testSealed, a.signer)})
	// A third agent can't fail it.
	ap := newApprover(t)
	c := h.approvedAgent(t, ap, "lab", "agent-c")
	h.connect(t, c)
	update(t, c, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: id, State: agentv1.DeliveryState_DELIVERY_STATE_FAILED, ErrorCode: "spool_full"})
	time.Sleep(200 * time.Millisecond)
	if got := h.run(t, run.ID).Deliveries[0]; got.Status != "claimed" || got.Evidence != "none" {
		t.Fatalf("delivery changed: %+v", got)
	}
}

func TestALeaseExpiresWithoutUpdates(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	send := claim(t, a)
	granted, _ := h.lease(t, send.GetWorkId())

	// Each update extends the lease from the time it arrives.
	h.clock.advance(50 * time.Second)
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: send.GetDeliveryId(), State: agentv1.DeliveryState_DELIVERY_STATE_SEALING})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if expires, _ := h.lease(t, send.GetWorkId()); expires.After(granted) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the update did not extend the lease")
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.clock.advance(50 * time.Second)
	h.srv.expireLeases(t.Context())
	if got := h.run(t, run.ID).Deliveries[0]; got.Status != "claimed" {
		t.Fatalf("an extended lease expired: %+v", got)
	}

	h.clock.advance(11 * time.Second)
	h.srv.expireLeases(t.Context())
	got := h.waitDelivery(t, run.ID, "failed")
	if got.ErrorCode == nil || *got.ErrorCode != codeLeaseExpired || h.run(t, run.ID).Status != "failed" {
		t.Fatalf("delivery %+v", got)
	}
	if _, reason := h.lease(t, send.GetWorkId()); reason == nil || *reason != "expired" {
		t.Fatalf("the lease ended with %v", reason)
	}
	if c := receive(t, a, (*agentv1.ConnectResponse).GetCancel); c.GetWorkId() != send.GetWorkId() || c.GetReason() != codeLeaseExpired {
		t.Fatalf("cancel %+v", c)
	}
	// An update after expiry changes nothing.
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: send.GetDeliveryId(), State: agentv1.DeliveryState_DELIVERY_STATE_SEALING})
	time.Sleep(100 * time.Millisecond)
	if expires, _ := h.lease(t, send.GetWorkId()); !expires.Before(h.clock.now()) {
		t.Fatal("an ended lease was extended")
	}
}

func TestAReleasedLeaseDoesNotExpire(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	send := claim(t, a)
	d := seal.Delivery{DeliveryID: send.GetDeliveryId(), SourceAgent: a.id, DestinationAgent: b.id}
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: d.DeliveryID, ManifestStatement: manifestFor(t, d, testSealed, a.signer)})
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: d.DeliveryID, SideDone: true})
	h.waitDelivery(t, run.ID, "transferring")
	h.clock.advance(40 * time.Second)
	receive := claim(t, b)
	h.clock.advance(30 * time.Second)
	h.srv.expireLeases(t.Context())
	if got := h.run(t, run.ID).Deliveries[0]; got.Status != "transferring" {
		t.Fatalf("delivery %+v", got)
	}
	// The receive lease, granted later, still expires on its own.
	h.clock.advance(31 * time.Second)
	h.srv.expireLeases(t.Context())
	h.waitDelivery(t, run.ID, "failed")
	if _, reason := h.lease(t, receive.GetWorkId()); reason == nil || *reason != "expired" {
		t.Fatalf("the receive lease ended with %v", reason)
	}
}

func TestAFailureCancelsTheOtherSide(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	send := claim(t, a)
	d := seal.Delivery{DeliveryID: send.GetDeliveryId(), SourceAgent: a.id, DestinationAgent: b.id}
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: d.DeliveryID, ManifestStatement: manifestFor(t, d, testSealed, a.signer)})
	receive := claim(t, b)
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: d.DeliveryID, State: agentv1.DeliveryState_DELIVERY_STATE_FAILED, ErrorCode: "relay_failed"})
	h.waitDelivery(t, run.ID, "failed")
	if c := receiveCancel(t, b); c.GetWorkId() != receive.GetWorkId() || c.GetReason() != "relay_failed" {
		t.Fatalf("cancel %+v", c)
	}
}

func receiveCancel(t *testing.T, a *runAgentFor) *agentv1.Cancel {
	t.Helper()
	return receive(t, a, (*agentv1.ConnectResponse).GetCancel)
}

func TestARestartGivesLeasesGrace(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	send := claim(t, a)
	// The orchestrator was down past the lease's expiry.
	h.clock.advance(5 * time.Minute)
	h.srv.graceLeases(t.Context())
	h.srv.expireLeases(t.Context())
	if got := h.run(t, run.ID).Deliveries[0]; got.Status != "claimed" {
		t.Fatalf("a lease expired at the restart: %+v", got)
	}
	if expires, _ := h.lease(t, send.GetWorkId()); !expires.Equal(h.clock.now().Add(time.Minute)) {
		t.Fatalf("the lease expires at %v", expires)
	}
}

func TestABadManifestFailsTheDelivery(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	send := claim(t, a)
	d := seal.Delivery{DeliveryID: send.GetDeliveryId(), SourceAgent: a.id, DestinationAgent: b.id}
	// Signed by the destination's key, but sent by the source.
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: d.DeliveryID, ManifestStatement: manifestFor(t, d, testSealed, b.signer)})
	got := h.waitDelivery(t, run.ID, "failed")
	if got.ErrorCode == nil || *got.ErrorCode != codeInvalidManifest {
		t.Fatalf("delivery %+v", got)
	}
}

func TestAReceiptForAnotherFileFailsTheDelivery(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	send := claim(t, a)
	d := seal.Delivery{DeliveryID: send.GetDeliveryId(), SourceAgent: a.id, DestinationAgent: b.id}
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: d.DeliveryID, ManifestStatement: manifestFor(t, d, testSealed, a.signer)})
	receive := claim(t, b)
	other := testSealed
	other.SHA256[0] ^= 1
	update(t, b, &agentv1.DeliveryUpdate{WorkId: receive.GetWorkId(), DeliveryId: d.DeliveryID, ReceiptStatement: receiptFor(t, d, other, b.signer)})
	got := h.waitDelivery(t, run.ID, "failed")
	if got.ErrorCode == nil || *got.ErrorCode != codeInvalidReceipt || got.Evidence != "source_only" {
		t.Fatalf("delivery %+v", got)
	}
	if h.run(t, run.ID).Status != "failed" {
		t.Fatal("the run did not fail")
	}
}

func TestAnAgentCanFailItsDelivery(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRun(t, runBody(a, b))
	send := claim(t, a)
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: send.GetDeliveryId(), State: agentv1.DeliveryState_DELIVERY_STATE_FAILED, ErrorCode: "source_missing"})
	if got := h.waitDelivery(t, run.ID, "failed"); got.ErrorCode == nil || *got.ErrorCode != "source_missing" {
		t.Fatalf("delivery %+v", got)
	}
	// A malformed code is replaced, never stored.
	_, run = h.startRun(t, runBody(a, b))
	send = claim(t, a)
	update(t, a, &agentv1.DeliveryUpdate{WorkId: send.GetWorkId(), DeliveryId: send.GetDeliveryId(), ErrorCode: "No such file: /home/sam/secret.txt"})
	if got := h.waitDelivery(t, run.ID, "failed"); got.ErrorCode == nil || *got.ErrorCode != codeAgentFailed {
		t.Fatalf("delivery %+v", got)
	}
}

func TestRunOutcome(t *testing.T) {
	for _, tc := range []struct {
		succeeded, total int
		want             string
	}{
		{1, 1, "succeeded"}, {3, 3, "succeeded"}, {1, 3, "partial_failure"}, {2, 3, "partial_failure"},
		{0, 1, "failed"}, {0, 3, "failed"}, {0, 0, "failed"},
	} {
		if got := runOutcome(tc.succeeded, tc.total); got != tc.want {
			t.Errorf("%d of %d succeeded: %s, want %s", tc.succeeded, tc.total, got, tc.want)
		}
	}
}

// runOf inserts a running run with n claimed deliveries from a to b.
func (h harness) runOf(t *testing.T, a, b string, n int) (string, []string) {
	t.Helper()
	ctx := t.Context()
	var runID string
	if err := h.db.QueryRow(ctx, `INSERT INTO runs (workspace_id, status)
		SELECT workspace_id, 'pending' FROM agents WHERE id = $1 RETURNING id`, a).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(ctx, `UPDATE runs SET status = 'running' WHERE id = $1`, runID); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, n)
	for i := range ids {
		if err := h.db.QueryRow(ctx, `INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, status)
			VALUES ($1, $2, $3, 'pending') RETURNING id`, runID, a, b).Scan(&ids[i]); err != nil {
			t.Fatal(err)
		}
		if _, err := h.db.Exec(ctx, `UPDATE deliveries SET status = 'claimed' WHERE id = $1`, ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	return runID, ids
}

// succeed walks a claimed delivery to succeeded, with stand-in statements.
func (h harness) succeed(t *testing.T, id string) {
	t.Helper()
	ctx := t.Context()
	sum := sha256.Sum256([]byte(id))
	if _, err := h.db.Exec(ctx, `INSERT INTO signed_statements (id, payload_type, envelope) VALUES ($1, 't', '\x00')`, sum[:]); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE deliveries SET status = 'transferring', evidence = 'source_only', manifest_statement_id = $2, sealed_sha256 = $2 WHERE id = $1`,
		`UPDATE deliveries SET status = 'verifying' WHERE id = $1 AND $2::bytea IS NOT NULL`,
		`UPDATE deliveries SET status = 'succeeded', evidence = 'verified', receipt_statement_id = $2 WHERE id = $1`,
	} {
		if _, err := h.db.Exec(ctx, sql, id, sum[:]); err != nil {
			t.Fatal(err)
		}
	}
	if err := pgx.BeginFunc(ctx, h.db, func(tx pgx.Tx) error {
		var runID string
		if err := tx.QueryRow(ctx, `SELECT run_id FROM deliveries WHERE id = $1`, id).Scan(&runID); err != nil {
			return err
		}
		return finishRun(ctx, tx, runID)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestARunEndsOnceEveryDeliveryHas(t *testing.T) {
	h, a, b := pair(t)
	for _, tc := range []struct {
		succeed int
		want    string
	}{{2, "succeeded"}, {1, "partial_failure"}, {0, "failed"}} {
		runID, ids := h.runOf(t, a.id, b.id, 2)
		for i, id := range ids {
			if i < tc.succeed {
				h.succeed(t, id)
			} else {
				h.srv.endDelivery(t.Context(), id, "relay_failed", "")
			}
			if status := h.run(t, runID).Status; i == 0 && status != "running" {
				t.Fatalf("the run ended at %s with a delivery active", status)
			}
		}
		if got := h.run(t, runID).Status; got != tc.want {
			t.Errorf("%d of 2 succeeded: %s, want %s", tc.succeed, got, tc.want)
		}
	}
}

func TestDeliveriesEndingTogetherEndTheirRun(t *testing.T) {
	h, a, b := pair(t)
	for range 10 {
		runID, ids := h.runOf(t, a.id, b.id, 4)
		var wg sync.WaitGroup
		for _, id := range ids {
			wg.Go(func() { h.srv.endDelivery(context.Background(), id, "relay_failed", "") })
		}
		wg.Wait()
		if got := h.run(t, runID).Status; got != "failed" {
			t.Fatalf("the run is %s", got)
		}
	}
}
