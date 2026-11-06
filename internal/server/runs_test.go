package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"testing"
	"time"

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

// startRunWhenConnected starts a run, retrying while the orchestrator hasn't
// registered both streams yet, which happens just after it sends the welcome.
func (h harness) startRunWhenConnected(t *testing.T, body map[string]string) (int, runItem) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, run := h.startRun(t, body)
		if code != http.StatusConflict || time.Now().After(deadline) {
			return code, run
		}
		time.Sleep(10 * time.Millisecond)
	}
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

func assignment(t *testing.T, a *runAgentFor) *agentv1.ManualDelivery {
	t.Helper()
	for {
		resp, err := a.stream.Recv()
		if err != nil {
			t.Fatalf("waiting for an assignment: %v", err)
		}
		if d := resp.GetManualDelivery(); d != nil {
			return d
		}
	}
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

func TestManualRunCompletesWithBothStatements(t *testing.T) {
	h, a, b := pair(t)
	code, run := h.startRunWhenConnected(t, runBody(a, b))
	if code != http.StatusAccepted || run.FlowID != nil || run.Status != "running" || len(run.Deliveries) != 1 {
		t.Fatalf("start: %d %+v", code, run)
	}

	send := assignment(t, a)
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

	d := seal.Delivery{DeliveryID: send.GetDeliveryId(), SourceAgent: a.id, DestinationAgent: b.id}
	manifest := manifestFor(t, d, testSealed, a.signer)
	update(t, a, &agentv1.DeliveryUpdate{DeliveryId: d.DeliveryID, State: agentv1.DeliveryState_DELIVERY_STATE_TRANSFERRING, ManifestStatement: manifest})
	got := h.waitDelivery(t, run.ID, "transferring")
	if got.Evidence != "source_only" || got.SizeBytes == nil || *got.SizeBytes != testSealed.Size {
		t.Fatalf("after the manifest: %+v", got)
	}

	receive := assignment(t, b)
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

	receipt := receiptFor(t, d, testSealed, b.signer)
	update(t, b, &agentv1.DeliveryUpdate{DeliveryId: d.DeliveryID, State: agentv1.DeliveryState_DELIVERY_STATE_SUCCEEDED, ReceiptStatement: receipt})
	got = h.waitDelivery(t, run.ID, "succeeded")
	if got.Evidence != "verified" || got.FileName == nil || *got.FileName != "report.csv" {
		t.Fatalf("after the receipt: %+v", got)
	}
	if h.run(t, run.ID).Status != "succeeded" {
		t.Fatal("the run did not succeed")
	}
}

func TestManualRunNeedsTwoApprovedConnectedAgents(t *testing.T) {
	h := startWithRelay(t)
	ap := newApprover(t)
	a := h.approvedAgent(t, ap, "lab", "agent-a")
	b := h.approvedAgent(t, ap, "lab", "agent-b")
	pending := h.approvedAgent(t, approver{}, "lab", "agent-p")
	other := h.approvedAgent(t, ap, "other", "agent-o")
	h.connect(t, a)
	h.connect(t, pending)
	h.connect(t, other)
	time.Sleep(100 * time.Millisecond)

	cases := map[string]struct {
		body map[string]string
		code int
	}{
		"destination offline": {runBody(a, b), http.StatusConflict},
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
	h.connect(t, a)
	h.connect(t, b)
	if code, _ := h.startRun(t, runBody(a, b)); code != http.StatusConflict {
		t.Fatalf("got %d, want 409", code)
	}
}

func TestStatementsFromTheWrongSideAreIgnored(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRunWhenConnected(t, runBody(a, b))
	id := assignment(t, a).GetDeliveryId()
	d := seal.Delivery{DeliveryID: id, SourceAgent: a.id, DestinationAgent: b.id}

	// The destination can't send the manifest, nor the source the receipt.
	update(t, b, &agentv1.DeliveryUpdate{DeliveryId: id, ManifestStatement: manifestFor(t, d, testSealed, b.signer)})
	update(t, a, &agentv1.DeliveryUpdate{DeliveryId: id, ReceiptStatement: receiptFor(t, d, testSealed, a.signer)})
	// A third agent can't fail it.
	ap := newApprover(t)
	c := h.approvedAgent(t, ap, "lab", "agent-c")
	h.connect(t, c)
	update(t, c, &agentv1.DeliveryUpdate{DeliveryId: id, State: agentv1.DeliveryState_DELIVERY_STATE_FAILED, ErrorCode: "spool_full"})
	time.Sleep(200 * time.Millisecond)
	if got := h.run(t, run.ID).Deliveries[0]; got.Status != "pending" || got.Evidence != "none" {
		t.Fatalf("delivery changed: %+v", got)
	}
}

func TestABadManifestFailsTheDelivery(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRunWhenConnected(t, runBody(a, b))
	id := assignment(t, a).GetDeliveryId()
	d := seal.Delivery{DeliveryID: id, SourceAgent: a.id, DestinationAgent: b.id}
	// Signed by the destination's key, but sent by the source.
	update(t, a, &agentv1.DeliveryUpdate{DeliveryId: id, ManifestStatement: manifestFor(t, d, testSealed, b.signer)})
	got := h.waitDelivery(t, run.ID, "failed")
	if got.ErrorCode == nil || *got.ErrorCode != codeInvalidManifest {
		t.Fatalf("delivery %+v", got)
	}
}

func TestAReceiptForAnotherFileFailsTheDelivery(t *testing.T) {
	h, a, b := pair(t)
	_, run := h.startRunWhenConnected(t, runBody(a, b))
	id := assignment(t, a).GetDeliveryId()
	d := seal.Delivery{DeliveryID: id, SourceAgent: a.id, DestinationAgent: b.id}
	update(t, a, &agentv1.DeliveryUpdate{DeliveryId: id, ManifestStatement: manifestFor(t, d, testSealed, a.signer)})
	_ = assignment(t, b)
	other := testSealed
	other.SHA256[0] ^= 1
	update(t, b, &agentv1.DeliveryUpdate{DeliveryId: id, ReceiptStatement: receiptFor(t, d, other, b.signer)})
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
	_, run := h.startRunWhenConnected(t, runBody(a, b))
	id := assignment(t, a).GetDeliveryId()
	update(t, a, &agentv1.DeliveryUpdate{DeliveryId: id, State: agentv1.DeliveryState_DELIVERY_STATE_FAILED, ErrorCode: "source_missing"})
	if got := h.waitDelivery(t, run.ID, "failed"); got.ErrorCode == nil || *got.ErrorCode != "source_missing" {
		t.Fatalf("delivery %+v", got)
	}
	// A malformed code is replaced, never stored.
	_, run = h.startRunWhenConnected(t, runBody(a, b))
	id = assignment(t, a).GetDeliveryId()
	update(t, a, &agentv1.DeliveryUpdate{DeliveryId: id, ErrorCode: "No such file: /home/sam/secret.txt"})
	if got := h.waitDelivery(t, run.ID, "failed"); got.ErrorCode == nil || *got.ErrorCode != codeAgentFailed {
		t.Fatalf("delivery %+v", got)
	}
}

func TestALostAssignmentFailsTheDelivery(t *testing.T) {
	h, a, b := pair(t)
	var runID, deliveryID string
	ctx := t.Context()
	if err := h.db.QueryRow(ctx, `INSERT INTO runs (workspace_id, status)
		SELECT workspace_id, 'running' FROM agents WHERE id = $1 RETURNING id`, a.id).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(ctx, `INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, status)
		VALUES ($1, $2, $3, 'pending') RETURNING id`, runID, a.id, b.id).Scan(&deliveryID); err != nil {
		t.Fatal(err)
	}
	// A stream whose writer never sends: its queue still holds the assignment
	// when the stream ends.
	const ghost = "0190a0b0-0000-7000-8000-00000000000f"
	_, unregister := h.srv.register(ghost)
	if !h.srv.push(ghost, manualDelivery(&agentv1.ManualDelivery{DeliveryId: deliveryID})) {
		t.Fatal("push failed")
	}
	unregister()
	got := h.waitDelivery(t, runID, "failed")
	if got.ErrorCode == nil || *got.ErrorCode != codeDispatchFailed || h.run(t, runID).Status != "failed" {
		t.Fatalf("delivery %+v", got)
	}
}
