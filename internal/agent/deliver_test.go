package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/relay"
	"mmft.dev/mmft/internal/seal"
	"mmft.dev/mmft/internal/server"
	"mmft.dev/mmft/internal/server/servertest"
)

// deliveryLab is an orchestrator with a relay, and two approved agents, each
// with an outbox, inbox, and spool.
type deliveryLab struct {
	o      servertest.Orchestrator
	ap     servertest.Approver
	agents map[string]*labAgent
}

type labAgent struct {
	name, dir, id        string
	outbox, inbox, spool string
	identity             []byte
	state                State
}

func startDeliveryLab(t *testing.T) *deliveryLab {
	t.Helper()
	// The relay's address and identity must exist before the orchestrator,
	// which hands them out, and the relay needs the orchestrator's CA.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayDir := filepath.Join(t.TempDir(), "relay")
	fp, err := relay.CreateIdentity(relayDir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := relay.LoadIdentity(relayDir)
	if err != nil {
		t.Fatal(err)
	}
	_, ticketKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	o := servertest.StartWith(t, func(c *server.Config) {
		c.RelayAddress, c.RelayCertificateSHA256, c.TicketKey = lis.Addr().String(), fp, ticketKey
	})
	block, _ := pem.Decode(o.CA.CertificatePEM())
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	s, err := relay.New(relay.Config{Identity: identity, ConnectionCA: caCert, TicketKey: ticketKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("relay: %v", err)
		}
	})
	l := &deliveryLab{o: o, ap: servertest.NewApprover(t), agents: map[string]*labAgent{}}
	for _, name := range []string{"agent-a", "agent-b"} {
		l.agents[name] = l.approve(t, name)
	}
	return l
}

func (l *deliveryLab) approve(t *testing.T, name string) *labAgent {
	t.Helper()
	a := &labAgent{name: name, dir: agentDir(t), outbox: t.TempDir(), inbox: t.TempDir(), spool: t.TempDir()}
	in := install(l.o, l.o.Token(t, "lab", name), name)
	in.RootFingerprint = l.ap.RootFingerprint()
	s, err := enroll(t, a.dir, in)
	if err != nil {
		t.Fatal(err)
	}
	a.id, a.state = s.AgentID, s
	a.identity = l.ap.Sign(t, s.AgentID, "lab", name, s.Keys())
	if code := l.o.PutIdentity(t, s.AgentID, a.identity); code != http.StatusNoContent {
		t.Fatalf("approve %s: %d", name, code)
	}
	return a
}

// run runs an agent with its delivery directories until the test ends.
func (a *labAgent) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, a.dir, RunConfig{
			Heartbeat: 50 * time.Millisecond, MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
			Outbox: a.outbox, Inbox: a.inbox, Spool: a.spool,
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("%s: %v", a.name, err)
		}
	})
}

// deliver starts a manual run once both agents are connected, and waits for it
// to end. It returns the run's only delivery.
func (l *deliveryLab) deliver(t *testing.T, name string) map[string]any {
	t.Helper()
	body := map[string]string{"source_agent_id": l.agents["agent-a"].id, "destination_agent_id": l.agents["agent-b"].id, "file_name": name}
	deadline := time.Now().Add(10 * time.Second)
	var code int
	var run map[string]any
	for {
		code, run = l.o.Call(t, http.MethodPost, "/api/v1/runs", body)
		if code != http.StatusConflict || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code != http.StatusAccepted {
		t.Fatalf("start run: %d %v", code, run)
	}
	id, _ := run["id"].(string)
	for {
		_, run = l.o.Call(t, http.MethodGet, "/api/v1/runs/"+id, nil)
		if s := run["status"]; s == "succeeded" || s == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the run did not end: %v", run)
		}
		time.Sleep(20 * time.Millisecond)
	}
	deliveries, _ := run["deliveries"].([]any)
	if len(deliveries) != 1 {
		t.Fatalf("run %v", run)
	}
	d, _ := deliveries[0].(map[string]any)
	d["run_status"] = run["status"]
	return d
}

func empty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s holds %d entries", dir, len(entries))
	}
}

func TestManualDeliveryMovesTheFile(t *testing.T) {
	l := startDeliveryLab(t)
	a, b := l.agents["agent-a"], l.agents["agent-b"]
	data := make([]byte, 700<<10)
	_, _ = rand.Read(data)
	if err := os.WriteFile(filepath.Join(a.outbox, "report.csv"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	a.run(t)
	b.run(t)

	d := l.deliver(t, "report.csv")
	if d["status"] != "succeeded" || d["evidence"] != "verified" || d["run_status"] != "succeeded" || d["file_name"] != "report.csv" {
		t.Fatalf("delivery %v", d)
	}
	got, err := os.ReadFile(filepath.Join(b.inbox, "report.csv"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the inbox file differs: %v", err)
	}
	// Only the placed file is left: no temporary file in the inbox, and
	// nothing in either spool.
	entries, _ := os.ReadDir(b.inbox)
	if len(entries) != 1 {
		t.Fatalf("the inbox holds %d entries", len(entries))
	}
	empty(t, a.spool)
	empty(t, b.spool)
}

func TestManualDeliveryNeverReplacesAFile(t *testing.T) {
	l := startDeliveryLab(t)
	a, b := l.agents["agent-a"], l.agents["agent-b"]
	if err := os.WriteFile(filepath.Join(a.outbox, "x.txt"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.inbox, "x.txt"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.run(t)
	b.run(t)
	d := l.deliver(t, "x.txt")
	if d["status"] != "failed" || d["error_code"] != codeDestinationExists {
		t.Fatalf("delivery %v", d)
	}
	if got, _ := os.ReadFile(filepath.Join(b.inbox, "x.txt")); string(got) != "existing" {
		t.Fatalf("the existing file changed to %q", got)
	}
}

func TestManualDeliveryReportsAMissingSource(t *testing.T) {
	l := startDeliveryLab(t)
	l.agents["agent-a"].run(t)
	l.agents["agent-b"].run(t)
	if d := l.deliver(t, "missing.txt"); d["status"] != "failed" || d["error_code"] != codeSourceMissing {
		t.Fatalf("delivery %v", d)
	}
}

// side builds a runner for one lab agent without running it, so one side of a
// delivery can be driven directly.
func (a *labAgent) side(t *testing.T) *runner {
	t.Helper()
	keys, err := LoadKeys(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := RunConfig{Outbox: a.outbox, Inbox: a.inbox, Spool: a.spool}
	cfg.defaults()
	return &runner{dir: a.dir, cfg: cfg, s: a.state, keys: keys, updates: make(chan *agentv1.ConnectRequest, updateBuffer)}
}

// quick bounds a side driven directly. Every refusal happens before the relay,
// so a skipped check shows up as relay_failed here rather than a hang.
func quick(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var de *deliveryError
	if !errors.As(err, &de) || de.code != code {
		t.Fatalf("got %v, want code %s", err, code)
	}
}

const testDelivery = "0190a0b0-0000-7000-8000-0000000000d1"

func TestTheSourceChecksTheDestinationsIdentity(t *testing.T) {
	l := startDeliveryLab(t)
	a, b := l.agents["agent-a"], l.agents["agent-b"]
	if err := os.WriteFile(filepath.Join(a.outbox, "f"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := a.side(t)
	ok := &agentv1.ManualDelivery{DeliveryId: testDelivery, Role: agentv1.DeliveryRole_DELIVERY_ROLE_SEND, FileName: "f", PeerAgentId: b.id, PeerIdentityStatement: b.identity}

	other := servertest.NewApprover(t)
	cases := map[string]func(*agentv1.ManualDelivery){
		// A compromised orchestrator could sign an identity with its own root.
		"another root": func(d *agentv1.ManualDelivery) {
			d.PeerIdentityStatement = other.Sign(t, b.id, "lab", "agent-b", b.state.Keys())
		},
		"another agent's identity": func(d *agentv1.ManualDelivery) { d.PeerAgentId = a.id; d.PeerIdentityStatement = a.identity },
		"another named agent":      func(d *agentv1.ManualDelivery) { d.PeerAgentId = "0190a0b0-0000-7000-8000-000000000009" },
		"another workspace": func(d *agentv1.ManualDelivery) {
			d.PeerIdentityStatement = l.ap.Sign(t, b.id, "other", "agent-b", b.state.Keys())
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := clone(ok)
			change(d)
			wantCode(t, r.sendSide(quick(t), d), codePeerInvalid)
			empty(t, a.spool)
		})
	}
}

func clone(d *agentv1.ManualDelivery) *agentv1.ManualDelivery {
	return proto.Clone(d).(*agentv1.ManualDelivery)
}

func TestTheSourceRefusesWhatItMayNotRead(t *testing.T) {
	l := startDeliveryLab(t)
	a, b := l.agents["agent-a"], l.agents["agent-b"]
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("outside the outbox"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(a.outbox, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(a.outbox, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := a.side(t)
	d := func(name string) *agentv1.ManualDelivery {
		return &agentv1.ManualDelivery{DeliveryId: testDelivery, Role: agentv1.DeliveryRole_DELIVERY_ROLE_SEND, FileName: name, PeerAgentId: b.id, PeerIdentityStatement: b.identity}
	}
	wantCode(t, r.sendSide(quick(t), d("link")), codeSourceNotRegular)
	wantCode(t, r.sendSide(quick(t), d("dir")), codeSourceNotRegular)
	wantCode(t, r.sendSide(quick(t), d("../secret")), codeInvalidFileName)
	wantCode(t, r.sendSide(quick(t), d(secret)), codeInvalidFileName)
	empty(t, a.spool)

	r.cfg.Outbox = ""
	wantCode(t, r.sendSide(quick(t), d("link")), codeNotConfigured)
}

func TestTheDestinationChecksTheManifest(t *testing.T) {
	l := startDeliveryLab(t)
	a, b := l.agents["agent-a"], l.agents["agent-b"]
	sealed := seal.Sealed{Size: 100, SHA256: [32]byte{1}}
	delivery := seal.Delivery{DeliveryID: testDelivery, SourceAgent: a.id, DestinationAgent: b.id}
	sign := func(dir string, d seal.Delivery) []byte {
		keys, err := LoadKeys(dir)
		if err != nil {
			t.Fatal(err)
		}
		e, err := seal.SignManifest(d, sealed, keys.Signer)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(e)
		return raw
	}
	r := b.side(t)
	d := func(manifest []byte) *agentv1.ManualDelivery {
		return &agentv1.ManualDelivery{DeliveryId: testDelivery, Role: agentv1.DeliveryRole_DELIVERY_ROLE_RECEIVE, FileName: "f",
			PeerAgentId: a.id, PeerIdentityStatement: a.identity, ManifestStatement: manifest}
	}
	// Signed by the destination itself, not the source.
	_, err := r.receiveSide(quick(t), d(sign(b.dir, delivery)))
	wantCode(t, err, codeManifestInvalid)
	// For another delivery.
	otherDelivery := delivery
	otherDelivery.DeliveryID = "0190a0b0-0000-7000-8000-0000000000d2"
	_, err = r.receiveSide(quick(t), d(sign(a.dir, otherDelivery)))
	wantCode(t, err, codeManifestInvalid)
	_, err = r.receiveSide(quick(t), d([]byte("not a manifest")))
	wantCode(t, err, codeManifestInvalid)
	empty(t, b.spool)
	empty(t, b.inbox)
}

func TestRunNeedsUsableDeliveryDirectories(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]RunConfig{
		"outbox without spool": {Outbox: dir},
		"inbox without spool":  {Inbox: dir},
		"missing inbox":        {Inbox: filepath.Join(dir, "missing"), Spool: dir},
		"file as spool":        {Outbox: dir, Spool: file},
	} {
		if err := cfg.checkDirs(); !errors.Is(err, ErrDeliveryDirs) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if err := (&RunConfig{Outbox: dir, Inbox: dir, Spool: dir}).checkDirs(); err != nil {
		t.Fatal(err)
	}
	if err := (&RunConfig{}).checkDirs(); err != nil {
		t.Fatal(err)
	}
}

func TestPlaceNeverReplacesAFile(t *testing.T) {
	dir := t.TempDir()
	opened := filepath.Join(dir, ".opened")
	write := func(path, data string) {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(opened, "new")
	existing := filepath.Join(dir, "existing")
	write(existing, "old")
	wantCode(t, place(opened, existing), codeDestinationExists)
	if got, _ := os.ReadFile(existing); string(got) != "old" {
		t.Fatalf("the existing file changed to %q", got)
	}
	// A link planted under the name is never followed or replaced.
	target := filepath.Join(t.TempDir(), "target")
	write(target, "elsewhere")
	planted := filepath.Join(dir, "planted")
	if err := os.Symlink(target, planted); err != nil {
		t.Fatal(err)
	}
	wantCode(t, place(opened, planted), codeDestinationExists)
	if got, _ := os.ReadFile(target); string(got) != "elsewhere" {
		t.Fatalf("the link's target changed to %q", got)
	}
	fresh := filepath.Join(dir, "fresh")
	if err := place(opened, fresh); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(fresh); string(got) != "new" {
		t.Fatalf("placed %q", got)
	}
}
