package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/version"
)

// ProtocolVersion is the agent protocol version this agent speaks.
const ProtocolVersion = 1

// RunConfig sets how an agent keeps its connection. Zero values get defaults.
type RunConfig struct {
	// Heartbeat is how often the agent reports in. The orchestrator closes a
	// stream that is silent for 90 seconds.
	Heartbeat time.Duration
	// MinBackoff and MaxBackoff bound the wait before reconnecting.
	MinBackoff, MaxBackoff time.Duration
	// Log receives one JSON object per line for each connection event.
	Log io.Writer
	Now func() time.Time
	// Outbox and Inbox are the only directories manual deliveries read from
	// and write to, set on this host. With neither, the agent takes no
	// deliveries. Spool holds sealed files in flight and is required with
	// either. See ADR 0021.
	Outbox, Inbox, Spool string
}

// updateBuffer is how many delivery updates can wait for a stream.
const updateBuffer = 64

const (
	defaultHeartbeat  = 30 * time.Second
	defaultMinBackoff = time.Second
	defaultMaxBackoff = time.Minute
	callTimeout       = 30 * time.Second
)

func (c *RunConfig) defaults() {
	if c.Heartbeat == 0 {
		c.Heartbeat = defaultHeartbeat
	}
	if c.MinBackoff == 0 {
		c.MinBackoff = defaultMinBackoff
	}
	if c.MaxBackoff == 0 {
		c.MaxBackoff = defaultMaxBackoff
	}
	if c.Log == nil {
		c.Log = io.Discard
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// runner holds what one Run needs between connections.
type runner struct {
	dir  string
	cfg  RunConfig
	s    State
	keys *Keys
	host string
	ca   *x509.Certificate
	mu   sync.Mutex
	// updates holds delivery updates until a stream can send them.
	updates chan *agentv1.ConnectRequest
}

// Run keeps the agent connected to the orchestrator until ctx ends. It
// reconnects with backoff when the stream drops, and renews the connection
// certificate once it is past half its lifetime. It returns
// ErrCertificateExpired if the certificate expires, because only a new token
// can fix that, and ErrDamaged or ErrNotEnrolled if the agent can't start.
func Run(ctx context.Context, dir string, cfg RunConfig) error {
	cfg.defaults()
	if err := cfg.checkDirs(); err != nil {
		return err
	}
	s, err := ReadState(dir)
	if err != nil {
		return err
	}
	keys, err := LoadKeys(dir)
	if err != nil {
		return err
	}
	host, err := checkSettings(s.Orchestrator, s.AgentName, s.CAFingerprint, s.RootFingerprint)
	if err != nil {
		return err
	}
	ca, err := readCertificate(filepath.Join(dir, CAFile))
	if errors.Is(err, fs.ErrNotExist) {
		return ErrMissingCA
	}
	if err != nil {
		return err
	}
	r := &runner{dir: dir, cfg: cfg, s: s, keys: keys, host: host, ca: ca, updates: make(chan *agentv1.ConnectRequest, updateBuffer)}
	backoff := newBackoff(cfg.MinBackoff, cfg.MaxBackoff)
	for {
		cert, err := r.certificate()
		if err != nil {
			r.log("stopped", err)
			return err
		}
		welcomed, sessionErr := r.session(ctx, ctx, cert)
		select {
		case <-ctx.Done():
			// Stopping is a normal end, whatever the stream reported.
			return nil
		default:
		}
		if welcomed {
			backoff.reset()
		}
		r.log("disconnected", sessionErr)
		if !backoff.wait(ctx) {
			return nil
		}
	}
}

// backoff is the wait before trying again. It doubles after each wait, up to a
// ceiling, until reset.
type backoff struct {
	min, max, step time.Duration
}

func newBackoff(minimum, maximum time.Duration) *backoff {
	return &backoff{min: minimum, max: maximum, step: minimum}
}

func (b *backoff) reset() { b.step = b.min }

// wait sleeps between half and all of the current step, so agents that lost
// the same server together don't all return at once. It reports false if ctx
// ended first.
func (b *backoff) wait(ctx context.Context) bool {
	d := b.step/2 + mrand.N(b.step/2+1) //nolint:gosec // jitter, not a secret
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
	}
	b.step = min(2*b.step, b.max)
	return true
}

// ErrDeliveryDirs is returned when the outbox, inbox, or spool is unusable.
var ErrDeliveryDirs = errors.New("agent: the outbox and inbox need a spool, and each must be an existing directory")

// checkDirs requires a spool with an outbox or inbox, and each set directory to
// exist.
func (c *RunConfig) checkDirs() error {
	if (c.Outbox != "" || c.Inbox != "") && c.Spool == "" {
		return ErrDeliveryDirs
	}
	for _, dir := range []string{c.Outbox, c.Inbox, c.Spool} {
		if dir == "" {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return ErrDeliveryDirs
		}
	}
	return nil
}

func (r *runner) log(event string, err error, fields ...any) {
	m := map[string]any{"time": r.cfg.Now().UTC().Format(time.RFC3339), "event": event}
	if err != nil {
		m["error"] = err.Error()
	}
	for i := 0; i+1 < len(fields); i += 2 {
		m[fields[i].(string)] = fields[i+1]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = json.NewEncoder(r.cfg.Log).Encode(m)
}

// certificate loads the saved connection certificate, checked as install
// checks it.
func (r *runner) certificate() (*x509.Certificate, error) {
	return loadCertificate(r.dir, r.s, r.keys, r.cfg.Now())
}

// session runs one stream until it fails or ctx ends. It reports whether the
// orchestrator welcomed the agent, so the caller can reset its backoff.
func (r *runner) session(runCtx, ctx context.Context, cert *x509.Certificate) (welcomed bool, err error) {
	tlsConfig := connca.PinnedClient(r.s.CAFingerprint, r.host, r.cfg.Now)
	tlsConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: r.keys.Connection}}
	conn, err := grpc.NewClient(r.s.Orchestrator, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := agentv1.NewAgentServiceClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		return false, err
	}
	if err := stream.Send(r.hello()); err != nil {
		return false, streamEnd(stream.Recv, err)
	}
	// A server that never answers must not hold the agent for ever.
	timer := time.AfterFunc(callTimeout, cancel)
	resp, err := stream.Recv()
	if !timer.Stop() {
		return false, errors.New("agent: the orchestrator did not answer the hello")
	}
	if err != nil {
		return false, err
	}
	welcome := resp.GetWelcome()
	if welcome == nil {
		return false, errors.New("agent: the orchestrator did not welcome the agent")
	}
	r.log("connected", nil, "orchestrator_version", welcome.GetOrchestratorVersion())

	// The reader starts each assigned delivery on its own, under the run's
	// context, so it carries on across reconnects.
	ended := make(chan error, 1)
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				ended <- err
				return
			}
			if d := resp.GetManualDelivery(); d != nil {
				go r.deliver(runCtx, d)
			}
		}
	}()
	ticker := time.NewTicker(r.cfg.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return true, nil
		case err := <-ended:
			return true, err
		case u := <-r.updates:
			if err := stream.Send(u); err != nil {
				// Keep the update for the next stream.
				select {
				case r.updates <- u:
				default:
				}
				if errors.Is(err, io.EOF) {
					return true, <-ended
				}
				return true, err
			}
		case <-ticker.C:
			if err := stream.Send(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}); err != nil {
				// A failed send reports only io.EOF. The reader goroutine
				// gets the real reason, and only it may receive.
				if errors.Is(err, io.EOF) {
					return true, <-ended
				}
				return true, err
			}
			if renewDue(cert, r.cfg.Now()) {
				renewed, err := r.renew(ctx, client, cert)
				if err != nil {
					// The current certificate still works, so try again at
					// the next heartbeat.
					r.log("renewal failed", err)
					continue
				}
				cert = renewed
				r.log("renewed", nil, "not_after", cert.NotAfter.UTC().Format(time.RFC3339))
			}
		}
	}
}

// streamEnd returns the real reason a send failed. A failed send reports only
// io.EOF, and the status comes from the next receive.
func streamEnd[T any](recv func() (T, error), err error) error {
	if errors.Is(err, io.EOF) {
		if _, rerr := recv(); rerr != nil {
			return rerr
		}
	}
	return err
}

func (r *runner) hello() *agentv1.ConnectRequest {
	h := &agentv1.Hello{ProtocolVersion: ProtocolVersion, AgentVersion: version.Version}
	// The saved identity was verified when it was fetched. A missing one
	// means the agent isn't approved yet.
	if identity, err := os.ReadFile(filepath.Join(r.dir, IdentityFile)); err == nil {
		h.IdentityStatement = identity
	}
	return &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Hello{Hello: h}}
}

// renewDue reports whether a certificate is past half its lifetime.
func renewDue(cert *x509.Certificate, now time.Time) bool {
	issued := connca.IssuedAt(cert)
	return !now.Before(issued.Add(cert.NotAfter.Sub(issued) / 2))
}

// renew asks for a new certificate for the same connection key, checks it as
// enrollment does, and saves it. Installs into the same directory wait while
// the file is replaced.
func (r *runner) renew(ctx context.Context, client agentv1.AgentServiceClient, current *x509.Certificate) (*x509.Certificate, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, r.keys.Connection)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := client.RenewCertificate(ctx, &agentv1.RenewCertificateRequest{CertificateRequest: csr})
	if err != nil {
		return nil, err
	}
	der := resp.GetConnectionCertificate()
	// Check the new certificate in full before it replaces one that works.
	if _, err := checkRenewed(der, current, r.ca, r.s.AgentID, r.keys.Connection, r.cfg.Now()); err != nil {
		return nil, err
	}
	unlock, err := lock(ctx, r.dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := replaceFile(filepath.Join(r.dir, CertFile), certPEM, 0o644); err != nil {
		return nil, saveFailed(err)
	}
	return r.certificate()
}

// checkRenewed requires a renewed certificate to pass every check the saved
// certificate gets, and to last longer than the current one.
func checkRenewed(der []byte, current, ca *x509.Certificate, agentID string, key ed25519.PrivateKey, now time.Time) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrBadCertificate
	}
	if err := checkConnection(cert, ca, agentID, key, now); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCertificate, err)
	}
	if !cert.NotAfter.After(current.NotAfter) {
		return nil, fmt.Errorf("%w: it ends no later than the current one", ErrBadCertificate)
	}
	return cert, nil
}
