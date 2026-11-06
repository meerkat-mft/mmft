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
}

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
}

// Run keeps the agent connected to the orchestrator until ctx ends. It
// reconnects with backoff when the stream drops, and renews the connection
// certificate once it is past half its lifetime. It returns
// ErrCertificateExpired if the certificate expires, because only a new token
// can fix that, and ErrDamaged or ErrNotEnrolled if the agent can't start.
func Run(ctx context.Context, dir string, cfg RunConfig) error {
	cfg.defaults()
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
	r := &runner{dir: dir, cfg: cfg, s: s, keys: keys, host: host, ca: ca}
	backoff := cfg.MinBackoff
	for {
		cert, err := r.certificate()
		if err != nil {
			r.log("stopped", err)
			return err
		}
		welcomed, sessionErr := r.session(ctx, cert)
		select {
		case <-ctx.Done():
			// Stopping is a normal end, whatever the stream reported.
			return nil
		default:
		}
		if welcomed {
			backoff = cfg.MinBackoff
		}
		r.log("disconnected", sessionErr)
		// Wait between half and all of the backoff, so agents that lost the
		// orchestrator together don't all return at once.
		wait := backoff/2 + mrand.N(backoff/2+1) //nolint:gosec // jitter, not a secret
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		backoff = min(2*backoff, cfg.MaxBackoff)
	}
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
func (r *runner) session(ctx context.Context, cert *x509.Certificate) (welcomed bool, err error) {
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
		return false, streamError(stream, err)
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

	// Nothing else comes from the orchestrator in M1, so the stream is read
	// only to notice that it ended.
	ended := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				ended <- err
				return
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

// streamError returns the real reason a send failed. A failed send reports
// only io.EOF, and the status comes from the next receive.
func streamError(stream agentv1.AgentService_ConnectClient, err error) error {
	if errors.Is(err, io.EOF) {
		if _, rerr := stream.Recv(); rerr != nil {
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
