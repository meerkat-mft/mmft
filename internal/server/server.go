// Package server runs the orchestrator's gRPC service for agents and its REST API.
// Enrollment is the only call allowed without a connection certificate.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/version"
)

const (
	enrollmentMethods = "/" + "mmft.agent.v1.EnrollmentService/"
	maxMessageBytes   = 8 << 20
	shutdownTimeout   = 10 * time.Second
)

// limits bound what one network peer can hold open. Enrollment needs no
// certificate, so anything on the network can open connections and streams;
// without these bounds a peer could pin goroutines and descriptors for ever.
type limits struct {
	// maxConnections caps accepted connections per listener.
	maxConnections int
	// maxStreams caps concurrent gRPC streams per connection.
	maxStreams uint32
	// connectionIdle closes a gRPC connection with no open stream after this long.
	connectionIdle time.Duration
	// connectionAge tells a gRPC peer to reconnect after this long, and
	// connectionAgeGrace then closes the connection even if a stream is still
	// open. Idle expiry never fires while a stream is open, so without this a
	// peer could hold a stream that never sends its request for ever.
	connectionAge, connectionAgeGrace time.Duration
	// readTimeout, writeTimeout, and idleTimeout bound one REST request, one
	// response, and the keep-alive wait between requests.
	readTimeout, writeTimeout, idleTimeout time.Duration
}

var defaultLimits = limits{
	maxConnections: 1024,
	maxStreams:     32,
	connectionIdle: 5 * time.Minute,
	// Agents only make short unary calls today. A future long-lived stream
	// reconnects once an hour, which gRPC clients do on their own.
	connectionAge:      time.Hour,
	connectionAgeGrace: 5 * time.Minute,
	readTimeout:        30 * time.Second,
	writeTimeout:       30 * time.Second,
	idleTimeout:        60 * time.Second,
}

// Config configures a server.
type Config struct {
	Authority *connca.Authority
	DB        *pgxpool.Pool
	// Names are the DNS names on the server certificate.
	Names []string
	// AdminTokenSHA256 is the hex hash of the bootstrap token from ADR 0017.
	AdminTokenSHA256 string
	Now              func() time.Time
}

// Server holds the gRPC and REST handlers.
type Server struct {
	cfg    Config
	limits limits
	mu     sync.Mutex
	cert   *tls.Certificate
	token  []byte
	grpc   *grpc.Server
}

// New validates a configuration and builds a server.
func New(cfg Config) (*Server, error) {
	if cfg.Authority == nil || cfg.DB == nil || len(cfg.Names) == 0 {
		return nil, errors.New("server: a CA, a database, and server names are required")
	}
	token, err := hex.DecodeString(cfg.AdminTokenSHA256)
	if err != nil || len(token) != sha256.Size {
		return nil, errors.New("server: the admin token hash must be 64 hex characters")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg, limits: defaultLimits, token: token}
	s.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(s.tlsConfig())),
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.MaxConcurrentStreams(s.limits.maxStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     s.limits.connectionIdle,
			MaxConnectionAge:      s.limits.connectionAge,
			MaxConnectionAgeGrace: s.limits.connectionAgeGrace,
		}),
		grpc.UnaryInterceptor(s.unaryAuth),
		grpc.StreamInterceptor(s.streamAuth),
	)
	agentv1.RegisterEnrollmentServiceServer(s.grpc, enrollment{s: s})
	agentv1.RegisterAgentServiceServer(s.grpc, agentService{s: s})
	return s, nil
}

// tlsConfig allows connections without a client certificate, because enrollment
// has none yet. Any certificate presented must verify, and the interceptors
// require one for everything except enrollment.
func (s *Server) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      s.cfg.Authority.Pool(),
		GetCertificate: s.certificate,
	}
}

// certificate returns the server certificate, replacing it at half its lifetime.
func (s *Server) certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if s.cert != nil && now.Before(s.cert.Leaf.NotAfter.Add(-connca.ServerLifetime/2)) {
		return s.cert, nil
	}
	cert, err := s.cfg.Authority.ServerCertificate(s.cfg.Names, now)
	if err != nil {
		return nil, err
	}
	s.cert = cert
	return cert, nil
}

// requireAgent admits enrollment calls, and otherwise requires a connection
// certificate for an agent that exists and isn't revoked. A certificate stays
// valid for up to a day, so revoking an agent must not wait for it to expire.
func (s *Server) requireAgent(ctx context.Context, method string) error {
	if strings.HasPrefix(method, enrollmentMethods) {
		return nil
	}
	id, err := AgentFromContext(ctx)
	if err != nil {
		return err
	}
	var agentStatus string
	err = s.cfg.DB.QueryRow(ctx, `SELECT status FROM agents WHERE id = $1`, id).Scan(&agentStatus)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return status.Error(codes.Unauthenticated, "the certificate names an unknown agent")
	case err != nil:
		return status.Error(codes.Unavailable, "could not check the agent")
	case agentStatus == "revoked":
		return status.Error(codes.PermissionDenied, "the agent is revoked")
	}
	return nil
}

// AgentFromContext returns the agent ID proven by the connection certificate.
func AgentFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no connection information")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 {
		return "", status.Error(codes.Unauthenticated, "a connection certificate is required")
	}
	id, err := connca.AgentID(info.State.VerifiedChains[0][0])
	if err != nil {
		return "", status.Error(codes.Unauthenticated, "the certificate does not identify an agent")
	}
	return id, nil
}

func (s *Server) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := s.requireAgent(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (s *Server) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.requireAgent(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}

// API returns the REST handler.
func (s *Server) API() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version.Version})
	})
	mux.Handle("POST /api/v1/agents/enrollment-tokens", s.requireAdmin(http.HandlerFunc(s.createToken)))
	mux.Handle("GET /api/v1/agents", s.requireAdmin(http.HandlerFunc(s.listAgents)))
	mux.Handle("PUT /api/v1/agents/{agent_id}/identity", s.requireAdmin(http.HandlerFunc(s.putIdentity)))
	mux.Handle("GET /api/v1/agents/{agent_id}", s.requireAdmin(http.HandlerFunc(s.getAgent)))
	// Anything else is a problem document too, never a plain-text page.
	mux.Handle("/api/v1/", s.requireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		problem(w, http.StatusNotFound, "No such resource.")
	})))
	return mux
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(token))
		if !ok || subtle.ConstantTimeCompare(sum[:], s.token) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			problem(w, http.StatusUnauthorized, "A valid token is required.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, code int, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": title, "status": code})
}

// Serve runs both listeners until ctx ends.
func (s *Server) Serve(ctx context.Context, grpcListener, apiListener net.Listener) error {
	grpcListener = netutil.LimitListener(grpcListener, s.limits.maxConnections)
	apiListener = netutil.LimitListener(apiListener, s.limits.maxConnections)
	api := &http.Server{
		Handler:           s.API(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: s.certificate},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       s.limits.readTimeout,
		WriteTimeout:      s.limits.writeTimeout,
		IdleTimeout:       s.limits.idleTimeout,
	}
	errs := make(chan error, 2)
	go func() { errs <- s.grpc.Serve(grpcListener) }()
	go func() { errs <- api.ServeTLS(apiListener, "", "") }()

	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	s.grpc.GracefulStop()
	return errors.Join(err, api.Shutdown(stop))
}
