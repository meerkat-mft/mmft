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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
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

// Config configures a server.
type Config struct {
	Authority *connca.Authority
	// Names are the DNS names on the server certificate.
	Names []string
	// AdminTokenSHA256 is the hex hash of the bootstrap token from ADR 0017.
	AdminTokenSHA256 string
	Now              func() time.Time
}

// Server holds the gRPC and REST handlers.
type Server struct {
	cfg   Config
	mu    sync.Mutex
	cert  *tls.Certificate
	token []byte
	grpc  *grpc.Server
}

// New validates a configuration and builds a server.
func New(cfg Config) (*Server, error) {
	if cfg.Authority == nil || len(cfg.Names) == 0 {
		return nil, errors.New("server: a CA and server names are required")
	}
	token, err := hex.DecodeString(cfg.AdminTokenSHA256)
	if err != nil || len(token) != sha256.Size {
		return nil, errors.New("server: the admin token hash must be 64 hex characters")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg, token: token}
	s.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(s.tlsConfig())),
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.UnaryInterceptor(unaryAuth),
		grpc.StreamInterceptor(streamAuth),
	)
	agentv1.RegisterEnrollmentServiceServer(s.grpc, agentv1.UnimplementedEnrollmentServiceServer{})
	agentv1.RegisterAgentServiceServer(s.grpc, agentv1.UnimplementedAgentServiceServer{})
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

func requireAgent(ctx context.Context, method string) error {
	if strings.HasPrefix(method, enrollmentMethods) {
		return nil
	}
	_, err := AgentFromContext(ctx)
	return err
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

func unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := requireAgent(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := requireAgent(ss.Context(), info.FullMethod); err != nil {
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
	mux.Handle("/api/v1/", s.requireAdmin(http.NotFoundHandler()))
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
	api := &http.Server{
		Handler:           s.API(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: s.certificate},
		ReadHeaderTimeout: 10 * time.Second,
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
