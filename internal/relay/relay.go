// Package relay forwards sealed files between agents that have no direct path,
// as ADRs 0002 and 0020 define. It pairs the two sides of a delivery by their
// relay tickets, passes bytes from one to the other as they arrive, and keeps
// nothing: no database, no files, and no copy of the data.
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	relayv1 "mmft.dev/mmft/gen/relay/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/relayticket"
)

const (
	shutdownTimeout = 10 * time.Second
	// openOverhead leaves room for a ticket and framing beside the largest
	// data message.
	openOverhead = 4096
	maxStreams   = 32
)

// Limits bound what the relay holds open. ADR 0020 sets the defaults. A zero
// field takes its default.
type Limits struct {
	// MaxPairs caps deliveries whose two sides are both connected.
	MaxPairs int
	// MaxWaiting caps sides still waiting for the other side.
	MaxWaiting int
	// MaxPerAgent caps the relay streams one agent can hold open.
	MaxPerAgent int
	// OpenWait is how long a new stream has to send its first message.
	OpenWait time.Duration
	// PairWait is how long one side waits for the other.
	PairWait time.Duration
	// Idle ends a pair when no data or acknowledgement moves for this long.
	Idle time.Duration
	// MaxChunk is the largest data message.
	MaxChunk int
	// MaxConnections caps accepted connections.
	MaxConnections int
}

// DefaultLimits are the limits from ADR 0020.
var DefaultLimits = Limits{
	MaxPairs:       256,
	MaxWaiting:     512,
	MaxPerAgent:    16,
	OpenWait:       30 * time.Second,
	PairWait:       2 * time.Minute,
	Idle:           60 * time.Second,
	MaxChunk:       1 << 20,
	MaxConnections: 1024,
}

func (l *Limits) defaults() {
	d := DefaultLimits
	set := func(v *int, def int) {
		if *v == 0 {
			*v = def
		}
	}
	setDuration := func(v *time.Duration, def time.Duration) {
		if *v == 0 {
			*v = def
		}
	}
	set(&l.MaxPairs, d.MaxPairs)
	set(&l.MaxWaiting, d.MaxWaiting)
	set(&l.MaxPerAgent, d.MaxPerAgent)
	set(&l.MaxChunk, d.MaxChunk)
	set(&l.MaxConnections, d.MaxConnections)
	setDuration(&l.OpenWait, d.OpenWait)
	setDuration(&l.PairWait, d.PairWait)
	setDuration(&l.Idle, d.Idle)
}

// Config configures a relay.
type Config struct {
	// Identity is the relay's own TLS certificate, which agents pin.
	Identity tls.Certificate
	// ConnectionCA is the orchestrator's connection CA certificate. Agents
	// connect with certificates it issued.
	ConnectionCA *x509.Certificate
	// TicketKey is the orchestrator's relay ticket public key.
	TicketKey ed25519.PublicKey
	Limits    Limits
	// Log receives one JSON object per line when a pair ends.
	Log io.Writer
	Now func() time.Time
	// Tap, if set, sees each data message as it is forwarded, with its offset
	// in the sealed file. Only the lab's test relay sets it, to check that
	// the relay sees nothing but sealed bytes. It must not keep chunk.
	Tap func(deliveryID string, offset uint64, chunk []byte)
}

// Server is a relay.
type Server struct {
	relayv1.UnimplementedRelayServiceServer

	cfg  Config
	grpc *grpc.Server

	mu       sync.Mutex
	logMu    sync.Mutex
	pairings map[string]*pairing
	perAgent map[string]int
}

// New validates a configuration and builds a relay.
func New(cfg Config) (*Server, error) {
	if len(cfg.Identity.Certificate) == 0 || cfg.ConnectionCA == nil || len(cfg.TicketKey) != ed25519.PublicKeySize {
		return nil, errors.New("relay: an identity, the connection CA, and the ticket key are required")
	}
	cfg.Limits.defaults()
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg, pairings: map[string]*pairing{}, perAgent: map[string]int{}}
	pool := x509.NewCertPool()
	pool.AddCert(cfg.ConnectionCA)
	s.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cfg.Identity},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
		})),
		grpc.MaxRecvMsgSize(cfg.Limits.MaxChunk+openOverhead),
		grpc.MaxConcurrentStreams(maxStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 5 * time.Minute}),
	)
	relayv1.RegisterRelayServiceServer(s.grpc, s)
	return s, nil
}

// Serve runs the relay until ctx ends. Pairs still forwarding get a short
// grace period, then end, and their agents resume later.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	errs := make(chan error, 1)
	go func() { errs <- s.grpc.Serve(netutil.LimitListener(lis, s.cfg.Limits.MaxConnections)) }()
	select {
	case <-ctx.Done():
	case err := <-errs:
		return err
	}
	stopped := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(shutdownTimeout):
		s.grpc.Stop()
	}
	return nil
}

func (s *Server) log(event, delivery string, err error) {
	m := map[string]any{"time": s.cfg.Now().UTC().Format(time.RFC3339), "event": event, "delivery_id": delivery}
	if err != nil {
		m["code"] = status.Code(err).String()
		m["error"] = status.Convert(err).Message()
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	_ = json.NewEncoder(s.cfg.Log).Encode(m)
}

// Send takes the sending side of a delivery.
func (s *Server) Send(stream relayv1.RelayService_SendServer) error {
	ctx := stream.Context()
	agent, err := peerAgent(ctx)
	if err != nil {
		return err
	}
	first, err := recvFirst(ctx, stream.Recv, s.cfg.Limits.OpenWait)
	if err != nil {
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "the first message must open the stream")
	}
	t, err := s.ticket(open.GetTicket(), relayticket.Send, agent, open.GetDeliveryId())
	if err != nil {
		return err
	}
	p, h, err := s.join(t, open.GetTotalBytes(), 0)
	if err != nil {
		return err
	}
	defer s.leave(p, h)
	if err := s.awaitPair(ctx, p); err != nil {
		return err
	}
	return p.runSender(stream)
}

// Receive takes the receiving side of a delivery.
func (s *Server) Receive(stream relayv1.RelayService_ReceiveServer) error {
	ctx := stream.Context()
	agent, err := peerAgent(ctx)
	if err != nil {
		return err
	}
	first, err := recvFirst(ctx, stream.Recv, s.cfg.Limits.OpenWait)
	if err != nil {
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "the first message must open the stream")
	}
	t, err := s.ticket(open.GetTicket(), relayticket.Receive, agent, open.GetDeliveryId())
	if err != nil {
		return err
	}
	p, h, err := s.join(t, 0, open.GetResumeOffset())
	if err != nil {
		return err
	}
	defer s.leave(p, h)
	if err := s.awaitPair(ctx, p); err != nil {
		return err
	}
	return p.runReceiver(stream)
}

// peerAgent returns the agent ID from the verified connection certificate.
func peerAgent(ctx context.Context) (string, error) {
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

// recvFirst waits a bounded time for a stream's first message, so a peer
// can't hold a stream open without saying what it's for.
func recvFirst[T any](ctx context.Context, recv func() (T, error), wait time.Duration) (T, error) {
	type result struct {
		msg T
		err error
	}
	got := make(chan result, 1)
	go func() {
		msg, err := recv()
		got <- result{msg, err}
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	var zero T
	select {
	case r := <-got:
		if errors.Is(r.err, io.EOF) {
			return zero, status.Error(codes.InvalidArgument, "the stream closed before opening")
		}
		if r.err != nil {
			return zero, status.Convert(r.err).Err()
		}
		return r.msg, nil
	case <-timer.C:
		return zero, status.Error(codes.DeadlineExceeded, "the stream sent no first message")
	case <-ctx.Done():
		return zero, status.FromContextError(ctx.Err()).Err()
	}
}

// ticket checks that a ticket is genuine and current, and that it lets this
// agent take this side of this delivery.
func (s *Server) ticket(data []byte, role relayticket.Role, agent, delivery string) (relayticket.Ticket, error) {
	t, err := relayticket.Verify(s.cfg.TicketKey, data, s.cfg.Now())
	switch {
	case errors.Is(err, relayticket.ErrExpired):
		return t, status.Error(codes.PermissionDenied, "the ticket has expired")
	case err != nil:
		return t, status.Error(codes.PermissionDenied, "the ticket is not valid")
	case t.Role != role:
		return t, status.Error(codes.PermissionDenied, "the ticket is for the other side of the delivery")
	case t.Holder != agent:
		return t, status.Error(codes.PermissionDenied, "the ticket is for another agent")
	case t.DeliveryID != delivery:
		return t, status.Error(codes.PermissionDenied, "the ticket is for another delivery")
	}
	return t, nil
}
