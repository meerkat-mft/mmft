package server

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/version"
)

// ProtocolVersion is the agent protocol version this orchestrator speaks.
const ProtocolVersion = 1

// agentVersionPattern bounds the version an agent reports, which is untrusted
// and shown to administrators.
var agentVersionPattern = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,64}$`)

type agentService struct {
	agentv1.UnimplementedAgentServiceServer
	s *Server
}

// Connect holds an agent's stream. The first message must be a Hello, which
// gets a Welcome. Each later heartbeat records the agent as seen and checks
// its status again, so a revoked agent's stream ends at its next heartbeat. A
// stream that sends nothing for streamSilence is closed.
func (a agentService) Connect(stream agentv1.AgentService_ConnectServer) error {
	ctx := stream.Context()
	id, err := AgentFromContext(ctx)
	if err != nil {
		return err
	}
	msgs := make(chan *agentv1.ConnectRequest)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	silence := a.s.limits.streamSilence
	timer := time.NewTimer(silence)
	defer timer.Stop()
	// sendErr reports a failed write once the writer goroutine runs.
	var sendErr chan error
	next := func() (*agentv1.ConnectRequest, error) {
		select {
		case m := <-msgs:
			timer.Reset(silence)
			return m, nil
		case err := <-recvErr:
			return nil, err
		case err := <-sendErr:
			return nil, err
		case <-timer.C:
			return nil, status.Error(codes.DeadlineExceeded, "the agent sent nothing for too long")
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}

	first, err := next()
	if err != nil {
		return streamEnd(err)
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "the first message must be a hello")
	}
	if hello.GetProtocolVersion() != ProtocolVersion {
		return status.Errorf(codes.FailedPrecondition, "protocol version %d is not supported, only %d", hello.GetProtocolVersion(), ProtocolVersion)
	}
	if !agentVersionPattern.MatchString(hello.GetAgentVersion()) {
		return status.Error(codes.InvalidArgument, "the agent version is invalid")
	}
	if err := a.seen(ctx, id, hello.GetAgentVersion()); err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{Message: &agentv1.ConnectResponse_Welcome{Welcome: &agentv1.Welcome{
		ProtocolVersion:     ProtocolVersion,
		OrchestratorVersion: version.Version,
	}}}); err != nil {
		return err
	}
	// From here on only the writer sends on the stream, so other code can
	// queue messages for this agent.
	out, unregister := a.s.register(id)
	defer unregister()
	sendErr = make(chan error, 1)
	go func() {
		for {
			select {
			case m := <-out.out:
				if err := stream.Send(m); err != nil {
					sendErr <- err
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	// Work waiting for this agent is offered now, not at the next sweep.
	a.s.offerWork(ctx, "", id)
	for {
		m, err := next()
		if err != nil {
			return streamEnd(err)
		}
		switch m.GetMessage().(type) {
		case *agentv1.ConnectRequest_Heartbeat:
			if err := a.seen(ctx, id, ""); err != nil {
				return err
			}
		case *agentv1.ConnectRequest_DeliveryUpdate:
			if err := a.seen(ctx, id, ""); err != nil {
				return err
			}
			a.s.deliveryUpdate(ctx, id, m.GetDeliveryUpdate())
		case *agentv1.ConnectRequest_LeaseClaim:
			if err := a.seen(ctx, id, ""); err != nil {
				return err
			}
			a.s.claim(ctx, id, m.GetLeaseClaim())
		case *agentv1.ConnectRequest_Hello:
			return status.Error(codes.InvalidArgument, "the stream already has a hello")
		default:
			return status.Error(codes.Unimplemented, "this message is not supported yet")
		}
	}
}

// streamEnd treats an agent closing its side as a normal end.
func streamEnd(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// seen checks that the agent may still connect and records it as seen. A
// Hello also records the agent's version.
func (a agentService) seen(ctx context.Context, id, agentVersion string) error {
	if err := a.s.checkAgent(ctx, id); err != nil {
		return err
	}
	now := a.s.cfg.Now()
	var err error
	if agentVersion != "" {
		_, err = a.s.cfg.DB.Exec(ctx, `
			INSERT INTO agent_presence (agent_id, agent_version, last_seen_at) VALUES ($1, $2, $3)
			ON CONFLICT (agent_id) DO UPDATE SET agent_version = EXCLUDED.agent_version, last_seen_at = EXCLUDED.last_seen_at`,
			id, agentVersion, now)
	} else {
		_, err = a.s.cfg.DB.Exec(ctx, `UPDATE agent_presence SET last_seen_at = $2 WHERE agent_id = $1`, id, now)
	}
	if err != nil {
		return status.Error(codes.Unavailable, "could not record the agent as seen")
	}
	return nil
}

// RenewCertificate issues a new connection certificate to an agent that still
// holds a valid one. The new certificate must be for the same connection key,
// so renewal can never move an agent to another key. Pending agents may renew,
// so that slow approval doesn't strand them.
func (a agentService) RenewCertificate(ctx context.Context, req *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
	current, err := peerCertificate(ctx)
	if err != nil {
		return nil, err
	}
	id, err := connca.AgentID(current)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "the certificate does not identify an agent")
	}
	// Compare keys before signing, so the CA never issues a certificate for
	// another key under this agent's ID, even one that would be thrown away.
	csr, err := x509.ParseCertificateRequest(req.GetCertificateRequest())
	if err != nil || csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "the certificate request is invalid")
	}
	oldKey, ok := current.PublicKey.(ed25519.PublicKey)
	if !ok || !oldKey.Equal(csr.PublicKey) {
		return nil, status.Error(codes.PermissionDenied, "renewal must keep the connection key")
	}
	der, err := a.s.cfg.Authority.SignAgent(req.GetCertificateRequest(), id, a.s.cfg.Now(), a.s.cfg.ConnectionLifetime)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the certificate request is invalid")
	}
	return &agentv1.RenewCertificateResponse{ConnectionCertificate: der}, nil
}

// GetIdentity returns the caller's own identity statement, as stored.
func (a agentService) GetIdentity(ctx context.Context, _ *agentv1.GetIdentityRequest) (*agentv1.GetIdentityResponse, error) {
	id, err := AgentFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var envelope []byte
	err = a.s.cfg.DB.QueryRow(ctx, `
		SELECT st.envelope FROM agent_identities i
		JOIN signed_statements st ON st.id = i.identity_statement_id
		WHERE i.agent_id = $1 AND i.revoked_at IS NULL`, id).Scan(&envelope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "the agent is not approved yet")
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not read the identity")
	}
	return &agentv1.GetIdentityResponse{IdentityStatement: envelope}, nil
}
