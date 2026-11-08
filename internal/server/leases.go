package server

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/relayticket"
	"mmft.dev/mmft/internal/trust"
)

// Leases, as ADR 0024 defines. Each side of a delivery is work that one agent
// claims under a lease. The orchestrator offers it while the agent is
// connected, grants one claim, extends the lease with each update, and fails
// the delivery when a lease expires.

// The two sides of a delivery, as delivery_leases names them.
const (
	sideSend    = "send"
	sideReceive = "receive"
)

// offerBatch bounds how many waiting deliveries one pass offers.
const offerBatch = 500

// activeStatuses are the delivery statuses that haven't ended.
const activeStatuses = `('pending', 'claimed', 'transferring', 'verifying', 'retry_wait')`

func workOffer(runID, workID string) *agentv1.ConnectResponse {
	return &agentv1.ConnectResponse{Message: &agentv1.ConnectResponse_WorkOffer{WorkOffer: &agentv1.WorkOffer{RunId: runID, WorkId: workID}}}
}

func leaseResult(workID string, granted bool, seconds uint32) *agentv1.ConnectResponse {
	return &agentv1.ConnectResponse{Message: &agentv1.ConnectResponse_LeaseResult{LeaseResult: &agentv1.LeaseResult{
		WorkId: workID, Granted: granted, LeaseSeconds: seconds,
	}}}
}

func cancelWork(workID, reason string) *agentv1.ConnectResponse {
	return &agentv1.ConnectResponse{Message: &agentv1.ConnectResponse_Cancel{Cancel: &agentv1.Cancel{WorkId: workID, Reason: reason}}}
}

// waiting is one side of a delivery that no agent holds yet.
type waiting struct {
	deliveryID, runID, status, source, destination string
	workID                                         *string
}

// offerWork offers each waiting side to its agent while the agent is
// connected. A delivery with an empty filter is any delivery, and an agent
// filter matches either side. The send side waits until both agents are
// connected, so the source never seals for a destination that isn't there.
func (s *Server) offerWork(ctx context.Context, deliveryID, agentID string) {
	var delivery, agent *string
	if deliveryID != "" {
		delivery = &deliveryID
	}
	if agentID != "" {
		agent = &agentID
	}
	rows, err := s.cfg.DB.Query(ctx, `
		SELECT d.id, d.run_id, d.status, d.source_agent_id, d.destination_agent_id, l.id
		FROM deliveries d
		LEFT JOIN delivery_leases l ON l.delivery_id = d.id AND l.ended_at IS NULL
		     AND l.side = CASE WHEN d.status = 'pending' THEN 'send' ELSE 'receive' END
		WHERE d.status IN ('pending', 'transferring') AND (l.id IS NULL OR l.granted_at IS NULL)
		  AND ($1::uuid IS NULL OR d.id = $1)
		  AND ($2::uuid IS NULL OR d.source_agent_id = $2 OR d.destination_agent_id = $2)
		ORDER BY d.id LIMIT $3`, delivery, agent, offerBatch)
	if err != nil {
		return
	}
	found, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (waiting, error) {
		var w waiting
		err := r.Scan(&w.deliveryID, &w.runID, &w.status, &w.source, &w.destination, &w.workID)
		return w, err
	})
	if err != nil {
		return
	}
	for _, w := range found {
		side, holder := sideSend, w.source
		if w.status == "transferring" {
			side, holder = sideReceive, w.destination
		}
		if !s.connected(holder) || (side == sideSend && !s.connected(w.destination)) {
			continue
		}
		if w.workID == nil {
			var id string
			err := s.cfg.DB.QueryRow(ctx, `
				INSERT INTO delivery_leases (delivery_id, side, agent_id, offered_at) VALUES ($1, $2, $3, $4)
				ON CONFLICT (delivery_id, side) WHERE ended_at IS NULL DO NOTHING RETURNING id`,
				w.deliveryID, side, holder, s.cfg.Now()).Scan(&id)
			if err != nil {
				// Another pass offered it first, and offers it.
				continue
			}
			w.workID = &id
		}
		s.push(holder, workOffer(w.runID, *w.workID))
	}
}

// claim grants an agent the work it was offered, if no one holds it and the
// delivery still needs that side. A grant is followed by the assignment.
func (s *Server) claim(ctx context.Context, agentID string, c *agentv1.LeaseClaim) {
	workID := c.GetWorkId()
	seconds := uint32(s.limits.leaseDuration / time.Second) //nolint:gosec // a set limit of about a minute
	if !trust.ValidAgentID(workID) {
		return
	}
	var assignment *agentv1.ManualDelivery
	err := pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		now := s.cfg.Now()
		var deliveryID, side string
		if err := tx.QueryRow(ctx, `
			UPDATE delivery_leases SET granted_at = $3, expires_at = $4
			WHERE id = $1 AND agent_id = $2 AND granted_at IS NULL AND ended_at IS NULL
			RETURNING delivery_id, side`, workID, agentID, now, now.Add(s.limits.leaseDuration)).Scan(&deliveryID, &side); err != nil {
			return err
		}
		var d openDelivery
		if err := tx.QueryRow(ctx, `
			SELECT d.run_id, d.source_agent_id, d.destination_agent_id, d.status, coalesce(f.file_name, ''),
			       d.manifest_statement_id
			FROM deliveries d LEFT JOIN delivery_files f ON f.delivery_id = d.id
			WHERE d.id = $1 FOR UPDATE OF d`, deliveryID).
			Scan(&d.runID, &d.source, &d.destination, &d.status, &d.fileName, &d.manifestID); err != nil {
			return err
		}
		switch {
		case side == sideSend && d.status == "pending":
			dest, err := s.loadRunAgent(ctx, tx, d.destination)
			if err != nil {
				return err
			}
			ticket, err := s.relayTicket(deliveryID, relayticket.Send, d.source, d.destination)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE deliveries SET status = 'claimed' WHERE id = $1`, deliveryID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE runs SET status = 'running' WHERE id = $1 AND status = 'pending'`, d.runID); err != nil {
				return err
			}
			assignment = &agentv1.ManualDelivery{
				DeliveryId:            deliveryID,
				Role:                  agentv1.DeliveryRole_DELIVERY_ROLE_SEND,
				FileName:              d.fileName,
				PeerAgentId:           d.destination,
				PeerIdentityStatement: dest.identity,
				RelayTicket:           ticket,
			}
		case side == sideReceive && d.status == "transferring":
			src, err := s.loadRunAgent(ctx, tx, d.source)
			if err != nil {
				return err
			}
			var manifest []byte
			if err := tx.QueryRow(ctx, `SELECT envelope FROM signed_statements WHERE id = $1`, d.manifestID).Scan(&manifest); err != nil {
				return err
			}
			ticket, err := s.relayTicket(deliveryID, relayticket.Receive, d.destination, d.source)
			if err != nil {
				return err
			}
			assignment = &agentv1.ManualDelivery{
				DeliveryId:            deliveryID,
				Role:                  agentv1.DeliveryRole_DELIVERY_ROLE_RECEIVE,
				FileName:              d.fileName,
				PeerAgentId:           d.source,
				PeerIdentityStatement: src.identity,
				RelayTicket:           ticket,
				ManifestStatement:     manifest,
			}
		default:
			return errNotClaimable
		}
		assignment.WorkId = workID
		return nil
	})
	if err != nil {
		s.push(agentID, leaseResult(workID, false, 0))
		return
	}
	// The lease expires if the assignment never reaches the agent.
	s.push(agentID, leaseResult(workID, true, seconds))
	s.push(agentID, manualDelivery(assignment))
}

var errNotClaimable = errors.New("server: the delivery no longer needs this side")

// extend renews the lease an update names, if this agent holds it for this
// delivery. It reports the lease's side, or false if the update must be
// ignored.
func (s *Server) extend(ctx context.Context, agentID string, u *agentv1.DeliveryUpdate) (string, bool) {
	if !trust.ValidAgentID(u.GetWorkId()) || !trust.ValidAgentID(u.GetDeliveryId()) {
		return "", false
	}
	var side string
	err := s.cfg.DB.QueryRow(ctx, `
		UPDATE delivery_leases SET expires_at = $4
		WHERE id = $1 AND agent_id = $2 AND delivery_id = $3 AND granted_at IS NOT NULL AND ended_at IS NULL
		RETURNING side`, u.GetWorkId(), agentID, u.GetDeliveryId(), s.cfg.Now().Add(s.limits.leaseDuration)).Scan(&side)
	return side, err == nil
}

// release ends a lease whose side has finished.
func (s *Server) release(ctx context.Context, workID string) {
	_, _ = s.cfg.DB.Exec(ctx, `
		UPDATE delivery_leases SET ended_at = $2, end_reason = 'released' WHERE id = $1 AND ended_at IS NULL`,
		workID, s.cfg.Now())
}

// expireLeases fails each delivery holding a lease past its expiry, and tells
// its agents to stop.
func (s *Server) expireLeases(ctx context.Context) {
	rows, err := s.cfg.DB.Query(ctx, `
		SELECT id FROM delivery_leases
		WHERE ended_at IS NULL AND granted_at IS NOT NULL AND expires_at < $1
		ORDER BY expires_at LIMIT $2`, s.cfg.Now(), offerBatch)
	if err != nil {
		return
	}
	expired, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return
	}
	for _, workID := range expired {
		s.endDelivery(ctx, "", codeLeaseExpired, workID)
	}
}

// graceLeases gives every open lease one more lease period, so agents that
// couldn't reach a stopped orchestrator don't lose their work when it starts.
func (s *Server) graceLeases(ctx context.Context) {
	_, _ = s.cfg.DB.Exec(ctx, `
		UPDATE delivery_leases SET expires_at = greatest(expires_at, $1)
		WHERE ended_at IS NULL AND granted_at IS NOT NULL`, s.cfg.Now().Add(s.limits.leaseDuration))
}

// sweep runs until ctx ends: it expires leases and offers waiting work again,
// which covers offers lost with a stream.
func (s *Server) sweep(ctx context.Context) {
	if s.limits.sweepInterval <= 0 {
		return
	}
	s.graceLeases(ctx)
	t := time.NewTicker(s.limits.sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.expireLeases(ctx)
			s.offerWork(ctx, "", "")
		}
	}
}
