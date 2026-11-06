package server

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/relayticket"
	"mmft.dev/mmft/internal/seal"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// Manual runs move one file from one agent's outbox to another's inbox, with
// no flow, as ADR 0021 defines. The orchestrator assigns each side over the
// agent's stream, stores the source's manifest and the destination's receipt,
// and never sees the file's contents.

// streamBuffer is how many messages can wait for one agent's stream.
const streamBuffer = 16

// errorCodePattern matches the stable error codes agents report, as the
// deliveries table requires.
var errorCodePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// Error codes the orchestrator sets itself.
const (
	codeAgentFailed     = "agent_failed"
	codeInvalidManifest = "invalid_manifest"
	codeInvalidReceipt  = "invalid_receipt"
	codeDispatchFailed  = "dispatch_failed"
)

// agentStream lets other code send messages on an agent's open stream. Only
// the stream's writer goroutine sends on the gRPC stream itself.
type agentStream struct {
	out chan *agentv1.ConnectResponse
}

// register makes a stream the agent's current one. A newer stream from the same
// agent replaces it. The returned function removes it again, and fails every
// delivery whose assignment was still waiting in its queue, so no delivery is
// left running with no agent working on it.
func (s *Server) register(agentID string) (*agentStream, func()) {
	st := &agentStream{out: make(chan *agentv1.ConnectResponse, streamBuffer)}
	s.streamsMu.Lock()
	s.streams[agentID] = st
	s.streamsMu.Unlock()
	return st, func() {
		s.streamsMu.Lock()
		if s.streams[agentID] == st {
			delete(s.streams, agentID)
		}
		s.streamsMu.Unlock()
		for {
			select {
			case m := <-st.out:
				s.dispatchLost(m)
			default:
				return
			}
		}
	}
}

// dispatchLost fails the delivery a message assigned, when the message never
// reached the agent.
func (s *Server) dispatchLost(m *agentv1.ConnectResponse) {
	if d := m.GetManualDelivery(); d != nil {
		s.failDelivery(context.Background(), d.GetDeliveryId(), codeDispatchFailed)
	}
}

func (s *Server) connected(agentID string) bool {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	return s.streams[agentID] != nil
}

// push queues a message for an agent's stream. It reports false if the agent
// isn't connected or its queue is full.
func (s *Server) push(agentID string, m *agentv1.ConnectResponse) bool {
	s.streamsMu.Lock()
	st := s.streams[agentID]
	s.streamsMu.Unlock()
	if st == nil {
		return false
	}
	select {
	case st.out <- m:
		return true
	default:
		return false
	}
}

// relayConfigured reports whether the orchestrator can issue relay tickets.
func (s *Server) relayConfigured() bool {
	return s.cfg.RelayAddress != ""
}

func (s *Server) relayTicket(delivery string, role relayticket.Role, holder, peer string) (*agentv1.RelayTicket, error) {
	data, err := relayticket.Issue(s.cfg.TicketKey, relayticket.Ticket{
		DeliveryID: delivery, Role: role, Holder: holder, Peer: peer,
		ExpiresAt: s.cfg.Now().Add(relayticket.Lifetime),
	})
	if err != nil {
		return nil, err
	}
	return &agentv1.RelayTicket{
		DeliveryId:             delivery,
		Ticket:                 data,
		RelayAddress:           s.cfg.RelayAddress,
		RelayCertificateSha256: s.cfg.RelayCertificateSHA256,
	}, nil
}

// runAgent is what a manual run needs to know about one of its agents.
type runAgent struct {
	status, workspaceID string
	identity            []byte
	verifier            statement.Verifier
}

func (s *Server) loadRunAgent(ctx context.Context, q pgx.Tx, id string) (runAgent, error) {
	var a runAgent
	var ed, ml []byte
	err := q.QueryRow(ctx, `
		SELECT a.status, a.workspace_id, st.envelope, i.ed25519_public_key, i.mldsa65_public_key
		FROM agents a
		LEFT JOIN agent_identities i ON i.agent_id = a.id AND i.revoked_at IS NULL
		LEFT JOIN signed_statements st ON st.id = i.identity_statement_id
		WHERE a.id = $1`, id).Scan(&a.status, &a.workspaceID, &a.identity, &ed, &ml)
	if err != nil {
		return a, err
	}
	if a.identity != nil {
		key, err := statement.NewPublicKey(ed, ml)
		if err != nil {
			return a, err
		}
		a.verifier = statement.Verifier{Key: key, Role: statement.RoleAgent, Owner: id}
	}
	return a, nil
}

type runRequest struct {
	SourceAgentID      string `json:"source_agent_id"`
	DestinationAgentID string `json:"destination_agent_id"`
	FileName           string `json:"file_name"`
}

type deliveryItem struct {
	ID                 string  `json:"id"`
	SourceAgentID      string  `json:"source_agent_id"`
	DestinationAgentID string  `json:"destination_agent_id"`
	FileName           *string `json:"file_name,omitempty"`
	SizeBytes          *int64  `json:"size_bytes,omitempty"`
	SealedSHA256       *string `json:"sealed_sha256,omitempty"`
	Status             string  `json:"status"`
	Evidence           string  `json:"evidence"`
	ErrorCode          *string `json:"error_code,omitempty"`
}

type runItem struct {
	ID          string         `json:"id"`
	FlowID      *string        `json:"flow_id"`
	FlowVersion *int           `json:"flow_version"`
	Status      string         `json:"status"`
	Deliveries  []deliveryItem `json:"deliveries"`
}

// startRun starts a manual run: one file from the source's outbox to the
// destination's inbox. Both agents must be approved, in the same workspace,
// and connected now, because manual runs don't wait or retry.
func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	var req runRequest
	if err := decodeStrict(r.Body, &req); err != nil || !trust.ValidAgentID(req.SourceAgentID) ||
		!trust.ValidAgentID(req.DestinationAgentID) || !seal.ValidFileName(req.FileName) {
		problem(w, http.StatusBadRequest, "source_agent_id and destination_agent_id must be agent IDs, and file_name a bare file name.")
		return
	}
	if req.SourceAgentID == req.DestinationAgentID {
		problem(w, http.StatusBadRequest, "The source and destination must be different agents.")
		return
	}
	if !s.relayConfigured() {
		problem(w, http.StatusConflict, "The orchestrator has no relay configured.")
		return
	}
	ctx := r.Context()
	var runID, deliveryID string
	var dest runAgent
	err := pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		src, err := s.loadRunAgent(ctx, tx, req.SourceAgentID)
		if err != nil {
			return err
		}
		dest, err = s.loadRunAgent(ctx, tx, req.DestinationAgentID)
		if err != nil {
			return err
		}
		for _, a := range []runAgent{src, dest} {
			if a.status != "approved" || a.identity == nil {
				return apiError{http.StatusConflict, "Both agents must be approved."}
			}
		}
		if src.workspaceID != dest.workspaceID {
			return apiError{http.StatusConflict, "Both agents must be in the same workspace."}
		}
		if !s.connected(req.SourceAgentID) || !s.connected(req.DestinationAgentID) {
			return apiError{http.StatusConflict, "Both agents must be connected."}
		}
		if err := tx.QueryRow(ctx, `INSERT INTO runs (workspace_id, status) VALUES ($1, 'running') RETURNING id`,
			src.workspaceID).Scan(&runID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO deliveries (run_id, source_agent_id, destination_agent_id, status)
			VALUES ($1, $2, $3, 'pending') RETURNING id`,
			runID, req.SourceAgentID, req.DestinationAgentID).Scan(&deliveryID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO delivery_files (delivery_id, file_name) VALUES ($1, $2)`, deliveryID, req.FileName)
		return err
	})
	var apiErr apiError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		problem(w, http.StatusNotFound, "No such agent.")
		return
	case errors.As(err, &apiErr):
		problem(w, apiErr.code, apiErr.title)
		return
	case err != nil:
		problem(w, http.StatusInternalServerError, "Could not start the run.")
		return
	}

	ticket, err := s.relayTicket(deliveryID, relayticket.Send, req.SourceAgentID, req.DestinationAgentID)
	if err != nil || !s.push(req.SourceAgentID, manualDelivery(&agentv1.ManualDelivery{
		DeliveryId:            deliveryID,
		Role:                  agentv1.DeliveryRole_DELIVERY_ROLE_SEND,
		FileName:              req.FileName,
		PeerAgentId:           req.DestinationAgentID,
		PeerIdentityStatement: dest.identity,
		RelayTicket:           ticket,
	})) {
		s.failDelivery(ctx, deliveryID, codeDispatchFailed)
	}
	run, err := s.readRun(ctx, runID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not read the run.")
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func manualDelivery(d *agentv1.ManualDelivery) *agentv1.ConnectResponse {
	return &agentv1.ConnectResponse{Message: &agentv1.ConnectResponse_ManualDelivery{ManualDelivery: d}}
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	if !trust.ValidAgentID(runID) {
		problem(w, http.StatusNotFound, "No such run.")
		return
	}
	run, err := s.readRun(r.Context(), runID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		problem(w, http.StatusNotFound, "No such run.")
	case err != nil:
		problem(w, http.StatusInternalServerError, "Could not read the run.")
	default:
		writeJSON(w, http.StatusOK, run)
	}
}

func (s *Server) readRun(ctx context.Context, runID string) (runItem, error) {
	var run runItem
	if err := s.cfg.DB.QueryRow(ctx, `SELECT id, flow_id, flow_version, status FROM runs WHERE id = $1`, runID).
		Scan(&run.ID, &run.FlowID, &run.FlowVersion, &run.Status); err != nil {
		return run, err
	}
	rows, err := s.cfg.DB.Query(ctx, `
		SELECT d.id, d.source_agent_id, d.destination_agent_id, f.file_name, d.size_bytes, d.sealed_sha256,
		       d.status, d.evidence, d.error_code
		FROM deliveries d LEFT JOIN delivery_files f ON f.delivery_id = d.id
		WHERE d.run_id = $1 ORDER BY d.id`, runID)
	if err != nil {
		return run, err
	}
	defer rows.Close()
	run.Deliveries = []deliveryItem{}
	for rows.Next() {
		var d deliveryItem
		var sum []byte
		if err := rows.Scan(&d.ID, &d.SourceAgentID, &d.DestinationAgentID, &d.FileName, &d.SizeBytes, &sum,
			&d.Status, &d.Evidence, &d.ErrorCode); err != nil {
			return run, err
		}
		if sum != nil {
			h := hex.EncodeToString(sum)
			d.SealedSHA256 = &h
		}
		run.Deliveries = append(run.Deliveries, d)
	}
	return run, rows.Err()
}

// failDelivery ends a delivery and its run as failed, unless it has already
// ended.
func (s *Server) failDelivery(ctx context.Context, deliveryID, code string) {
	_ = pgx.BeginFunc(context.WithoutCancel(ctx), s.cfg.DB, func(tx pgx.Tx) error {
		var runID string
		err := tx.QueryRow(context.WithoutCancel(ctx), `
			UPDATE deliveries SET status = 'failed', error_code = $2
			WHERE id = $1 AND status NOT IN ('succeeded', 'failed', 'cancelled')
			RETURNING run_id`, deliveryID, code).Scan(&runID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(context.WithoutCancel(ctx), `UPDATE runs SET status = 'failed' WHERE id = $1`, runID)
		return err
	})
}

// openDelivery is a delivery still in progress, as an update sees it.
type openDelivery struct {
	runID, source, destination, status string
	fileName                           string
	manifestID                         []byte
}

// deliveryUpdate handles an agent's report on a manual delivery. An update for
// an unknown or finished delivery, or from an agent that isn't part of it, is
// ignored, so no agent can end another pair's delivery.
func (s *Server) deliveryUpdate(ctx context.Context, agentID string, u *agentv1.DeliveryUpdate) {
	if !trust.ValidAgentID(u.GetDeliveryId()) {
		return
	}
	var d openDelivery
	err := s.cfg.DB.QueryRow(ctx, `
		SELECT d.run_id, d.source_agent_id, d.destination_agent_id, d.status, coalesce(f.file_name, ''),
		       d.manifest_statement_id
		FROM deliveries d LEFT JOIN delivery_files f ON f.delivery_id = d.id
		WHERE d.id = $1 AND d.status NOT IN ('succeeded', 'failed', 'cancelled')`, u.GetDeliveryId()).
		Scan(&d.runID, &d.source, &d.destination, &d.status, &d.fileName, &d.manifestID)
	if err != nil || (agentID != d.source && agentID != d.destination) {
		return
	}
	id := u.GetDeliveryId()
	switch {
	case u.GetState() == agentv1.DeliveryState_DELIVERY_STATE_FAILED || u.GetErrorCode() != "":
		code := u.GetErrorCode()
		if !errorCodePattern.MatchString(code) {
			code = codeAgentFailed
		}
		s.failDelivery(ctx, id, code)
	case agentID == d.source && d.status == "pending" && len(u.GetManifestStatement()) > 0:
		s.manifestArrived(ctx, id, d, u.GetManifestStatement())
	case agentID == d.destination && d.status == "transferring" && len(u.GetReceiptStatement()) > 0:
		s.receiptArrived(ctx, id, d, u.GetReceiptStatement())
	}
}

func (d openDelivery) delivery(id string) seal.Delivery {
	return seal.Delivery{DeliveryID: id, SourceAgent: d.source, DestinationAgent: d.destination}
}

// manifestArrived stores the source's manifest and assigns the destination its
// side, with the manifest and the source's identity.
func (s *Server) manifestArrived(ctx context.Context, id string, d openDelivery, raw []byte) {
	var src runAgent
	var stored bool
	err := pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		var err error
		if src, err = s.loadRunAgent(ctx, tx, d.source); err != nil {
			return err
		}
		m, statementID, err := seal.VerifyManifest(raw, src.verifier, d.delivery(id))
		if err != nil {
			return err
		}
		sid, err := hex.DecodeString(statementID)
		if err != nil {
			return err
		}
		sum, err := hex.DecodeString(m.SealedSHA256)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO signed_statements (id, payload_type, envelope) VALUES ($1, $2, $3)
			ON CONFLICT (id) DO NOTHING`, sid, string(statement.TypeDeliveryManifest), raw); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			UPDATE deliveries SET status = 'transferring', evidence = 'source_only', manifest_statement_id = $2,
			       sealed_sha256 = $3, size_bytes = $4
			WHERE id = $1 AND status = 'pending'`, id, sid, sum, m.SealedSize)
		stored = err == nil && tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		s.failDelivery(ctx, id, codeInvalidManifest)
		return
	}
	if !stored {
		return
	}
	ticket, err := s.relayTicket(id, relayticket.Receive, d.destination, d.source)
	if err != nil || !s.push(d.destination, manualDelivery(&agentv1.ManualDelivery{
		DeliveryId:            id,
		Role:                  agentv1.DeliveryRole_DELIVERY_ROLE_RECEIVE,
		FileName:              d.fileName,
		PeerAgentId:           d.source,
		PeerIdentityStatement: src.identity,
		RelayTicket:           ticket,
		ManifestStatement:     raw,
	})) {
		s.failDelivery(ctx, id, codeDispatchFailed)
	}
}

// receiptArrived stores the destination's receipt once it matches the stored
// manifest, and completes the delivery and its run.
func (s *Server) receiptArrived(ctx context.Context, id string, d openDelivery, raw []byte) {
	err := pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		src, err := s.loadRunAgent(ctx, tx, d.source)
		if err != nil {
			return err
		}
		dest, err := s.loadRunAgent(ctx, tx, d.destination)
		if err != nil {
			return err
		}
		var manifest []byte
		if err := tx.QueryRow(ctx, `SELECT envelope FROM signed_statements WHERE id = $1`, d.manifestID).Scan(&manifest); err != nil {
			return err
		}
		m, _, err := seal.VerifyManifest(manifest, src.verifier, d.delivery(id))
		if err != nil {
			return err
		}
		_, statementID, err := seal.VerifyReceipt(raw, dest.verifier, d.delivery(id), m)
		if err != nil {
			return err
		}
		sid, err := hex.DecodeString(statementID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO signed_statements (id, payload_type, envelope) VALUES ($1, $2, $3)
			ON CONFLICT (id) DO NOTHING`, sid, string(statement.TypeDeliveryReceipt), raw); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			UPDATE deliveries SET status = 'succeeded', evidence = 'verified', receipt_statement_id = $2
			WHERE id = $1 AND status = 'transferring'`, id, sid)
		if err != nil || tag.RowsAffected() != 1 {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE runs SET status = 'succeeded' WHERE id = $1`, d.runID)
		return err
	})
	if err != nil {
		s.failDelivery(ctx, id, codeInvalidReceipt)
	}
}
