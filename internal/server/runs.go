package server

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/relayticket"
	"mmft.dev/mmft/internal/seal"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// Manual runs move one file from one agent's outbox to another's inbox, with
// no flow, as ADR 0021 defines. Each side is claimed under a lease, as ADR 0024
// defines, and assigned over the agent's stream. The orchestrator stores the
// source's manifest and the destination's receipt, and never sees the file's
// contents.

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
	codeLeaseExpired    = "lease_expired"
)

// agentStream lets other code send messages on an agent's open stream. Only
// the stream's writer goroutine sends on the gRPC stream itself.
type agentStream struct {
	out chan *agentv1.ConnectResponse
}

// register makes a stream the agent's current one. A newer stream from the same
// agent replaces it. The returned function removes it again. A message still
// in its queue is dropped: an offer is made again, and a lease whose
// assignment never arrived expires.
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
// destination's inbox. Both agents must be approved and in the same
// workspace. The run waits, pending, until both are connected and the source
// claims its side.
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
	err := pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		src, err := s.loadRunAgent(ctx, tx, req.SourceAgentID)
		if err != nil {
			return err
		}
		dest, err := s.loadRunAgent(ctx, tx, req.DestinationAgentID)
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
		if err := tx.QueryRow(ctx, `INSERT INTO runs (workspace_id, status) VALUES ($1, 'pending') RETURNING id`,
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
	s.offerWork(ctx, deliveryID, "")
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

// endDelivery fails a delivery with code, unless it has already ended, ends
// its leases, and ends its run once every delivery has. With expiredWork set,
// it first expires that lease, and does nothing if an update renewed it
// meanwhile. Agents still holding a lease are told to stop.
func (s *Server) endDelivery(ctx context.Context, deliveryID, code, expiredWork string) {
	ctx = context.WithoutCancel(ctx)
	var cancels []held
	err := pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		cancels = nil
		now := s.cfg.Now()
		if expiredWork != "" {
			var holder string
			if err := tx.QueryRow(ctx, `
				UPDATE delivery_leases SET ended_at = $2, end_reason = 'expired'
				WHERE id = $1 AND ended_at IS NULL AND granted_at IS NOT NULL AND expires_at < $2
				RETURNING delivery_id, agent_id`, expiredWork, now).Scan(&deliveryID, &holder); err != nil {
				return err
			}
			cancels = append(cancels, held{expiredWork, holder})
		}
		var runID string
		if err := tx.QueryRow(ctx, `
			UPDATE deliveries SET status = 'failed', error_code = $2
			WHERE id = $1 AND status IN `+activeStatuses+`
			RETURNING run_id`, deliveryID, code).Scan(&runID); err != nil {
			return err
		}
		ended, err := endLeases(ctx, tx, deliveryID, now)
		if err != nil {
			return err
		}
		cancels = append(cancels, ended...)
		return finishRun(ctx, tx, runID)
	})
	if err != nil {
		return
	}
	for _, h := range cancels {
		s.push(h.agentID, cancelWork(h.workID, code))
	}
}

// held is a granted lease and the agent holding it.
type held struct{ workID, agentID string }

// endLeases ends every open lease of a delivery that has ended, and returns
// the granted ones, whose agents may still be working.
func endLeases(ctx context.Context, tx pgx.Tx, deliveryID string, now time.Time) ([]held, error) {
	rows, err := tx.Query(ctx, `
		UPDATE delivery_leases SET ended_at = $2, end_reason = 'delivery_ended'
		WHERE delivery_id = $1 AND ended_at IS NULL
		RETURNING id, agent_id, granted_at IS NOT NULL`, deliveryID, now)
	if err != nil {
		return nil, err
	}
	var out []held
	var h held
	var granted bool
	_, err = pgx.ForEachRow(rows, []any{&h.workID, &h.agentID, &granted}, func() error {
		if granted {
			out = append(out, h)
		}
		return nil
	})
	return out, err
}

// runOutcome is a run's final status once none of its deliveries is active.
func runOutcome(succeeded, total int) string {
	switch {
	case total > 0 && succeeded == total:
		return "succeeded"
	case succeeded > 0:
		return "partial_failure"
	default:
		return "failed"
	}
}

// finishRun ends a run once none of its deliveries is active. It locks the run
// row first, so two deliveries ending together can't both miss the end.
func finishRun(ctx context.Context, tx pgx.Tx, runID string) error {
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM runs WHERE id = $1 FOR UPDATE`, runID).Scan(&status); err != nil {
		return err
	}
	var active, succeeded, total int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status IN `+activeStatuses+`),
		       count(*) FILTER (WHERE status = 'succeeded'), count(*)
		FROM deliveries WHERE run_id = $1`, runID).Scan(&active, &succeeded, &total); err != nil {
		return err
	}
	if active > 0 || (status != "pending" && status != "running") {
		return nil
	}
	outcome := runOutcome(succeeded, total)
	if status == "pending" && outcome != "failed" {
		if _, err := tx.Exec(ctx, `UPDATE runs SET status = 'running' WHERE id = $1`, runID); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE runs SET status = $2 WHERE id = $1`, runID, outcome)
	return err
}

// openDelivery is a delivery still in progress, as an update sees it.
type openDelivery struct {
	runID, source, destination, status string
	fileName                           string
	manifestID                         []byte
}

// deliveryUpdate handles an agent's report on its side of a delivery. The
// update must name a lease the agent holds for that delivery, and renews it.
// Anything else is ignored, so no agent can end another pair's delivery, and
// an agent whose lease has ended can no longer act.
func (s *Server) deliveryUpdate(ctx context.Context, agentID string, u *agentv1.DeliveryUpdate) {
	side, ok := s.extend(ctx, agentID, u)
	if !ok {
		return
	}
	id := u.GetDeliveryId()
	var d openDelivery
	err := s.cfg.DB.QueryRow(ctx, `
		SELECT d.run_id, d.source_agent_id, d.destination_agent_id, d.status, coalesce(f.file_name, ''),
		       d.manifest_statement_id
		FROM deliveries d LEFT JOIN delivery_files f ON f.delivery_id = d.id
		WHERE d.id = $1 AND d.status IN `+activeStatuses, id).
		Scan(&d.runID, &d.source, &d.destination, &d.status, &d.fileName, &d.manifestID)
	if err != nil {
		return
	}
	switch {
	case u.GetState() == agentv1.DeliveryState_DELIVERY_STATE_FAILED || u.GetErrorCode() != "":
		code := u.GetErrorCode()
		if !errorCodePattern.MatchString(code) {
			code = codeAgentFailed
		}
		s.endDelivery(ctx, id, code, "")
		return
	case side == sideSend && d.status == "claimed" && len(u.GetManifestStatement()) > 0:
		s.manifestArrived(ctx, id, d, u.GetManifestStatement())
	case side == sideReceive && (d.status == "transferring" || d.status == "verifying") && len(u.GetReceiptStatement()) > 0:
		s.receiptArrived(ctx, id, d, u.GetReceiptStatement())
		return
	case side == sideReceive && d.status == "transferring" && u.GetState() == agentv1.DeliveryState_DELIVERY_STATE_VERIFYING:
		_, _ = s.cfg.DB.Exec(ctx, `UPDATE deliveries SET status = 'verifying' WHERE id = $1 AND status = 'transferring'`, id)
	}
	if side == sideSend && u.GetSideDone() {
		s.release(ctx, u.GetWorkId())
	}
}

func (d openDelivery) delivery(id string) seal.Delivery {
	return seal.Delivery{DeliveryID: id, SourceAgent: d.source, DestinationAgent: d.destination}
}

// manifestArrived stores the source's manifest, and offers the receive side
// to the destination.
func (s *Server) manifestArrived(ctx context.Context, id string, d openDelivery, raw []byte) {
	var stored bool
	err := pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		src, err := s.loadRunAgent(ctx, tx, d.source)
		if err != nil {
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
			WHERE id = $1 AND status = 'claimed'`, id, sid, sum, m.SealedSize)
		stored = err == nil && tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		s.endDelivery(ctx, id, codeInvalidManifest, "")
		return
	}
	if stored {
		s.offerWork(ctx, id, "")
	}
}

// receiptArrived stores the destination's receipt once it matches the stored
// manifest, and completes the delivery and, once every delivery has ended, its
// run.
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
		// A receipt implies the destination verified the file, even if its
		// verifying update was never handled.
		if _, err := tx.Exec(ctx, `UPDATE deliveries SET status = 'verifying' WHERE id = $1 AND status = 'transferring'`, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			UPDATE deliveries SET status = 'succeeded', evidence = 'verified', receipt_statement_id = $2
			WHERE id = $1 AND status = 'verifying'`, id, sid)
		if err != nil || tag.RowsAffected() != 1 {
			return err
		}
		if _, err := endLeases(ctx, tx, id, s.cfg.Now()); err != nil {
			return err
		}
		return finishRun(ctx, tx, d.runID)
	})
	if err != nil {
		s.endDelivery(ctx, id, codeInvalidReceipt, "")
	}
}
