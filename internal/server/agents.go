package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// publicKeys are an agent's public keys, which an administrator needs to
// recompute its fingerprint before approving it.
type publicKeys struct {
	Ed25519   []byte `json:"ed25519"`
	MLDSA65   []byte `json:"mldsa65"`
	Recipient string `json:"encryption_recipient"`
}

type agentItem struct {
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	Workspace         string      `json:"workspace"`
	Status            string      `json:"status"`
	IdentityExpiresAt *time.Time  `json:"identity_expires_at,omitempty"`
	PublicKeys        *publicKeys `json:"public_keys,omitempty"`
}

// listAgents returns a page of agents in ID order, optionally with one status.
// The cursor is the last ID of the previous page.
func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var agentStatus, cursor *string
	if v := q.Get("status"); v != "" {
		if v != "pending_approval" && v != "approved" && v != "revoked" {
			problem(w, http.StatusBadRequest, "status must be pending_approval, approved, or revoked.")
			return
		}
		agentStatus = &v
	}
	if v := q.Get("cursor"); v != "" {
		if !trust.ValidAgentID(v) {
			problem(w, http.StatusBadRequest, "The cursor is invalid.")
			return
		}
		cursor = &v
	}
	limit := defaultPageSize
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxPageSize {
			problem(w, http.StatusBadRequest, "limit must be from 1 to 200.")
			return
		}
		limit = n
	}
	rows, err := s.cfg.DB.Query(r.Context(), `
		SELECT a.id, a.name, w.name, a.status, i.not_after,
		       i.ed25519_public_key, i.mldsa65_public_key, i.encryption_recipient
		FROM agents a
		JOIN workspaces w ON w.id = a.workspace_id
		LEFT JOIN agent_identities i ON i.agent_id = a.id AND i.revoked_at IS NULL
		WHERE ($1::text IS NULL OR a.status = $1) AND ($2::uuid IS NULL OR a.id > $2::uuid)
		ORDER BY a.id
		LIMIT $3`, agentStatus, cursor, limit+1)
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not list agents.")
		return
	}
	items := []agentItem{}
	for rows.Next() {
		var item agentItem
		var ed, ml []byte
		var recipient *string
		if err := rows.Scan(&item.ID, &item.Name, &item.Workspace, &item.Status, &item.IdentityExpiresAt, &ed, &ml, &recipient); err != nil {
			rows.Close()
			problem(w, http.StatusInternalServerError, "Could not list agents.")
			return
		}
		if recipient != nil {
			item.PublicKeys = &publicKeys{Ed25519: ed, MLDSA65: ml, Recipient: *recipient}
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		problem(w, http.StatusInternalServerError, "Could not list agents.")
		return
	}
	page := map[string]any{"items": items}
	if len(items) > limit {
		page["items"] = items[:limit]
		page["next_cursor"] = items[limit-1].ID
	}
	writeJSON(w, http.StatusOK, page)
}

// apiError is a failure with the status and title a client sees.
type apiError struct {
	code  int
	title string
}

func (e apiError) Error() string { return e.title }

var (
	errNoAgent          = apiError{http.StatusNotFound, "No such agent."}
	errAgentRevoked     = apiError{http.StatusConflict, "The agent is revoked."}
	errIdentityMismatch = apiError{http.StatusBadRequest, "The identity does not match the agent."}
	errHasIdentity      = apiError{http.StatusConflict, "The agent already has a different identity."}
)

// putIdentity stores an identity statement signed in the CLI and approves the
// agent. The orchestrator can't judge whether to trust the statement, but it
// refuses one that is malformed or doesn't match the agent and keys it holds.
// Storing the same statement again changes nothing.
func (s *Server) putIdentity(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agent_id")
	if !trust.ValidAgentID(agentID) {
		problem(w, errNoAgent.code, errNoAgent.title)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		problem(w, http.StatusBadRequest, "The identity statement is invalid.")
		return
	}
	now := s.cfg.Now()
	claim, err := trust.CheckIdentity(body, now)
	if err != nil {
		problem(w, http.StatusBadRequest, "The identity statement is invalid.")
		return
	}
	if claim.AgentID != agentID {
		problem(w, errIdentityMismatch.code, errIdentityMismatch.title)
		return
	}
	err = pgx.BeginFunc(r.Context(), s.cfg.DB, func(tx pgx.Tx) error {
		return storeIdentity(r.Context(), tx, claim, body)
	})
	var apiErr apiError
	switch {
	case errors.As(err, &apiErr):
		problem(w, apiErr.code, apiErr.title)
	case err != nil:
		problem(w, http.StatusInternalServerError, "Could not store the identity.")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func storeIdentity(ctx context.Context, tx pgx.Tx, claim trust.IdentityClaim, envelope []byte) error {
	var agentStatus, workspace, name string
	err := tx.QueryRow(ctx, `
		SELECT a.status, w.name, a.name FROM agents a JOIN workspaces w ON w.id = a.workspace_id
		WHERE a.id = $1 FOR UPDATE OF a`, claim.AgentID).Scan(&agentStatus, &workspace, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return errNoAgent
	}
	if err != nil {
		return err
	}
	if agentStatus == "revoked" {
		return errAgentRevoked
	}
	if workspace != claim.Workspace || name != claim.AgentName {
		return errIdentityMismatch
	}
	var identityID string
	var ed, ml []byte
	var recipient string
	var current []byte
	err = tx.QueryRow(ctx, `
		SELECT id, ed25519_public_key, mldsa65_public_key, encryption_recipient, identity_statement_id
		FROM agent_identities WHERE agent_id = $1 AND revoked_at IS NULL FOR UPDATE`, claim.AgentID).
		Scan(&identityID, &ed, &ml, &recipient, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return errIdentityMismatch
	}
	if err != nil {
		return err
	}
	if (trust.AgentKeys{Ed25519: ed, MLDSA65: ml, Recipient: recipient}).Fingerprint() != claim.Keys().Fingerprint() {
		return errIdentityMismatch
	}
	// A statement is identified by the SHA-256 of its exact bytes.
	sum := sha256.Sum256(envelope)
	if current != nil {
		if string(current) == string(sum[:]) {
			return nil
		}
		return errHasIdentity
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO signed_statements (id, payload_type, envelope) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO NOTHING`, sum[:], string(statement.TypeAgentIdentity), envelope); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_identities SET identity_statement_id = $2, not_after = $3 WHERE id = $1`,
		identityID, sum[:], claim.NotAfter); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE agents SET status = 'approved' WHERE id = $1`, claim.AgentID)
	return err
}

type agentService struct {
	agentv1.UnimplementedAgentServiceServer
	s *Server
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
