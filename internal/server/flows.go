package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"mmft.dev/mmft/internal/flow"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// maxFlowRequestBytes bounds a draft or an approval. A payload may be up to
// statement.MaxPayloadBytes, and an approval carries it base64 encoded with
// its certificates.
const maxFlowRequestBytes = 2 << 20

var (
	errNoFlow          = apiError{http.StatusNotFound, "No such flow."}
	errNoFlowVersion   = apiError{http.StatusNotFound, "No such flow version."}
	errFlowAgents      = apiError{http.StatusBadRequest, "Every agent a flow names must be approved and in the flow's workspace."}
	errApprovalPayload = apiError{http.StatusBadRequest, "The approval signs a different payload than this version."}
	errSuperseded      = apiError{http.StatusConflict, "A newer version is already approved."}
	errRetired         = apiError{http.StatusConflict, "The flow is retired."}
	errRetirementFlow  = apiError{http.StatusBadRequest, "The retirement names another flow or workspace."}
)

type flowItem struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Workspace       string `json:"workspace"`
	ApprovedVersion *int   `json:"approved_version,omitempty"`
	LatestVersion   *int   `json:"latest_version,omitempty"`
	Retired         bool   `json:"retired"`
}

// flowSelect reads a flow with its approved and latest version numbers, for
// scanFlow.
const flowSelect = `
		SELECT f.id, f.name, w.name,
		       (SELECT version FROM flow_versions WHERE flow_id = f.id AND status = 'approved'),
		       (SELECT max(version) FROM flow_versions WHERE flow_id = f.id),
		       f.retired_at IS NOT NULL
		FROM flows f
		JOIN workspaces w ON w.id = f.workspace_id`

func scanFlow(row pgx.Row) (flowItem, error) {
	var item flowItem
	err := row.Scan(&item.ID, &item.Name, &item.Workspace, &item.ApprovedVersion, &item.LatestVersion, &item.Retired)
	return item, err
}

// createFlow creates an empty flow in an existing workspace. It runs nothing
// until a version is saved and approved.
func (s *Server) createFlow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Workspace string `json:"workspace"`
	}
	if err := decodeStrict(r.Body, &req); err != nil || !trust.ValidName(req.Name) || !trust.ValidName(req.Workspace) {
		problem(w, http.StatusBadRequest, "name and workspace must each be 1 to 128 letters, digits, dots, hyphens, or underscores.")
		return
	}
	ctx := r.Context()
	var id string
	err := s.cfg.DB.QueryRow(ctx, `
		INSERT INTO flows (workspace_id, name)
		SELECT id, $2 FROM workspaces WHERE name = $1
		RETURNING id`, req.Workspace, req.Name).Scan(&id)
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		problem(w, http.StatusBadRequest, "No such workspace.")
		return
	case errors.As(err, &pgErr) && pgErr.Code == uniqueViolation:
		problem(w, http.StatusConflict, "The workspace already has a flow with this name.")
		return
	case err != nil:
		problem(w, http.StatusInternalServerError, "Could not create the flow.")
		return
	}
	writeJSON(w, http.StatusCreated, flowItem{ID: id, Name: req.Name, Workspace: req.Workspace})
}

// listFlows returns a page of flows in ID order. The cursor is the last ID of
// the previous page.
func (s *Server) listFlows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var cursor *string
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
	rows, err := s.cfg.DB.Query(r.Context(), flowSelect+`
		WHERE ($1::uuid IS NULL OR f.id > $1::uuid)
		ORDER BY f.id
		LIMIT $2`, cursor, limit+1)
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not list flows.")
		return
	}
	items := []flowItem{}
	for rows.Next() {
		item, err := scanFlow(rows)
		if err != nil {
			rows.Close()
			problem(w, http.StatusInternalServerError, "Could not list flows.")
			return
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		problem(w, http.StatusInternalServerError, "Could not list flows.")
		return
	}
	page := map[string]any{"items": items}
	if len(items) > limit {
		page["items"] = items[:limit]
		page["next_cursor"] = items[limit-1].ID
	}
	writeJSON(w, http.StatusOK, page)
}

// getFlow returns one flow, in the same form as the listing.
func (s *Server) getFlow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("flow_id")
	if !trust.ValidAgentID(id) {
		problem(w, errNoFlow.code, errNoFlow.title)
		return
	}
	item, err := scanFlow(s.cfg.DB.QueryRow(r.Context(), flowSelect+` WHERE f.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, errNoFlow.code, errNoFlow.title)
		return
	}
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not read the flow.")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// definition is a flow's tree of cards as the API takes and returns it. The
// orchestrator adds the rest of the payload.
type definition struct {
	SchemaVersion int         `json:"schema_version"`
	Cards         []flow.Card `json:"cards"`
}

type flowVersionItem struct {
	FlowID     string     `json:"flow_id"`
	Version    int        `json:"version"`
	Status     string     `json:"status"`
	Definition definition `json:"definition"`
	// Payload is the exact bytes an administrator approves, base64 encoded.
	Payload       []byte          `json:"payload"`
	PayloadSHA256 string          `json:"payload_sha256"`
	Approval      json.RawMessage `json:"approval,omitempty"`
}

func newFlowVersionItem(flowID string, version int, status string, payload, approval []byte) (flowVersionItem, error) {
	parsed, err := flow.Parse(payload)
	if err != nil {
		return flowVersionItem{}, err
	}
	sum := sha256.Sum256(payload)
	return flowVersionItem{
		FlowID: flowID, Version: version, Status: status,
		Definition: definition{SchemaVersion: flow.PayloadVersion, Cards: parsed.Cards},
		Payload:    payload, PayloadSHA256: hex.EncodeToString(sum[:]), Approval: approval,
	}, nil
}

// createFlowVersion saves a draft as the flow's next version. The orchestrator
// builds the payload from the cards and checks it with the same package the
// CLI and agents use, so a stored draft is always a valid flow version.
func (s *Server) createFlowVersion(w http.ResponseWriter, r *http.Request) {
	flowID := r.PathValue("flow_id")
	if !trust.ValidAgentID(flowID) {
		problem(w, errNoFlow.code, errNoFlow.title)
		return
	}
	var req definition
	if err := decodeStrictLimit(r.Body, maxFlowRequestBytes, &req); err != nil || req.SchemaVersion != flow.PayloadVersion {
		problem(w, http.StatusBadRequest, "The body must be a flow definition with schema_version 1 and its cards.")
		return
	}
	ctx := r.Context()
	var item flowVersionItem
	err := pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		var workspaceID, workspace string
		var retired bool
		err := tx.QueryRow(ctx, `
			SELECT f.workspace_id, w.name, f.retired_at IS NOT NULL FROM flows f JOIN workspaces w ON w.id = f.workspace_id
			WHERE f.id = $1 FOR UPDATE OF f`, flowID).Scan(&workspaceID, &workspace, &retired)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoFlow
		}
		if err != nil {
			return err
		}
		if retired {
			return errRetired
		}
		var next int
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) + 1 FROM flow_versions WHERE flow_id = $1`, flowID).Scan(&next); err != nil {
			return err
		}
		payload, err := buildPayload(flowID, workspace, next, req.Cards)
		if err != nil {
			return err
		}
		if err := checkFlowAgents(ctx, tx, workspaceID, payload); err != nil {
			return err
		}
		sum := sha256.Sum256(payload)
		if _, err := tx.Exec(ctx, `
			INSERT INTO flow_versions (flow_id, version, payload, payload_sha256, status)
			VALUES ($1, $2, $3, $4, 'draft')`, flowID, next, payload, sum[:]); err != nil {
			return err
		}
		item, err = newFlowVersionItem(flowID, next, "draft", payload, nil)
		return err
	})
	var apiErr apiError
	switch {
	case errors.As(err, &apiErr):
		problem(w, apiErr.code, apiErr.title)
	case err != nil:
		problem(w, http.StatusInternalServerError, "Could not save the flow version.")
	default:
		writeJSON(w, http.StatusCreated, item)
	}
}

// buildPayload makes the payload of a flow version from its cards, and refuses
// one that internal/flow rejects, with its reason.
func buildPayload(flowID, workspace string, version int, cards []flow.Card) ([]byte, error) {
	agents := make([]string, 0, len(cards))
	for _, c := range cards {
		agents = append(agents, c.Agent)
	}
	slices.Sort(agents)
	payload, err := json.Marshal(flow.Version{
		Version: flow.PayloadVersion, FlowID: flowID, Workspace: workspace, FlowVersion: int64(version),
		Agents: slices.Compact(agents), Cards: cards,
	})
	if err != nil {
		return nil, err
	}
	if _, err := flow.Parse(payload); err != nil {
		var fe *flow.Error
		if errors.As(err, &fe) {
			return nil, apiError{http.StatusBadRequest, "The flow is invalid: " + strings.TrimPrefix(err.Error(), "flow: ")}
		}
		return nil, err
	}
	return payload, nil
}

// checkFlowAgents requires every agent the payload names to be approved and in
// the flow's workspace, as manual runs do (ADR 0021).
func checkFlowAgents(ctx context.Context, tx pgx.Tx, workspaceID string, payload []byte) error {
	parsed, err := flow.Parse(payload)
	if err != nil {
		return err
	}
	var found int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM agents WHERE id = ANY($1::uuid[]) AND workspace_id = $2 AND status = 'approved'`,
		parsed.Agents, workspaceID).Scan(&found); err != nil {
		return err
	}
	if found != len(parsed.Agents) {
		return errFlowAgents
	}
	return nil
}

// flowVersionPath reads the flow ID and version number from the path.
func flowVersionPath(r *http.Request) (string, int, bool) {
	flowID := r.PathValue("flow_id")
	version, err := strconv.Atoi(r.PathValue("version"))
	return flowID, version, trust.ValidAgentID(flowID) && err == nil && version >= 1
}

func (s *Server) getFlowVersion(w http.ResponseWriter, r *http.Request) {
	flowID, version, ok := flowVersionPath(r)
	if !ok {
		problem(w, errNoFlowVersion.code, errNoFlowVersion.title)
		return
	}
	var status string
	var payload, approval []byte
	err := s.cfg.DB.QueryRow(r.Context(), `
		SELECT status, payload, approval FROM flow_versions WHERE flow_id = $1 AND version = $2`,
		flowID, version).Scan(&status, &payload, &approval)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, errNoFlowVersion.code, errNoFlowVersion.title)
		return
	}
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not read the flow version.")
		return
	}
	item, err := newFlowVersionItem(flowID, version, status, payload, approval)
	if err != nil {
		problem(w, http.StatusInternalServerError, "Could not read the flow version.")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// putFlowApproval stores an approval signed in the CLI. The orchestrator pins
// no root, so it can't judge whether to trust the approval. It refuses one
// that doesn't verify against the certificates and root it carries, or that
// signs anything but this version's exact payload (ADR 0023). Agents check
// the root and the number of approvers. Approving an approved version again
// changes nothing.
func (s *Server) putFlowApproval(w http.ResponseWriter, r *http.Request) {
	flowID, version, ok := flowVersionPath(r)
	if !ok {
		problem(w, errNoFlowVersion.code, errNoFlowVersion.title)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFlowRequestBytes+1))
	if err != nil || len(body) > maxFlowRequestBytes {
		problem(w, http.StatusBadRequest, "The approval is invalid.")
		return
	}
	got, err := trust.CheckApproval(body, statement.TypeFlowVersion, s.cfg.Now())
	if err != nil {
		problem(w, http.StatusBadRequest, "The approval is invalid.")
		return
	}
	var approval trust.Approval
	statementID, idErr := hex.DecodeString(got.ID)
	if err := json.Unmarshal(body, &approval); err != nil || idErr != nil || len(statementID) != sha256.Size {
		problem(w, http.StatusInternalServerError, "Could not store the approval.")
		return
	}
	ctx := r.Context()
	err = pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		return storeApproval(ctx, tx, flowID, version, got.Payload, statementID, approval.Statement, body, s.cfg.Now())
	})
	var apiErr apiError
	switch {
	case errors.As(err, &apiErr):
		problem(w, apiErr.code, apiErr.title)
	case err != nil:
		problem(w, http.StatusInternalServerError, "Could not store the approval.")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// storeApproval approves a draft whose payload the approval signs, and
// supersedes every older version of the flow.
func storeApproval(ctx context.Context, tx pgx.Tx, flowID string, version int, signed, statementID, envelope, approval []byte, now time.Time) error {
	// Locking the flow keeps two approvals, or an approval and a retirement,
	// from interleaving.
	var retired bool
	if err := tx.QueryRow(ctx, `SELECT retired_at IS NOT NULL FROM flows WHERE id = $1 FOR UPDATE`, flowID).Scan(&retired); errors.Is(err, pgx.ErrNoRows) {
		return errNoFlowVersion
	} else if err != nil {
		return err
	}
	if retired {
		return errRetired
	}
	var status string
	var payload []byte
	err := tx.QueryRow(ctx, `
		SELECT status, payload FROM flow_versions WHERE flow_id = $1 AND version = $2`,
		flowID, version).Scan(&status, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return errNoFlowVersion
	}
	if err != nil {
		return err
	}
	// The approval must be for exactly the bytes this version holds.
	if !bytes.Equal(signed, payload) {
		return errApprovalPayload
	}
	switch status {
	case "approved":
		// A statement's ID covers only its type and payload (ADR 0015), so any
		// approval of these bytes is the statement already stored. The first
		// approval received is kept.
		return nil
	case "superseded":
		return errSuperseded
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO signed_statements (id, payload_type, envelope) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO NOTHING`, statementID, string(statement.TypeFlowVersion), envelope); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE flow_versions SET status = 'superseded'
		WHERE flow_id = $1 AND version < $2 AND status IN ('draft', 'approved')`, flowID, version); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE flow_versions SET status = 'approved', approval = $3, approval_statement_id = $4, approved_at = $5
		WHERE flow_id = $1 AND version = $2`, flowID, version, approval, statementID, now)
	return err
}

// putFlowRetirement stores a retirement signed in the CLI, in the same form as
// an approval (ADR 0023, ADR 0024). Like an approval, it is checked only for
// consistency, and agents decide whether it is trusted. A retired flow takes
// no new drafts or approvals. Retiring a retired flow again changes nothing.
func (s *Server) putFlowRetirement(w http.ResponseWriter, r *http.Request) {
	flowID := r.PathValue("flow_id")
	if !trust.ValidAgentID(flowID) {
		problem(w, errNoFlow.code, errNoFlow.title)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFlowRequestBytes+1))
	if err != nil || len(body) > maxFlowRequestBytes {
		problem(w, http.StatusBadRequest, "The retirement is invalid.")
		return
	}
	got, err := trust.CheckApproval(body, statement.TypeFlowRetirement, s.cfg.Now())
	if err != nil {
		problem(w, http.StatusBadRequest, "The retirement is invalid.")
		return
	}
	retirement, err := flow.ParseRetirement(got.Payload)
	if err != nil {
		problem(w, http.StatusBadRequest, "The retirement is invalid.")
		return
	}
	var bundle trust.Approval
	statementID, idErr := hex.DecodeString(got.ID)
	if err := json.Unmarshal(body, &bundle); err != nil || idErr != nil || len(statementID) != sha256.Size {
		problem(w, http.StatusInternalServerError, "Could not store the retirement.")
		return
	}
	ctx := r.Context()
	err = pgx.BeginFunc(ctx, s.cfg.DB, func(tx pgx.Tx) error {
		var workspace string
		var retired bool
		err := tx.QueryRow(ctx, `
			SELECT w.name, f.retired_at IS NOT NULL FROM flows f JOIN workspaces w ON w.id = f.workspace_id
			WHERE f.id = $1 FOR UPDATE OF f`, flowID).Scan(&workspace, &retired)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoFlow
		}
		if err != nil {
			return err
		}
		if retirement.FlowID != flowID || retirement.Workspace != workspace {
			return errRetirementFlow
		}
		// The payload names only the flow and its workspace, so any retirement
		// of this flow is the statement already stored.
		if retired {
			return nil
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO signed_statements (id, payload_type, envelope) VALUES ($1, $2, $3)
			ON CONFLICT (id) DO NOTHING`, statementID, string(statement.TypeFlowRetirement), []byte(bundle.Statement)); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			UPDATE flows SET retirement = $2, retirement_statement_id = $3, retired_at = $4 WHERE id = $1`,
			flowID, body, statementID, s.cfg.Now())
		return err
	})
	var apiErr apiError
	switch {
	case errors.As(err, &apiErr):
		problem(w, apiErr.code, apiErr.title)
	case err != nil:
		problem(w, http.StatusInternalServerError, "Could not store the retirement.")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
