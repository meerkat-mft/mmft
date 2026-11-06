package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/trust"
)

const (
	// TokenLifetime is how long an enrollment token works, from ADR 0011.
	TokenLifetime = time.Hour

	maxTokenBytes   = 256
	maxRequestBytes = 64 << 10
	uniqueViolation = "23505"
)

// errBadToken is the one answer for an unknown, used, expired, or mismatched
// token, so a caller learns nothing about which it was.
var errBadToken = status.Error(codes.PermissionDenied, "the enrollment token is not valid")

type tokenRequest struct {
	AgentName string `json:"agent_name"`
	Workspace string `json:"workspace"`
}

// createToken stores a new one-use token as a hash and returns it once. A
// workspace is created on first use, until workspaces get their own API. A
// token may name an existing agent, which then re-enrolls with its own keys.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := decodeStrict(r.Body, &req); err != nil || !trust.ValidName(req.AgentName) || !trust.ValidName(req.Workspace) {
		problem(w, http.StatusBadRequest, "agent_name and workspace must be names of 1 to 128 letters, digits, or . _ -.")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		problem(w, http.StatusInternalServerError, "Could not create a token.")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	expires := s.cfg.Now().Add(TokenLifetime).UTC()

	err := pgx.BeginFunc(r.Context(), s.cfg.DB, func(tx pgx.Tx) error {
		var workspaceID string
		err := tx.QueryRow(r.Context(), `
			INSERT INTO workspaces (name) VALUES ($1)
			ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			RETURNING id`, req.Workspace).Scan(&workspaceID)
		if err != nil {
			return err
		}
		// A token for an existing agent re-enrolls it with its own keys, so a
		// lost token or an expired certificate can be recovered. A revoked agent
		// can't come back this way.
		var revoked bool
		err = tx.QueryRow(r.Context(),
			`SELECT status = 'revoked' FROM agents WHERE workspace_id = $1 AND name = $2`,
			workspaceID, req.AgentName).Scan(&revoked)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if revoked {
			return errAgentRevoked
		}
		_, err = tx.Exec(r.Context(), `
			INSERT INTO enrollment_tokens (token_sha256, workspace_id, agent_name, expires_at)
			VALUES ($1, $2, $3, $4)`, sum[:], workspaceID, req.AgentName, expires)
		return err
	})
	switch {
	case errors.Is(err, errAgentRevoked):
		problem(w, http.StatusConflict, "The agent with this name is revoked.")
	case err != nil:
		problem(w, http.StatusInternalServerError, "Could not create a token.")
	default:
		writeJSON(w, http.StatusCreated, map[string]string{"token": token, "expires_at": expires.Format(time.RFC3339)})
	}
}

// decodeStrict reads one bounded JSON object and rejects unknown fields.
func decodeStrict(body io.Reader, v any) error {
	data, err := io.ReadAll(io.LimitReader(body, maxRequestBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxRequestBytes {
		return errors.New("request too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

type enrollment struct {
	agentv1.UnimplementedEnrollmentServiceServer
	s *Server
}

// reissue gives an existing agent a new connection certificate, for a retry
// after a lost response or a re-enrollment with a new token. The proof showed
// the caller holds the keys, so only the agent's current keys qualify, and
// only while neither the agent nor those keys are revoked. Anyone else is
// refused as for any used token.
func (e enrollment) reissue(ctx context.Context, tx pgx.Tx, agentID string, keys trust.AgentKeys, csr []byte, now time.Time, resp *agentv1.EnrollResponse) error {
	var agentStatus, recipient string
	var ed, ml []byte
	err := tx.QueryRow(ctx, `
		SELECT a.status, i.ed25519_public_key, i.mldsa65_public_key, i.encryption_recipient
		FROM agents a JOIN agent_identities i ON i.agent_id = a.id
		WHERE a.id = $1 AND i.revoked_at IS NULL ORDER BY i.id DESC LIMIT 1`, agentID).Scan(&agentStatus, &ed, &ml, &recipient)
	if errors.Is(err, pgx.ErrNoRows) {
		return errBadToken
	}
	if err != nil {
		return err
	}
	if agentStatus == "revoked" || !bytes.Equal(ed, keys.Ed25519) || !bytes.Equal(ml, keys.MLDSA65) || recipient != keys.Recipient {
		return errBadToken
	}
	cert, err := e.s.cfg.Authority.SignAgent(csr, agentID, now, e.s.cfg.ConnectionLifetime)
	if err != nil {
		return status.Error(codes.InvalidArgument, "the certificate request is invalid")
	}
	resp.AgentId, resp.ConnectionCertificate = agentID, cert
	return nil
}

// Enroll checks the proof of key possession, then claims the token, creates the
// agent as pending approval, and issues its first connection certificate, all in
// one transaction. A bad request never uses up a token. Within the token's
// lifetime, the agent that used it can repeat the call with the same keys. A
// new token for an existing agent re-enrolls it, but only with its own keys, so
// a lost token or an expired first certificate can be recovered without
// letting other keys take the agent's place.
func (e enrollment) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	keys := trust.AgentKeys{
		Ed25519:   req.GetEd25519PublicKey(),
		MLDSA65:   req.GetMldsa65PublicKey(),
		Recipient: req.GetEncryptionRecipient(),
	}
	if req.GetToken() == "" || len(req.GetToken()) > maxTokenBytes {
		return nil, errBadToken
	}
	if !trust.ValidName(req.GetAgentName()) || !trust.ValidName(req.GetWorkspace()) || keys.Validate() != nil || len(req.GetCertificateRequest()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "the agent name, workspace, keys, or certificate request are invalid")
	}
	// The agent ID is derived from the keys, so the orchestrator never chooses
	// it. See ADR 0019.
	agentID := keys.AgentID()
	if req.GetAgentId() != agentID {
		return nil, status.Error(codes.InvalidArgument, "the agent ID is not the one derived from the keys")
	}
	if err := trust.CheckEnrollment(req.GetProofStatement(), req.GetToken(), agentID, req.GetWorkspace(), req.GetAgentName(), keys, req.GetCertificateRequest()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "the enrollment proof does not match the request")
	}

	sum := sha256.Sum256([]byte(req.GetToken()))
	var resp agentv1.EnrollResponse
	err := pgx.BeginFunc(ctx, e.s.cfg.DB, func(tx pgx.Tx) error {
		var workspaceID, workspace, name string
		var expires time.Time
		var usedBy *string
		err := tx.QueryRow(ctx, `
			SELECT t.workspace_id, w.name, t.agent_name, t.expires_at, t.agent_id
			FROM enrollment_tokens t JOIN workspaces w ON w.id = t.workspace_id
			WHERE t.token_sha256 = $1 FOR UPDATE OF t`, sum[:]).
			Scan(&workspaceID, &workspace, &name, &expires, &usedBy)
		// Read the clock only once the row is locked, so a token that expires
		// while waiting for the lock is refused.
		now := e.s.cfg.Now()
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (name != req.GetAgentName() || workspace != req.GetWorkspace())) {
			return errBadToken
		}
		if err != nil {
			return err
		}
		if !now.Before(expires) {
			return errBadToken
		}
		if usedBy != nil {
			return e.reissue(ctx, tx, *usedBy, keys, req.GetCertificateRequest(), now, &resp)
		}
		var existing string
		err = tx.QueryRow(ctx, `SELECT id FROM agents WHERE workspace_id = $1 AND name = $2`, workspaceID, name).Scan(&existing)
		if err == nil {
			// Re-enrollment: the name is taken, so only the agent's own keys,
			// and so its own derived ID, may use the token.
			if existing != agentID {
				return errBadToken
			}
			if err := e.reissue(ctx, tx, existing, keys, req.GetCertificateRequest(), now, &resp); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE enrollment_tokens SET used_at = $2, agent_id = $3 WHERE token_sha256 = $1`, sum[:], now, existing)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO agents (id, workspace_id, name, status) VALUES ($1, $2, $3, 'pending_approval')`,
			agentID, workspaceID, name)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return status.Error(codes.AlreadyExists, "an agent with this name or these keys already exists")
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_identities (agent_id, ed25519_public_key, mldsa65_public_key, encryption_recipient)
			VALUES ($1, $2, $3, $4)`, agentID, keys.Ed25519, keys.MLDSA65, keys.Recipient); err != nil {
			return err
		}
		cert, err := e.s.cfg.Authority.SignAgent(req.GetCertificateRequest(), agentID, now, e.s.cfg.ConnectionLifetime)
		if err != nil {
			return status.Error(codes.InvalidArgument, "the certificate request is invalid")
		}
		if _, err := tx.Exec(ctx, `
			UPDATE enrollment_tokens SET used_at = $2, agent_id = $3 WHERE token_sha256 = $1`,
			sum[:], now, agentID); err != nil {
			return err
		}
		resp.AgentId, resp.ConnectionCertificate = agentID, cert
		return nil
	})
	if _, ok := status.FromError(err); ok && err != nil {
		return nil, err
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "enrollment failed")
	}
	return &resp, nil
}
