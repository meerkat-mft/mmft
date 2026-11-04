package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"filippo.io/age"

	"mmft.dev/mmft/internal/statement"
)

const (
	// MaxAgentLifetime is the longest agent identity ADR 0011 allows.
	MaxAgentLifetime = 365 * 24 * time.Hour

	maxRecipientBytes = 4096
	fingerprintTag    = "mmft-agent-fingerprint-v1\x00"
)

// Errors for agent enrollment and identities.
var (
	ErrInvalidAgentKeys  = errors.New("trust: invalid agent keys")
	ErrInvalidProof      = errors.New("trust: enrollment proof does not match the request")
	ErrWrongAgent        = errors.New("trust: agent does not match the expected fingerprint, ID, or name")
	ErrInvalidIdentity   = errors.New("trust: invalid agent identity")
	ErrAgentSharesKey    = errors.New("trust: agent key is shared with a trust root or administrator key")
	ErrWrongCertificate  = errors.New("trust: administrator certificate is not for this key")
	errUnverifiedPayload = errors.New("trust: unreadable payload")
)

var (
	idPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	namePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// ValidAgentID reports whether a string is an agent ID in its one form.
func ValidAgentID(id string) bool {
	return idPattern.MatchString(id)
}

// ValidName reports whether a string can name an agent or workspace.
func ValidName(name string) bool {
	return namePattern.MatchString(name)
}

// AgentKeys are an agent's public keys: two signing halves and the age hybrid
// recipient that sealed files are encrypted to.
type AgentKeys struct {
	Ed25519   []byte
	MLDSA65   []byte
	Recipient string
}

// Signing returns the validated signing key.
func (k AgentKeys) Signing() (statement.PublicKey, error) {
	key, err := statement.NewPublicKey(k.Ed25519, k.MLDSA65)
	if err != nil {
		return statement.PublicKey{}, ErrInvalidAgentKeys
	}
	return key, nil
}

// Validate checks every key, and requires a post-quantum hybrid recipient.
func (k AgentKeys) Validate() error {
	if _, err := k.Signing(); err != nil {
		return err
	}
	if len(k.Recipient) > maxRecipientBytes {
		return ErrInvalidAgentKeys
	}
	r, err := age.ParseHybridRecipient(k.Recipient)
	if err != nil || r.String() != k.Recipient {
		return ErrInvalidAgentKeys
	}
	return nil
}

// Fingerprint is the value an administrator compares with the host, as defined
// in ADR 0018. It covers the encryption recipient, so that a swapped recipient
// can't be signed. It is empty for invalid keys.
func (k AgentKeys) Fingerprint() string {
	if k.Validate() != nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(fingerprintTag))
	h.Write(k.Ed25519)
	h.Write(k.MLDSA65)
	// The recipient has a decimal length prefix, so no other split of the
	// input gives the same digest.
	h.Write([]byte(strconv.Itoa(len(k.Recipient)) + "\x00" + k.Recipient))
	return hex.EncodeToString(h.Sum(nil))
}

func (k AgentKeys) equal(o AgentKeys) bool {
	return bytes.Equal(k.Ed25519, o.Ed25519) && bytes.Equal(k.MLDSA65, o.MLDSA65) && k.Recipient == o.Recipient
}

// enrollmentClaim is the payload of an enrollment request statement.
type enrollmentClaim struct {
	Version     int    `json:"version"`
	TokenSHA256 []byte `json:"token_sha256"`
	AgentName   string `json:"agent_name"`
	Ed25519     []byte `json:"ed25519"`
	MLDSA65     []byte `json:"mldsa65"`
	Recipient   string `json:"encryption_recipient"`
	CSRSHA256   []byte `json:"csr_sha256"`
}

func newEnrollmentClaim(token, name string, keys AgentKeys, csr []byte) enrollmentClaim {
	tokenSum := sha256.Sum256([]byte(token))
	csrSum := sha256.Sum256(csr)
	return enrollmentClaim{
		Version:     formatVersion,
		TokenSHA256: tokenSum[:],
		AgentName:   name,
		Ed25519:     keys.Ed25519,
		MLDSA65:     keys.MLDSA65,
		Recipient:   keys.Recipient,
		CSRSHA256:   csrSum[:],
	}
}

// ProveEnrollment signs an enrollment request with the agent's own keys, which
// proves it holds them. The signer must be the agent's signing key.
func ProveEnrollment(agent *statement.Signer, token, name, recipient string, csr []byte) (*statement.Envelope, error) {
	ed, ml := agent.Public().Bytes()
	payload, err := json.Marshal(newEnrollmentClaim(token, name, AgentKeys{Ed25519: ed, MLDSA65: ml, Recipient: recipient}, csr))
	if err != nil {
		return nil, err
	}
	return statement.Sign(statement.TypeEnrollmentRequest, payload, agent)
}

// CheckEnrollment verifies a proof against the keys in the request itself, and
// requires every field of the proof to match the request.
func CheckEnrollment(proof []byte, token, name string, keys AgentKeys, csr []byte) error {
	if err := keys.Validate(); err != nil {
		return err
	}
	key, _ := keys.Signing()
	e, err := statement.Parse(proof)
	if err != nil {
		return ErrInvalidProof
	}
	trusted := []statement.Verifier{{Key: key, Role: statement.RoleAgent, Owner: "agent"}}
	got, err := statement.Verify(e, statement.TypeEnrollmentRequest, trusted, 1)
	if err != nil {
		return ErrInvalidProof
	}
	var claim enrollmentClaim
	if err := strictJSON(got.Payload, &claim); err != nil {
		return ErrInvalidProof
	}
	want := newEnrollmentClaim(token, name, keys, csr)
	if claim.Version != want.Version || claim.AgentName != want.AgentName ||
		!bytes.Equal(claim.TokenSHA256, want.TokenSHA256) || !bytes.Equal(claim.CSRSHA256, want.CSRSHA256) ||
		!(AgentKeys{Ed25519: claim.Ed25519, MLDSA65: claim.MLDSA65, Recipient: claim.Recipient}).equal(keys) {
		return ErrInvalidProof
	}
	return nil
}

// IdentityClaim is the payload of an agent identity statement. It embeds the
// signer's administrator certificate and the trust root's public key, so it
// verifies from a pinned root fingerprint alone.
type IdentityClaim struct {
	Version                  int             `json:"version"`
	AgentID                  string          `json:"agent_id"`
	Workspace                string          `json:"workspace"`
	AgentName                string          `json:"agent_name"`
	Ed25519                  []byte          `json:"ed25519"`
	MLDSA65                  []byte          `json:"mldsa65"`
	Recipient                string          `json:"encryption_recipient"`
	NotBefore                time.Time       `json:"not_before"`
	NotAfter                 time.Time       `json:"not_after"`
	RootEd25519              []byte          `json:"root_ed25519"`
	RootMLDSA65              []byte          `json:"root_mldsa65"`
	AdministratorCertificate json.RawMessage `json:"administrator_certificate"`
}

// Keys returns the agent's keys from the claim.
func (c IdentityClaim) Keys() AgentKeys {
	return AgentKeys{Ed25519: c.Ed25519, MLDSA65: c.MLDSA65, Recipient: c.Recipient}
}

// AgentRequest is what an administrator approves: the agent as the orchestrator
// reports it, and the values collected from the host.
type AgentRequest struct {
	AgentID   string
	Workspace string
	AgentName string
	Keys      AgentKeys
	// Expected values come from the host, never from the orchestrator.
	ExpectedFingerprint string
	ExpectedID          string
	ExpectedName        string
}

// CertifyAgent has an administrator sign an agent identity, only if the agent
// matches the fingerprint, ID, and name collected from the host. The
// administrator's certificate must verify against the pinned root and name the
// signing key.
func CertifyAgent(admin *statement.Signer, certificate []byte, root statement.PublicKey, pinnedRoot string, req AgentRequest, now time.Time, lifetime time.Duration) (*statement.Envelope, error) {
	adminV, _, err := VerifyAdministrator(certificate, root, pinnedRoot, now)
	if err != nil {
		return nil, err
	}
	if adminV.Key.Fingerprint() != admin.Public().Fingerprint() {
		return nil, ErrWrongCertificate
	}
	// The validity starts clockSkew in the past, so a shorter lifetime would
	// already be over when it is signed.
	if lifetime <= clockSkew || lifetime > MaxAgentLifetime {
		return nil, ErrBadLifetime
	}
	if !idPattern.MatchString(req.AgentID) || !ValidName(req.Workspace) || !ValidName(req.AgentName) {
		return nil, ErrInvalidIdentity
	}
	fp := req.Keys.Fingerprint()
	if fp == "" || req.ExpectedFingerprint == "" || fp != req.ExpectedFingerprint ||
		req.AgentID != req.ExpectedID || req.AgentName != req.ExpectedName {
		return nil, ErrWrongAgent
	}
	signing, _ := req.Keys.Signing()
	if sameHalf(signing, root) || sameHalf(signing, adminV.Key) {
		return nil, ErrAgentSharesKey
	}
	cert, err := compactJSON(certificate)
	if err != nil {
		return nil, err
	}
	rootEd, rootML := root.Bytes()
	notBefore := now.Add(-clockSkew).UTC()
	payload, err := json.Marshal(IdentityClaim{
		Version:                  formatVersion,
		AgentID:                  req.AgentID,
		Workspace:                req.Workspace,
		AgentName:                req.AgentName,
		Ed25519:                  req.Keys.Ed25519,
		MLDSA65:                  req.Keys.MLDSA65,
		Recipient:                req.Keys.Recipient,
		NotBefore:                notBefore,
		NotAfter:                 notBefore.Add(lifetime),
		RootEd25519:              rootEd,
		RootMLDSA65:              rootML,
		AdministratorCertificate: cert,
	})
	if err != nil {
		return nil, err
	}
	return statement.Sign(statement.TypeAgentIdentity, payload, admin)
}

func compactJSON(data []byte) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return nil, ErrInvalidClaim
	}
	return buf.Bytes(), nil
}

// VerifyAgent checks an identity statement back to the pinned root: the
// embedded root key must match the pin, the administrator certificate must
// verify against it, and the identity against the administrator's key. It
// returns the claim and a verifier for the agent's signing key.
func VerifyAgent(identity []byte, pinnedRoot string, now time.Time) (IdentityClaim, statement.Verifier, error) {
	claim, v, _, err := verifyAgent(identity, pinnedRoot, now)
	return claim, v, err
}

// verifyAgent is VerifyAgent, and also returns the statement's ID.
func verifyAgent(identity []byte, pinnedRoot string, now time.Time) (IdentityClaim, statement.Verifier, string, error) {
	fail := func(err error) (IdentityClaim, statement.Verifier, string, error) {
		return IdentityClaim{}, statement.Verifier{}, "", err
	}
	e, err := statement.Parse(identity)
	if err != nil {
		return fail(err)
	}
	if e.PayloadType != string(statement.TypeAgentIdentity) {
		return fail(statement.ErrWrongType)
	}
	// The chain is read from the unverified payload, and trusted only once the
	// root matches the pin and each signature verifies.
	unverified, err := unverifiedClaim(e)
	if err != nil {
		return fail(ErrInvalidIdentity)
	}
	root, err := statement.NewPublicKey(unverified.RootEd25519, unverified.RootMLDSA65)
	if err != nil {
		return fail(ErrInvalidIdentity)
	}
	adminV, _, err := VerifyAdministrator(unverified.AdministratorCertificate, root, pinnedRoot, now)
	if err != nil {
		return fail(err)
	}
	got, err := statement.Verify(e, statement.TypeAgentIdentity, []statement.Verifier{adminV}, 1)
	if err != nil {
		return fail(err)
	}
	var claim IdentityClaim
	if err := strictJSON(got.Payload, &claim); err != nil {
		return fail(ErrInvalidIdentity)
	}
	if claim.Version != formatVersion || !idPattern.MatchString(claim.AgentID) ||
		!ValidName(claim.Workspace) || !ValidName(claim.AgentName) || !claim.NotAfter.After(claim.NotBefore) ||
		claim.NotAfter.Sub(claim.NotBefore) > MaxAgentLifetime || claim.Keys().Validate() != nil {
		return fail(ErrInvalidIdentity)
	}
	signing, _ := claim.Keys().Signing()
	if sameHalf(signing, root) || sameHalf(signing, adminV.Key) {
		return fail(ErrAgentSharesKey)
	}
	if now.Before(claim.NotBefore) {
		return fail(ErrNotYetValid)
	}
	if !now.Before(claim.NotAfter) {
		return fail(ErrExpired)
	}
	return claim, statement.Verifier{Key: signing, Role: statement.RoleAgent, Owner: claim.AgentID}, got.ID, nil
}

// CheckIdentity verifies an identity statement against the root key embedded
// in it, and returns the claim and the statement's ID, which doesn't depend on
// its signatures or formatting. The orchestrator uses it to refuse a malformed
// identity before storing it. It proves nothing about trust, because the
// orchestrator pins no root, so agents always verify with VerifyAgent.
func CheckIdentity(identity []byte, now time.Time) (IdentityClaim, string, error) {
	e, err := statement.Parse(identity)
	if err != nil {
		return IdentityClaim{}, "", ErrInvalidIdentity
	}
	unverified, err := unverifiedClaim(e)
	if err != nil {
		return IdentityClaim{}, "", ErrInvalidIdentity
	}
	root, err := statement.NewPublicKey(unverified.RootEd25519, unverified.RootMLDSA65)
	if err != nil {
		return IdentityClaim{}, "", ErrInvalidIdentity
	}
	claim, _, id, err := verifyAgent(identity, root.Fingerprint(), now)
	return claim, id, err
}

func unverifiedClaim(e *statement.Envelope) (IdentityClaim, error) {
	payload, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil || len(payload) > statement.MaxPayloadBytes {
		return IdentityClaim{}, errUnverifiedPayload
	}
	var claim IdentityClaim
	if err := strictJSON(payload, &claim); err != nil {
		return IdentityClaim{}, errUnverifiedPayload
	}
	return claim, nil
}
