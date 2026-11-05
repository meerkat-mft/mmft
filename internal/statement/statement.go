// Package statement creates and verifies signed statements, as defined in ADR
// 0012 and ADR 0015. A statement is a DSSE envelope, and a signer counts only if
// both its Ed25519 and ML-DSA-65 signatures verify.
//
// Callers must use only the values returned by Verify. Envelope fields are
// untrusted until then, and the identity of a statement is Verified.ID, never a
// hash of the envelope, because signatures can be reordered or added.
package statement

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"filippo.io/edwards25519"
)

// Limits on untrusted input. Four approvers use eight signatures.
const (
	MaxPayloadBytes  = 1 << 20
	MaxSignatures    = 8
	maxEnvelopeBytes = 3 << 19
)

var (
	maxPayloadEncoded = base64.StdEncoding.EncodedLen(MaxPayloadBytes)
	maxSigEncoded     = base64.StdEncoding.EncodedLen(mldsa.MLDSA65SignatureSize)
)

// Errors returned by this package.
var (
	ErrMalformed        = errors.New("statement: malformed envelope")
	ErrTooLarge         = errors.New("statement: envelope exceeds limits")
	ErrWrongType        = errors.New("statement: unexpected payload type")
	ErrUnknownType      = errors.New("statement: unknown payload type")
	ErrRoleNotAllowed   = errors.New("statement: role may not sign this type")
	ErrNotEnoughSigners = errors.New("statement: not enough valid signers")
	ErrInvalidKey       = errors.New("statement: invalid key")
	ErrInvalidThreshold = errors.New("statement: required signers must be at least one")
)

// Type is a versioned payload type.
type Type string

// Statement types.
const (
	TypeRootRollover        Type = "application/vnd.mmft.root-rollover+json;v=1"
	TypeAdministratorKey    Type = "application/vnd.mmft.administrator-key+json;v=1"
	TypeAdministratorRevoke Type = "application/vnd.mmft.administrator-revocation+json;v=1"
	TypeFlowVersion         Type = "application/vnd.mmft.flow-version+json;v=1"
	TypeFlowRetirement      Type = "application/vnd.mmft.flow-retirement+json;v=1"
	TypeAutomationKey       Type = "application/vnd.mmft.automation-key+json;v=1"
	TypeCheckpointKey       Type = "application/vnd.mmft.audit-checkpoint-key+json;v=1"
	TypeAgentIdentity       Type = "application/vnd.mmft.agent-identity+json;v=1"
	TypeRevocation          Type = "application/vnd.mmft.revocation+json;v=1"
	TypeDeliveryManifest    Type = "application/vnd.mmft.delivery-manifest+json;v=1"
	TypeDeliveryReceipt     Type = "application/vnd.mmft.delivery-receipt+json;v=1"
	TypeAuditBatch          Type = "application/vnd.mmft.audit-batch+json;v=1"
	TypeAuditCheckpoint     Type = "application/vnd.mmft.audit-checkpoint+json;v=1"
	TypeEnrollmentRequest   Type = "application/vnd.mmft.enrollment-request+json;v=1"
)

// Role is what a key is trusted to do.
type Role uint8

// Key roles.
const (
	RoleRoot Role = iota + 1
	RoleAdministrator
	RoleAutomation
	RoleAgent
	RoleCheckpoint
)

// allowedRoles is the signer table from ADR 0012, plus the enrollment request
// from ADR 0019.
var allowedRoles = map[Type][]Role{
	TypeRootRollover:        {RoleRoot},
	TypeAdministratorKey:    {RoleRoot},
	TypeAdministratorRevoke: {RoleRoot},
	TypeFlowVersion:         {RoleAdministrator},
	TypeFlowRetirement:      {RoleAdministrator},
	TypeAutomationKey:       {RoleAdministrator},
	TypeCheckpointKey:       {RoleAdministrator},
	TypeAgentIdentity:       {RoleAdministrator, RoleAutomation},
	TypeRevocation:          {RoleAdministrator},
	TypeDeliveryManifest:    {RoleAgent},
	TypeDeliveryReceipt:     {RoleAgent},
	TypeAuditBatch:          {RoleAgent},
	TypeAuditCheckpoint:     {RoleCheckpoint},
	TypeEnrollmentRequest:   {RoleAgent},
}

func roleAllowed(t Type, r Role) (bool, error) {
	roles, ok := allowedRoles[t]
	if !ok {
		return false, ErrUnknownType
	}
	for _, allowed := range roles {
		if allowed == r {
			return true, nil
		}
	}
	return false, nil
}

// PublicKey is a hybrid public key.
type PublicKey struct {
	ed ed25519.PublicKey
	ml *mldsa.PublicKey
}

// NewPublicKey validates and builds a public key from its encoded parts. It
// rejects small-order Ed25519 keys, for which one forged signature verifies on
// any message, because they would silently remove the hybrid property.
func NewPublicKey(ed, ml []byte) (PublicKey, error) {
	if len(ed) != ed25519.PublicKeySize {
		return PublicKey{}, ErrInvalidKey
	}
	p, err := new(edwards25519.Point).SetBytes(ed)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	if p.MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return PublicKey{}, fmt.Errorf("%w: small-order Ed25519 key", ErrInvalidKey)
	}
	k, err := mldsa.NewPublicKey(mldsa.MLDSA65(), ml)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return PublicKey{ed: bytes.Clone(ed), ml: k}, nil
}

func (k PublicKey) valid() bool {
	return k.ed != nil && k.ml != nil
}

// Bytes returns the encoded Ed25519 and ML-DSA-65 public keys.
func (k PublicKey) Bytes() (ed, ml []byte) {
	if !k.valid() {
		return nil, nil
	}
	return bytes.Clone(k.ed), k.ml.Bytes()
}

// Fingerprint returns a stable hex digest of both public keys, or an empty
// string for the zero value.
func (k PublicKey) Fingerprint() string {
	if !k.valid() {
		return ""
	}
	h := sha256.New()
	h.Write([]byte("mmft-public-key-v1\x00"))
	h.Write(k.ed)
	h.Write(k.ml.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}

// Signer holds a hybrid private key and its role.
type Signer struct {
	ed   ed25519.PrivateKey
	ml   *mldsa.PrivateKey
	role Role
}

// GenerateSigner creates a new hybrid key for a role.
func GenerateSigner(role Role) (*Signer, error) {
	edSeed := make([]byte, ed25519.SeedSize)
	mlSeed := make([]byte, mldsa.PrivateKeySize)
	if _, err := rand.Read(edSeed); err != nil {
		return nil, err
	}
	if _, err := rand.Read(mlSeed); err != nil {
		return nil, err
	}
	return NewSigner(role, edSeed, mlSeed)
}

// NewSigner rebuilds a hybrid key from its seeds.
func NewSigner(role Role, edSeed, mlSeed []byte) (*Signer, error) {
	if len(edSeed) != ed25519.SeedSize {
		return nil, ErrInvalidKey
	}
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), mlSeed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return &Signer{ed: ed25519.NewKeyFromSeed(edSeed), ml: ml, role: role}, nil
}

// Seeds returns copies of the private seeds, for encrypted storage.
func (s *Signer) Seeds() (edSeed, mlSeed []byte) {
	return bytes.Clone(s.ed.Seed()), s.ml.Bytes()
}

// Role returns the signer's role.
func (s *Signer) Role() Role {
	return s.role
}

// Public returns the signer's public key.
func (s *Signer) Public() PublicKey {
	pub, ok := s.ed.Public().(ed25519.PublicKey)
	if !ok {
		panic("statement: unexpected Ed25519 public key type")
	}
	return PublicKey{ed: pub, ml: s.ml.PublicKey()}
}

// Verifier is a trusted public key. Owner names the person, pipeline, or agent
// that controls it. Thresholds count distinct owners, so one administrator's old
// and new keys count once.
type Verifier struct {
	Key   PublicKey
	Role  Role
	Owner string
}

// Verified is the result of a successful Verify.
type Verified struct {
	Payload []byte
	// Signers lists every trusted key that signed. Callers must use this for
	// scope checks, such as an automation key's workspace.
	Signers []Verifier
	// ID identifies the statement, independent of its signatures.
	ID string
}

// Signature is one DSSE signature. Keyid is an untrusted hint and is ignored.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// Envelope is a DSSE JSON envelope.
type Envelope struct {
	Payload     string      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// pae is the DSSE pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	out := make([]byte, 0, len(payloadType)+len(payload)+32)
	out = append(out, "DSSEv1 "...)
	out = strconv.AppendInt(out, int64(len(payloadType)), 10)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = strconv.AppendInt(out, int64(len(payload)), 10)
	out = append(out, ' ')
	return append(out, payload...)
}

// decode is standard padded base64 with one valid form for any value. Go's
// strict mode still skips line breaks, so they are rejected here.
func decode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, ErrMalformed
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrMalformed
	}
	return b, nil
}

func decodePayload(s string) ([]byte, error) {
	if len(s) > maxPayloadEncoded {
		return nil, ErrTooLarge
	}
	b, err := decode(s)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxPayloadBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}

// Sign creates an envelope signed by one signer.
func Sign(t Type, payload []byte, s *Signer) (*Envelope, error) {
	if len(payload) > MaxPayloadBytes {
		return nil, ErrTooLarge
	}
	e := &Envelope{Payload: base64.StdEncoding.EncodeToString(payload), PayloadType: string(t)}
	if err := Countersign(e, s); err != nil {
		return nil, err
	}
	return e, nil
}

// Countersign adds a signer to an envelope, for example a second approver. It
// signs the envelope's own payload, so callers must have verified it first.
func Countersign(e *Envelope, s *Signer) error {
	if e == nil {
		return ErrMalformed
	}
	if s == nil {
		return ErrInvalidKey
	}
	ok, err := roleAllowed(Type(e.PayloadType), s.role)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRoleNotAllowed
	}
	if len(e.Signatures)+2 > MaxSignatures {
		return ErrTooLarge
	}
	payload, err := decodePayload(e.Payload)
	if err != nil {
		return err
	}
	msg := pae(e.PayloadType, payload)
	mlSig, err := s.ml.Sign(rand.Reader, msg, &mldsa.Options{})
	if err != nil {
		return err
	}
	e.Signatures = append(e.Signatures,
		Signature{Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(s.ed, msg))},
		Signature{Sig: base64.StdEncoding.EncodeToString(mlSig)},
	)
	return nil
}

// Parse decodes an envelope from untrusted bytes, and proves nothing about who
// signed it. It reads tokens rather than using encoding/json's struct decoding,
// which accepts duplicate and differently cased keys that another reader could
// interpret differently. Unknown fields are ignored, as DSSE requires.
func Parse(data []byte) (*Envelope, error) {
	if len(data) > maxEnvelopeBytes {
		return nil, ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	var e Envelope
	seen := map[string]bool{}
	for dec.More() {
		key, err := readKey(dec, seen, "payload", "payloadType", "signatures")
		if err != nil {
			return nil, err
		}
		switch key {
		case "payload":
			e.Payload, err = readString(dec)
		case "payloadType":
			e.PayloadType, err = readString(dec)
		case "signatures":
			e.Signatures, err = readSignatures(dec)
		default:
			err = skipValue(dec)
		}
		if err != nil {
			return nil, err
		}
	}
	if !seen["payload"] || !seen["payloadType"] || !seen["signatures"] {
		return nil, ErrMalformed
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrMalformed
	}
	return &e, nil
}

func readSignatures(dec *json.Decoder) ([]Signature, error) {
	if err := expectDelim(dec, '['); err != nil {
		return nil, err
	}
	sigs := []Signature{}
	for dec.More() {
		if len(sigs) == MaxSignatures {
			return nil, ErrTooLarge
		}
		if err := expectDelim(dec, '{'); err != nil {
			return nil, err
		}
		var s Signature
		seen := map[string]bool{}
		for dec.More() {
			key, err := readKey(dec, seen, "keyid", "sig")
			if err != nil {
				return nil, err
			}
			switch key {
			case "keyid":
				s.KeyID, err = readString(dec)
			case "sig":
				s.Sig, err = readString(dec)
			default:
				err = skipValue(dec)
			}
			if err != nil {
				return nil, err
			}
		}
		if !seen["sig"] {
			return nil, ErrMalformed
		}
		if err := expectDelim(dec, '}'); err != nil {
			return nil, err
		}
		sigs = append(sigs, s)
	}
	if err := expectDelim(dec, ']'); err != nil {
		return nil, err
	}
	return sigs, nil
}

// readKey returns the next object key, and rejects a repeat of a known key or a
// differently cased form of one.
func readKey(dec *json.Decoder, seen map[string]bool, known ...string) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", ErrMalformed
	}
	key, ok := tok.(string)
	if !ok {
		return "", ErrMalformed
	}
	for _, k := range known {
		if !strings.EqualFold(key, k) {
			continue
		}
		if key != k || seen[k] {
			return "", ErrMalformed
		}
		seen[k] = true
	}
	return key, nil
}

func readString(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", ErrMalformed
	}
	s, ok := tok.(string)
	if !ok {
		return "", ErrMalformed
	}
	return s, nil
}

func skipValue(dec *json.Decoder) error {
	var skip json.RawMessage
	if err := dec.Decode(&skip); err != nil {
		return ErrMalformed
	}
	return nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return ErrMalformed
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return ErrMalformed
	}
	return nil
}

// checkTrusted rejects a trusted set that could count one key twice, and returns
// each usable key once. Cost grows with the size of the set, so callers should
// pass only keys that could have signed, never a whole fleet.
func checkTrusted(want Type, trusted []Verifier) ([]Verifier, error) {
	byFingerprint := map[string]Verifier{}
	byEd := map[string]string{}
	byML := map[string]string{}
	var usable []Verifier
	for _, v := range trusted {
		ok, err := roleAllowed(want, v.Role)
		if err != nil {
			return nil, err
		}
		if !ok || !v.Key.valid() {
			continue
		}
		if v.Owner == "" {
			return nil, fmt.Errorf("%w: key has no owner", ErrInvalidKey)
		}
		fp := v.Key.Fingerprint()
		if prior, dup := byFingerprint[fp]; dup {
			if prior.Owner != v.Owner {
				return nil, fmt.Errorf("%w: key has two owners", ErrInvalidKey)
			}
			continue
		}
		ed, ml := v.Key.Bytes()
		if byEd[string(ed)] != "" || byML[string(ml)] != "" {
			return nil, fmt.Errorf("%w: keys share a half", ErrInvalidKey)
		}
		byFingerprint[fp], byEd[string(ed)], byML[string(ml)] = v, fp, fp
		usable = append(usable, v)
	}
	return usable, nil
}

// Verify checks an envelope against the expected type and trusted keys. At least
// required distinct owners, each with a key whose role is allowed for the type,
// must have both signatures present and valid.
func Verify(e *Envelope, want Type, trusted []Verifier, required int) (*Verified, error) {
	if required < 1 {
		return nil, ErrInvalidThreshold
	}
	if _, ok := allowedRoles[want]; !ok {
		return nil, ErrUnknownType
	}
	if e == nil {
		return nil, ErrMalformed
	}
	if e.PayloadType != string(want) {
		return nil, ErrWrongType
	}
	if len(e.Signatures) > MaxSignatures {
		return nil, ErrTooLarge
	}
	payload, err := decodePayload(e.Payload)
	if err != nil {
		return nil, err
	}
	keys, err := checkTrusted(want, trusted)
	if err != nil {
		return nil, err
	}

	var edSigs, mlSigs [][]byte
	for _, s := range e.Signatures {
		if len(s.Sig) > maxSigEncoded {
			return nil, ErrTooLarge
		}
		raw, err := decode(s.Sig)
		if err != nil {
			return nil, err
		}
		switch len(raw) {
		case ed25519.SignatureSize:
			edSigs = append(edSigs, raw)
		case mldsa.MLDSA65SignatureSize:
			mlSigs = append(mlSigs, raw)
		}
	}

	msg := pae(e.PayloadType, payload)
	result := &Verified{Payload: payload}
	owners := map[string]bool{}
	for _, v := range keys {
		if signedBy(v.Key, msg, edSigs, mlSigs) {
			owners[v.Owner] = true
			result.Signers = append(result.Signers, v)
		}
	}
	if len(owners) < required {
		return nil, ErrNotEnoughSigners
	}
	id := sha256.Sum256(msg)
	result.ID = hex.EncodeToString(id[:])
	return result, nil
}

func signedBy(k PublicKey, msg []byte, edSigs, mlSigs [][]byte) bool {
	edOK := false
	for _, sig := range edSigs {
		if ed25519.Verify(k.ed, msg, sig) {
			edOK = true
			break
		}
	}
	if !edOK {
		return false
	}
	for _, sig := range mlSigs {
		if mldsa.Verify(k.ml, msg, sig, &mldsa.Options{}) == nil {
			return true
		}
	}
	return false
}
