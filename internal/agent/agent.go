// Package agent holds an agent's own keys and enrollment state, and enrolls it
// with the orchestrator. Private keys are stored unencrypted in a file only the
// agent's service account can read, as ADR 0017 decides, so that the agent can
// restart unattended.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"filippo.io/age"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

// File names in the agent's directory.
const (
	KeyFile   = "agent.key"
	StateFile = "agent.json"
	CertFile  = "connection.crt"
	// CAFile holds the connection CA as pinned at enrollment, so the agent
	// can check its own certificate's signature without the orchestrator.
	CAFile = "ca.crt"
	// IdentityFile holds the agent's verified identity statement.
	IdentityFile = "identity.json"
	lockFile     = ".lock"

	formatVersion = 1
)

// Errors returned by this package.
var (
	ErrNotEnrolled        = errors.New("agent: not enrolled yet")
	ErrDamaged            = errors.New("agent: key or state file is damaged")
	ErrInvalidInstall     = errors.New("agent: invalid install settings")
	ErrBadCertificate     = errors.New("agent: the orchestrator returned an unusable connection certificate")
	ErrUnsupported        = errors.New("agent: private keys can't be stored safely on this platform yet")
	ErrNotApproved        = errors.New("agent: not approved yet")
	ErrWrongIdentity      = errors.New("agent: the identity is for another agent or other keys")
	ErrSaveFailed         = errors.New("agent: saving the enrollment failed")
	ErrOtherSettings      = errors.New("agent: already enrolled with other settings")
	ErrCertificateExpired = errors.New("agent: the connection certificate has expired, so create a new token with `mmft agent token` and run install again")
	// ErrMissingCA means the agent was enrolled before the CA certificate was
	// saved. A new token re-enrolls it with its own keys and saves the CA.
	ErrMissingCA = errors.New("agent: no CA certificate is saved from enrollment, so create a new token with `mmft agent token` and run install again")
	// ErrAlreadyEnrolled is returned only with a valid saved state.
	ErrAlreadyEnrolled = errors.New("agent: already enrolled")
)

type keyFile struct {
	Version    int    `json:"version"`
	Ed25519    []byte `json:"ed25519_seed"`
	MLDSA65    []byte `json:"mldsa65_seed"`
	Encryption string `json:"encryption_identity"`
	Connection []byte `json:"connection_seed"`
}

// Keys are the agent's private keys.
type Keys struct {
	Signer     *statement.Signer
	Encryption *age.HybridIdentity
	Connection ed25519.PrivateKey
}

// Public returns the public keys that enrollment registers.
func (k *Keys) Public() trust.AgentKeys {
	ed, ml := k.Signer.Public().Bytes()
	return trust.AgentKeys{Ed25519: ed, MLDSA65: ml, Recipient: k.Encryption.Recipient().String()}
}

// LoadOrCreateKeys loads the agent's keys from dir, or generates and saves them
// if there are none. Keys are never replaced, so a repeated install keeps them.
func LoadOrCreateKeys(dir string) (*Keys, error) {
	if !keyStorageSupported {
		return nil, ErrUnsupported
	}
	if err := trust.PrepareDir(dir); err != nil {
		return nil, err
	}
	k, err := LoadKeys(dir)
	if !errors.Is(err, fs.ErrNotExist) {
		return k, err
	}
	signer, err := statement.GenerateSigner(statement.RoleAgent)
	if err != nil {
		return nil, err
	}
	enc, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, err
	}
	_, conn, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	edSeed, mlSeed := signer.Seeds()
	data, err := json.Marshal(keyFile{
		Version:    formatVersion,
		Ed25519:    edSeed,
		MLDSA65:    mlSeed,
		Encryption: enc.String(),
		Connection: conn.Seed(),
	})
	if err != nil {
		return nil, err
	}
	defer clear(data)
	err = trust.WriteNew(filepath.Join(dir, KeyFile), data, 0o600)
	if errors.Is(err, os.ErrExist) {
		// Another process saved its keys first, so use those.
		return LoadKeys(dir)
	}
	if err != nil {
		return nil, err
	}
	return &Keys{Signer: signer, Encryption: enc, Connection: conn}, nil
}

// LoadKeys reads the agent's keys, and refuses a file that others can read.
func LoadKeys(dir string) (*Keys, error) {
	if !keyStorageSupported {
		return nil, ErrUnsupported
	}
	data, err := trust.ReadPrivate(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var f keyFile
	if err := decode(data, &f); err != nil || f.Version != formatVersion || len(f.Connection) != ed25519.SeedSize {
		return nil, ErrDamaged
	}
	defer clear(f.Ed25519)
	defer clear(f.MLDSA65)
	defer clear(f.Connection)
	signer, err := statement.NewSigner(statement.RoleAgent, f.Ed25519, f.MLDSA65)
	if err != nil {
		return nil, ErrDamaged
	}
	enc, err := age.ParseHybridIdentity(f.Encryption)
	if err != nil {
		return nil, ErrDamaged
	}
	return &Keys{Signer: signer, Encryption: enc, Connection: ed25519.NewKeyFromSeed(f.Connection)}, nil
}

// State records a completed enrollment. It holds only public values, so tools
// can read it without the private keys.
type State struct {
	Version         int    `json:"version"`
	Orchestrator    string `json:"orchestrator"`
	CAFingerprint   string `json:"ca_fingerprint"`
	RootFingerprint string `json:"root_fingerprint"`
	AgentID         string `json:"agent_id"`
	Workspace       string `json:"workspace"`
	AgentName       string `json:"agent_name"`
	Ed25519         []byte `json:"ed25519"`
	MLDSA65         []byte `json:"mldsa65"`
	Recipient       string `json:"encryption_recipient"`
}

// Keys returns the agent's public keys.
func (s State) Keys() trust.AgentKeys {
	return trust.AgentKeys{Ed25519: s.Ed25519, MLDSA65: s.MLDSA65, Recipient: s.Recipient}
}

// Fingerprint is the value an administrator compares before approving.
func (s State) Fingerprint() string {
	return s.Keys().Fingerprint()
}

// ReadState reads the enrollment state, or returns ErrNotEnrolled.
func ReadState(dir string) (State, error) {
	data, err := os.ReadFile(filepath.Join(filepath.Clean(dir), StateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, ErrNotEnrolled
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := decode(data, &s); err != nil || s.Version != formatVersion || s.Fingerprint() == "" ||
		s.AgentID != s.Keys().AgentID() || !trust.ValidName(s.Workspace) {
		return State{}, ErrDamaged
	}
	if _, err := checkSettings(s.Orchestrator, s.AgentName, s.CAFingerprint, s.RootFingerprint); err != nil {
		return State{}, ErrDamaged
	}
	return s, nil
}

func decode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Install holds the values from the install command.
type Install struct {
	// Orchestrator is the host and port of the orchestrator's agent service.
	Orchestrator    string
	Token           string
	Workspace       string
	AgentName       string
	CAFingerprint   string
	RootFingerprint string
}

func validFingerprint(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// checkSettings validates the values an install and its saved state share, and
// returns the orchestrator's host name.
func checkSettings(orchestrator, name, caPin, rootPin string) (host string, err error) {
	host, port, err := net.SplitHostPort(orchestrator)
	if err != nil || host == "" || port == "" || !trust.ValidName(name) || !validFingerprint(caPin) || !validFingerprint(rootPin) {
		return "", ErrInvalidInstall
	}
	return host, nil
}

func (in Install) check() (host string, err error) {
	if in.Token == "" || !trust.ValidName(in.Workspace) {
		return "", ErrInvalidInstall
	}
	return checkSettings(in.Orchestrator, in.AgentName, in.CAFingerprint, in.RootFingerprint)
}

// Enroll generates the agent's keys, or reuses keys from an earlier attempt,
// and enrolls with the orchestrator, trusting it only through the pinned CA
// fingerprint. It returns ErrAlreadyEnrolled with the saved state if the agent
// is already enrolled, so a repeated install changes nothing. If the response was
// lost, or saving it failed, a retry with the same token and the kept keys
// gets the same agent. Installs into one directory run one at a time.
func Enroll(ctx context.Context, dir string, in Install, now func() time.Time) (State, error) {
	host, err := in.check()
	if err != nil {
		return State{}, err
	}
	if !keyStorageSupported {
		return State{}, ErrUnsupported
	}
	if err := trust.PrepareDir(dir); err != nil {
		return State{}, err
	}
	unlock, err := lock(ctx, dir)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	// An enrolled agent with these settings is a safe repeat. One whose
	// certificate has expired, for example because approval came after it ran
	// out, re-enrolls with the new token and its own keys.
	saved, err := CheckInstalled(dir, in, now())
	switch {
	case err == nil:
		return saved, ErrAlreadyEnrolled
	case errors.Is(err, ErrCertificateExpired), errors.Is(err, ErrMissingCA):
	case errors.Is(err, ErrNotEnrolled):
		saved = State{}
	default:
		return State{}, err
	}
	keys, err := LoadOrCreateKeys(dir)
	if err != nil {
		return State{}, err
	}
	pub := keys.Public()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, keys.Connection)
	if err != nil {
		return State{}, err
	}
	proof, err := trust.ProveEnrollment(keys.Signer, in.Token, in.Workspace, in.AgentName, pub.Recipient, csr)
	if err != nil {
		return State{}, err
	}
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return State{}, err
	}

	// Keep the CA the handshake matched to the pin, to check the certificate
	// against later.
	var pinnedCA atomic.Pointer[x509.Certificate]
	tlsConfig := connca.PinnedClient(in.CAFingerprint, host, now)
	verify := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := verify(cs); err != nil {
			return err
		}
		for _, c := range cs.PeerCertificates[1:] {
			if connca.Fingerprint(c) == in.CAFingerprint {
				pinnedCA.Store(c)
			}
		}
		return nil
	}
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(in.Orchestrator, grpc.WithTransportCredentials(creds))
	if err != nil {
		return State{}, err
	}
	defer func() { _ = conn.Close() }()
	resp, err := agentv1.NewEnrollmentServiceClient(conn).Enroll(ctx, &agentv1.EnrollRequest{
		Token:               in.Token,
		AgentId:             pub.AgentID(),
		Workspace:           in.Workspace,
		AgentName:           in.AgentName,
		Ed25519PublicKey:    pub.Ed25519,
		Mldsa65PublicKey:    pub.MLDSA65,
		EncryptionRecipient: pub.Recipient,
		CertificateRequest:  csr,
		ProofStatement:      proofBytes,
	})
	if err != nil {
		return State{}, err
	}
	if err := checkCertificate(resp, keys.Connection, pub.AgentID()); err != nil {
		return State{}, err
	}

	ca := pinnedCA.Load()
	if ca == nil {
		return State{}, ErrBadCertificate
	}
	if err := checkSignedBy(resp.GetConnectionCertificate(), ca); err != nil {
		return State{}, err
	}
	// The CA and certificate are written before the state, because the state
	// marks a finished enrollment. Each replaces any earlier file atomically,
	// so a failed re-enrollment keeps the old certificate and can be retried.
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := replaceFile(filepath.Join(dir, CAFile), caPEM, 0o644); err != nil {
		return State{}, saveFailed(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: resp.GetConnectionCertificate()})
	if err := replaceFile(filepath.Join(dir, CertFile), certPEM, 0o644); err != nil {
		return State{}, saveFailed(err)
	}
	if saved.Version != 0 {
		// The state is already saved, and the new certificate is all that changed.
		return saved, nil
	}
	s := State{
		Version:         formatVersion,
		Orchestrator:    in.Orchestrator,
		CAFingerprint:   in.CAFingerprint,
		RootFingerprint: in.RootFingerprint,
		AgentID:         pub.AgentID(),
		Workspace:       in.Workspace,
		AgentName:       in.AgentName,
		Ed25519:         pub.Ed25519,
		MLDSA65:         pub.MLDSA65,
		Recipient:       pub.Recipient,
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return State{}, err
	}
	if err := trust.WriteNew(filepath.Join(dir, StateFile), append(data, '\n'), 0o644); err != nil {
		return State{}, saveFailed(err)
	}
	return s, nil
}

// CheckInstalled checks an enrolled agent in dir: its saved settings must match
// in, apart from the token, its key file and connection certificate must load
// and belong to it, and the certificate must not have expired. It returns
// ErrNotEnrolled, ErrOtherSettings, ErrDamaged, ErrCertificateExpired, or
// ErrMissingCA. The last two are fixed by installing again with a new token.
func CheckInstalled(dir string, in Install, now time.Time) (State, error) {
	s, err := ReadState(dir)
	if err != nil {
		return State{}, err
	}
	if s.Orchestrator != in.Orchestrator || s.Workspace != in.Workspace || s.AgentName != in.AgentName ||
		s.CAFingerprint != in.CAFingerprint || s.RootFingerprint != in.RootFingerprint {
		return s, ErrOtherSettings
	}
	keys, err := LoadKeys(dir)
	if err != nil {
		return s, fmt.Errorf("%w: %w", ErrDamaged, err)
	}
	if keys.Public().Fingerprint() != s.Fingerprint() {
		return s, ErrDamaged
	}
	if _, err := loadCertificate(dir, s, keys, now); err != nil {
		return s, err
	}
	return s, nil
}

// readCertificate reads one PEM certificate.
func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDamaged, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrDamaged
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrDamaged
	}
	return cert, nil
}

// loadCertificate reads the connection certificate and requires it to hold
// the agent's connection key, name its ID, and chain to the CA pinned at
// enrollment for client use at now, exactly as the server's TLS check does. A
// certificate that has only expired returns ErrCertificateExpired, which a new
// token fixes. Anything else wrong is damage.
func loadCertificate(dir string, s State, keys *Keys, now time.Time) (*x509.Certificate, error) {
	ca, err := readCertificate(filepath.Join(dir, CAFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMissingCA
	}
	if err != nil {
		return nil, err
	}
	if !ca.IsCA || connca.Fingerprint(ca) != s.CAFingerprint {
		return nil, ErrDamaged
	}
	cert, err := readCertificate(filepath.Join(dir, CertFile))
	if err != nil {
		return nil, err
	}
	if err := checkConnection(cert, ca, s.AgentID, keys.Connection, now); err != nil {
		return nil, err
	}
	return cert, nil
}

// checkConnection requires a connection certificate to hold the agent's
// connection key, name its ID, and chain to the pinned CA for client use at
// now. It returns ErrCertificateExpired for a certificate that has only
// expired, and ErrDamaged for anything else wrong.
func checkConnection(cert, ca *x509.Certificate, agentID string, key ed25519.PrivateKey, now time.Time) error {
	if cert.CheckSignatureFrom(ca) != nil {
		return ErrDamaged
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return ErrDamaged
	}
	if id, err := connca.AgentID(cert); err != nil || id != agentID {
		return ErrDamaged
	}
	if !now.Before(cert.NotAfter) {
		return ErrCertificateExpired
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrDamaged, err)
	}
	return nil
}

// checkSignedBy requires the new connection certificate to be signed by the
// CA the handshake matched to the pin.
func checkSignedBy(der []byte, ca *x509.Certificate) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.CheckSignatureFrom(ca) != nil {
		return ErrBadCertificate
	}
	return nil
}

// saveFailed reports a failure to save an enrollment the orchestrator already
// recorded. It never matches os.ErrExist, so an existing file in the way can't
// pass for an earlier enrollment. A retry with the same token completes it.
func saveFailed(err error) error {
	return fmt.Errorf("%w, so run install again: %s", ErrSaveFailed, err.Error())
}

// checkCertificate requires the certificate to hold this agent's connection key
// and name the agent ID the orchestrator returned.
func checkCertificate(resp *agentv1.EnrollResponse, key ed25519.PrivateKey, agentID string) error {
	// The ID comes from the agent's own keys, so the orchestrator can't change it.
	if resp.GetAgentId() != agentID {
		return fmt.Errorf("%w: wrong agent ID", ErrBadCertificate)
	}
	cert, err := x509.ParseCertificate(resp.GetConnectionCertificate())
	if err != nil {
		return ErrBadCertificate
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return ErrBadCertificate
	}
	if id, err := connca.AgentID(cert); err != nil || id != resp.GetAgentId() {
		return fmt.Errorf("%w: wrong agent ID", ErrBadCertificate)
	}
	return nil
}

// FetchIdentity asks the orchestrator for the agent's identity, verifies it
// back to the pinned trust root, and saves it. The orchestrator is trusted for
// nothing here: an identity it altered or made up fails verification. It returns
// ErrNotApproved until an administrator has signed the identity.
func FetchIdentity(ctx context.Context, dir string, now func() time.Time) (trust.IdentityClaim, error) {
	s, err := ReadState(dir)
	if err != nil {
		return trust.IdentityClaim{}, err
	}
	keys, err := LoadKeys(dir)
	if err != nil {
		return trust.IdentityClaim{}, err
	}
	// A certificate TLS would refuse fails the handshake with an unclear
	// error, so check it first and say what to do instead.
	cert, err := loadCertificate(dir, s, keys, now())
	if err != nil {
		return trust.IdentityClaim{}, err
	}
	host, err := checkSettings(s.Orchestrator, s.AgentName, s.CAFingerprint, s.RootFingerprint)
	if err != nil {
		return trust.IdentityClaim{}, err
	}
	cfg := connca.PinnedClient(s.CAFingerprint, host, now)
	cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: keys.Connection}}
	conn, err := grpc.NewClient(s.Orchestrator, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return trust.IdentityClaim{}, err
	}
	defer func() { _ = conn.Close() }()
	resp, err := agentv1.NewAgentServiceClient(conn).GetIdentity(ctx, &agentv1.GetIdentityRequest{})
	switch status.Code(err) {
	case codes.OK:
	case codes.NotFound:
		return trust.IdentityClaim{}, ErrNotApproved
	case codes.PermissionDenied, codes.Unauthenticated:
		// Not the enrollment token's code, which a caller may map to a refusal.
		return trust.IdentityClaim{}, fmt.Errorf("agent: the orchestrator refused the agent: %s", status.Convert(err).Message())
	default:
		return trust.IdentityClaim{}, err
	}
	identity := resp.GetIdentityStatement()
	claim, err := VerifyIdentity(s, identity, now())
	if err != nil {
		return trust.IdentityClaim{}, err
	}
	if err := replaceFile(filepath.Join(dir, IdentityFile), identity, 0o644); err != nil {
		return trust.IdentityClaim{}, err
	}
	return claim, nil
}

// VerifyIdentity checks an identity statement back to the agent's pinned root,
// and requires it to name this agent and hold exactly its keys.
func VerifyIdentity(s State, identity []byte, now time.Time) (trust.IdentityClaim, error) {
	claim, _, err := trust.VerifyAgent(identity, s.RootFingerprint, now)
	if err != nil {
		return trust.IdentityClaim{}, err
	}
	if claim.AgentID != s.AgentID || claim.Workspace != s.Workspace || claim.AgentName != s.AgentName ||
		claim.Keys().Fingerprint() != s.Fingerprint() {
		return trust.IdentityClaim{}, ErrWrongIdentity
	}
	return claim, nil
}

// replaceFile writes a file under a temporary name and renames it into place,
// so a reader sees either the old or the new contents.
func replaceFile(path string, data []byte, mode os.FileMode) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
