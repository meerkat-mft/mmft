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
	"time"

	"filippo.io/age"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

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
	lockFile  = ".lock"

	formatVersion = 1
)

// Errors returned by this package.
var (
	ErrNotEnrolled    = errors.New("agent: not enrolled yet")
	ErrDamaged        = errors.New("agent: key or state file is damaged")
	ErrInvalidInstall = errors.New("agent: invalid install settings")
	ErrBadCertificate = errors.New("agent: the orchestrator returned an unusable connection certificate")
	ErrUnsupported    = errors.New("agent: private keys can't be stored safely on this platform yet")
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
	if err := decode(data, &s); err != nil || s.Version != formatVersion || s.Fingerprint() == "" || !trust.ValidAgentID(s.AgentID) {
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
	if in.Token == "" {
		return "", ErrInvalidInstall
	}
	return checkSettings(in.Orchestrator, in.AgentName, in.CAFingerprint, in.RootFingerprint)
}

// Enroll generates the agent's keys, or reuses keys from an earlier attempt,
// and enrolls with the orchestrator, trusting it only through the pinned CA
// fingerprint. It returns os.ErrExist with the saved state if the agent is
// already enrolled, so a repeated install changes nothing. If the response was
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
	if s, err := ReadState(dir); err == nil {
		return s, os.ErrExist
	} else if !errors.Is(err, ErrNotEnrolled) {
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
	proof, err := trust.ProveEnrollment(keys.Signer, in.Token, in.AgentName, pub.Recipient, csr)
	if err != nil {
		return State{}, err
	}
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return State{}, err
	}

	creds := credentials.NewTLS(connca.PinnedClient(in.CAFingerprint, host, now))
	conn, err := grpc.NewClient(in.Orchestrator, grpc.WithTransportCredentials(creds))
	if err != nil {
		return State{}, err
	}
	defer func() { _ = conn.Close() }()
	resp, err := agentv1.NewEnrollmentServiceClient(conn).Enroll(ctx, &agentv1.EnrollRequest{
		Token:               in.Token,
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
	if err := checkCertificate(resp, keys.Connection); err != nil {
		return State{}, err
	}

	// The certificate is written before the state, because the state marks a
	// finished enrollment. A leftover certificate from a failed attempt goes.
	certPath := filepath.Join(dir, CertFile)
	if err := os.Remove(certPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return State{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: resp.GetConnectionCertificate()})
	if err := trust.WriteNew(certPath, certPEM, 0o644); err != nil {
		return State{}, err
	}
	s := State{
		Version:         formatVersion,
		Orchestrator:    in.Orchestrator,
		CAFingerprint:   in.CAFingerprint,
		RootFingerprint: in.RootFingerprint,
		AgentID:         resp.GetAgentId(),
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
		return State{}, err
	}
	return s, nil
}

// checkCertificate requires the certificate to hold this agent's connection key
// and name the agent ID the orchestrator returned.
func checkCertificate(resp *agentv1.EnrollResponse, key ed25519.PrivateKey) error {
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
