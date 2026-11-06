// Package connca is the orchestrator's connection CA, as defined in ADR 0017. Its
// certificates only allow a connection. End-to-end trust comes from the trust
// root, never from here.
package connca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"mmft.dev/mmft/internal/newfile"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"

	caLifetime = 5 * 365 * 24 * time.Hour
	// ConnectionLifetime is how long an agent's certificate lasts, from ADR 0011.
	ConnectionLifetime = 24 * time.Hour
	// MinConnectionLifetime is the shortest lifetime SignAgent accepts. Shorter
	// lifetimes exist only so the lab can test renewal quickly.
	MinConnectionLifetime = 2 * time.Minute
	// ServerLifetime is how long a server certificate lasts before it's replaced.
	ServerLifetime = 7 * 24 * time.Hour

	clockSkew   = 5 * time.Minute
	agentURI    = "urn:mmft:agent:"
	maxCSRBytes = 4096
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Errors returned by this package.
var (
	ErrInvalidRequest  = errors.New("connca: invalid certificate request")
	ErrInvalidAgentID  = errors.New("connca: invalid agent ID")
	ErrNotAnAgent      = errors.New("connca: certificate does not identify an agent")
	ErrInvalidLifetime = errors.New("connca: the connection certificate lifetime must be from 2 minutes to 24 hours")
)

// Authority is a loaded connection CA.
type Authority struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

// Create generates a CA in dir. It refuses to replace an existing one.
func Create(dir string, now time.Time) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Meerkat MFT connection CA"},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := newfile.Write(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := newfile.Write(filepath.Join(dir, caCertFile), certPEM, 0o644); err != nil {
		_ = os.Remove(filepath.Join(dir, caKeyFile))
		return nil, err
	}
	return &Authority{cert: cert, key: key}, nil
}

// Load reads a CA from dir.
func Load(dir string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(filepath.Clean(dir), caCertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(filepath.Clean(dir), caKeyFile))
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("connca: damaged CA files")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("connca: damaged CA certificate: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.New("connca: damaged CA key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("connca: CA key is not Ed25519")
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("connca: CA key does not match its certificate")
	}
	return &Authority{cert: cert, key: key}, nil
}

func serial() *big.Int {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

// Fingerprint returns the hex SHA-256 of the CA certificate, for install commands.
func (a *Authority) Fingerprint() string {
	return Fingerprint(a.cert)
}

// Fingerprint returns the hex SHA-256 of a certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// CertificatePEM returns the CA certificate, which the relay uses to check
// agents' connection certificates.
func (a *Authority) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
}

// Pool returns a pool holding only this CA.
func (a *Authority) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	return pool
}

// ServerCertificate issues a short-lived server certificate for names, with the
// CA certificate as its chain.
func (a *Authority) ServerCertificate(names []string, now time.Time) (*tls.Certificate, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "Meerkat MFT server"},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ServerLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// The CA certificate follows, so a client holding only its fingerprint can
	// verify the server. See ADR 0019.
	return &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// SignAgent issues a connection certificate for a verified agent. It takes only
// the public key from the request, so that a request can't choose its own names,
// usages, or lifetime. The lifetime is ConnectionLifetime outside the lab.
func (a *Authority) SignAgent(csrDER []byte, agentID string, now time.Time, lifetime time.Duration) ([]byte, error) {
	if lifetime < MinConnectionLifetime || lifetime > ConnectionLifetime {
		return nil, ErrInvalidLifetime
	}
	if !uuidPattern.MatchString(agentID) {
		return nil, ErrInvalidAgentID
	}
	if len(csrDER) > maxCSRBytes {
		return nil, ErrInvalidRequest
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, ErrInvalidRequest
	}
	pub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidRequest
	}
	uri, err := url.Parse(agentURI + agentID)
	if err != nil {
		return nil, ErrInvalidAgentID
	}
	template := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "Meerkat MFT agent"},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	return x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
}

// IssuedAt returns when a certificate from this CA was issued. NotBefore is
// set earlier than that, to allow for clock skew.
func IssuedAt(cert *x509.Certificate) time.Time {
	return cert.NotBefore.Add(clockSkew)
}

// AgentID returns the agent ID in a verified connection certificate.
func AgentID(cert *x509.Certificate) (string, error) {
	if len(cert.URIs) != 1 {
		return "", ErrNotAnAgent
	}
	id, ok := strings.CutPrefix(cert.URIs[0].String(), agentURI)
	if !ok || !uuidPattern.MatchString(id) {
		return "", ErrNotAnAgent
	}
	return id, nil
}

// ErrWrongServer is returned when the server's chain doesn't lead to the pinned CA.
var ErrWrongServer = errors.New("connca: server is not signed by the pinned CA")

// PinnedClient returns a TLS client configuration that trusts a server only if
// it sends the CA with this fingerprint after a certificate that the CA issued
// for serverName. The install command carries the fingerprint, so no CA file
// is needed. See ADR 0019.
func PinnedClient(caFingerprint, serverName string, now func() time.Time) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// The default verification needs the CA in advance. VerifyConnection does
		// the full check against the pinned CA instead.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinned(cs.PeerCertificates, caFingerprint, serverName, now())
		},
	}
}

func verifyPinned(chain []*x509.Certificate, caFingerprint, serverName string, now time.Time) error {
	if len(chain) < 2 || caFingerprint == "" {
		return ErrWrongServer
	}
	var ca *x509.Certificate
	for _, c := range chain[1:] {
		if Fingerprint(c) == caFingerprint && c.IsCA {
			ca = c
		}
	}
	if ca == nil {
		return ErrWrongServer
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     serverName,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrWrongServer, err)
	}
	return nil
}
