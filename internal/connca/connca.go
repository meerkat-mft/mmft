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
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"

	caLifetime = 5 * 365 * 24 * time.Hour
	// ConnectionLifetime is how long an agent's certificate lasts, from ADR 0011.
	ConnectionLifetime = 24 * time.Hour
	// ServerLifetime is how long a server certificate lasts before it's replaced.
	ServerLifetime = 7 * 24 * time.Hour

	clockSkew   = 5 * time.Minute
	agentURI    = "urn:mmft:agent:"
	maxCSRBytes = 4096
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Errors returned by this package.
var (
	ErrInvalidRequest = errors.New("connca: invalid certificate request")
	ErrInvalidAgentID = errors.New("connca: invalid agent ID")
	ErrNotAnAgent     = errors.New("connca: certificate does not identify an agent")
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
	if err := writeNew(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeNew(filepath.Join(dir, caCertFile), certPEM, 0o644); err != nil {
		_ = os.Remove(filepath.Join(dir, caKeyFile))
		return nil, err
	}
	return &Authority{cert: cert, key: key}, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
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

// Pool returns a pool holding only this CA.
func (a *Authority) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	return pool
}

// ServerCertificate issues a short-lived server certificate for names.
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
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// SignAgent issues a connection certificate for a verified agent. It takes only
// the public key from the request, so that a request can't choose its own names,
// usages, or lifetime.
func (a *Authority) SignAgent(csrDER []byte, agentID string, now time.Time) ([]byte, error) {
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
		NotAfter:     now.Add(ConnectionLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	return x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
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
