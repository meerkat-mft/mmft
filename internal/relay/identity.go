package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	identityKeyFile  = "relay.key"
	identityCertFile = "relay.crt"
	// Agents pin the relay's certificate by its hash, so its dates never
	// decide trust. A long lifetime only avoids surprising other tools.
	identityLifetime = 10 * 365 * 24 * time.Hour
)

// ErrWrongRelay is returned when a relay presents a certificate other than the
// one its ticket names.
var ErrWrongRelay = errors.New("relay: the relay's certificate does not match its ticket")

// CreateIdentity generates the relay's TLS key and self-signed certificate in
// dir, and returns the certificate's SHA-256 for the orchestrator's settings.
// It refuses to replace an existing identity.
func CreateIdentity(dir string, now time.Time) ([]byte, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Meerkat MFT relay"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(identityLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, identityKeyFile)
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(dir, identityCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		_ = os.Remove(keyPath)
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
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

// LoadIdentity reads the relay's key and certificate from dir.
func LoadIdentity(dir string) (tls.Certificate, error) {
	dir = filepath.Clean(dir)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, identityCertFile), filepath.Join(dir, identityKeyFile))
	if err != nil {
		return tls.Certificate{}, err
	}
	if _, ok := cert.PrivateKey.(ed25519.PrivateKey); !ok {
		return tls.Certificate{}, errors.New("relay: the relay key is not Ed25519")
	}
	return cert, nil
}

// Fingerprint returns the SHA-256 of a relay's certificate.
func Fingerprint(cert tls.Certificate) []byte {
	sum := sha256.Sum256(cert.Certificate[0])
	return sum[:]
}

// PinnedClient returns the TLS configuration an agent uses to reach the relay.
// It presents the agent's connection certificate and trusts the relay only if
// its certificate has this SHA-256, which arrived with the ticket over the
// agent's authenticated stream to the orchestrator.
func PinnedClient(fingerprint []byte, agent tls.Certificate) *tls.Config {
	want := bytes.Clone(fingerprint)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{agent},
		// The default verification needs a CA. VerifyConnection checks the pin
		// instead, and TLS 1.3 proves the relay holds the pinned key.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(want) != sha256.Size || len(cs.PeerCertificates) == 0 {
				return ErrWrongRelay
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(sum[:], want) {
				return ErrWrongRelay
			}
			return nil
		},
	}
}
