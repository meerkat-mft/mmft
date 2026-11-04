// Package trust stores keys and certifies administrator keys, as defined in ADR
// 0011. Private keys only ever reach disk encrypted with a passphrase.
package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"mmft.dev/mmft/internal/statement"
)

// File names in a key directory.
const (
	RootKeyFile   = "root.key.age"
	RootPublic    = "root.pub.json"
	AdminKeyFile  = "administrator.key.age"
	AdminPublic   = "administrator.pub.json"
	formatVersion = 1
)

const (
	// MinPassphraseBytes is the shortest passphrase accepted for a new key.
	MinPassphraseBytes = 16
	// MaxAdministratorLifetime is the longest certificate ADR 0011 allows.
	MaxAdministratorLifetime = 365 * 24 * time.Hour

	// clockSkew backdates certificates, because the offline machine that signs
	// them is likely to have a drifting clock.
	clockSkew = 5 * time.Minute

	rootOwner         = "root"
	defaultWorkFactor = 18
	maxPassphrase     = 4096
)

// Errors returned by this package.
var (
	ErrWeakPassphrase      = errors.New("trust: passphrase is too weak")
	ErrWrongRoot           = errors.New("trust: root key does not match the pinned fingerprint")
	ErrWrongAdministrator  = errors.New("trust: administrator key does not match the expected fingerprint")
	ErrRootAsAdmin         = errors.New("trust: the root key can't be an administrator key")
	ErrNotYetValid         = errors.New("trust: certificate is not valid yet")
	ErrExpired             = errors.New("trust: certificate has expired")
	ErrInvalidClaim        = errors.New("trust: invalid certificate")
	ErrBadLifetime         = errors.New("trust: certificate lifetime is out of range")
	ErrWrongKeyFile        = errors.New("trust: key file is damaged or has a different role")
	ErrInvalidOwner        = errors.New("trust: owner must be lower-case letters, digits, or . _ @ -")
	ErrNotPrivate          = errors.New("trust: file or directory is not private to this user")
	ErrUnsupportedPlatform = errors.New("trust: private key files can't be protected on Windows yet, so use Linux, macOS, or WSL")
	ErrInvalidPublic       = errors.New("trust: invalid public key file")
)

// scryptWorkFactor sets the cost of a passphrase guess. Tests lower it.
var scryptWorkFactor = defaultWorkFactor

// ownerPattern is the one form of an owner name. Thresholds count distinct
// owners, so names must not vary by case, spacing, or invisible characters.
var ownerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,63}$`)

// fieldPattern is the one form of a JSON field name.
var fieldPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// ValidOwner reports whether a name can own an administrator key.
func ValidOwner(owner string) bool {
	return owner != rootOwner && ownerPattern.MatchString(owner)
}

type keyFile struct {
	Version int    `json:"version"`
	Role    int    `json:"role"`
	Owner   string `json:"owner"`
	Ed25519 []byte `json:"ed25519_seed"`
	MLDSA65 []byte `json:"mldsa65_seed"`
}

// PublicRecord is the public half of a key, safe to copy anywhere.
type PublicRecord struct {
	Version int    `json:"version"`
	Owner   string `json:"owner"`
	Ed25519 []byte `json:"ed25519"`
	MLDSA65 []byte `json:"mldsa65"`
}

// Key returns the validated public key.
func (r PublicRecord) Key() (statement.PublicKey, error) {
	return statement.NewPublicKey(r.Ed25519, r.MLDSA65)
}

func publicRecord(s *statement.Signer, owner string) PublicRecord {
	ed, ml := s.Public().Bytes()
	return PublicRecord{Version: formatVersion, Owner: owner, Ed25519: ed, MLDSA65: ml}
}

// WriteNew creates a file that must not already exist. It writes to a temporary
// name, syncs, and then links into place, so a crash can't leave a truncated key
// and a key can't be lost after success is reported.
func WriteNew(path string, data []byte, mode os.FileMode) (err error) {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
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
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func saveKey(path string, s *statement.Signer, owner, passphrase string) error {
	if err := CheckPassphrase(passphrase); err != nil {
		return err
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	recipient.SetWorkFactor(scryptWorkFactor)

	edSeed, mlSeed := s.Seeds()
	plain, err := json.Marshal(keyFile{Version: formatVersion, Role: int(s.Role()), Owner: owner, Ed25519: edSeed, MLDSA65: mlSeed})
	clear(edSeed)
	clear(mlSeed)
	if err != nil {
		return err
	}
	defer clear(plain)

	var sealed bytes.Buffer
	w, err := age.Encrypt(&sealed, recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return WriteNew(path, sealed.Bytes(), 0o600)
}

// CheckPassphrase rejects a passphrase too weak for a new key.
func CheckPassphrase(passphrase string) error {
	if len(passphrase) < MinPassphraseBytes || strings.TrimSpace(passphrase) == "" {
		return ErrWeakPassphrase
	}
	return nil
}

// ReadPassphrase reads a passphrase from a file, which must be a regular file
// private to this user. A trailing line break is removed. Errors never repeat
// the path, in case a passphrase was passed by mistake.
func ReadPassphrase(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", errors.New("trust: cannot open the passphrase file")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", errors.New("trust: cannot read the passphrase file")
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("trust: the passphrase file must be a regular file")
	}
	if err := checkPrivateFile(info); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPassphrase+1))
	if err != nil {
		return "", errors.New("trust: cannot read the passphrase file")
	}
	if len(data) > maxPassphrase {
		return "", errors.New("trust: the passphrase file is too large")
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

// LoadKey decrypts a key file, and refuses it unless it is private to this user
// and holds the expected role.
func LoadKey(path, passphrase string, role statement.Role) (*statement.Signer, string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if err := checkPrivateFile(info); err != nil {
		return nil, "", err
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, "", err
	}
	r, err := age.Decrypt(f, identity)
	if err != nil {
		return nil, "", fmt.Errorf("trust: cannot decrypt key: %w", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, "", fmt.Errorf("trust: cannot decrypt key: %w", err)
	}
	defer clear(plain)

	var k keyFile
	if err := strictJSON(plain, &k); err != nil {
		return nil, "", ErrWrongKeyFile
	}
	defer clear(k.Ed25519)
	defer clear(k.MLDSA65)
	if k.Version != formatVersion || k.Role != int(role) {
		return nil, "", ErrWrongKeyFile
	}
	s, err := statement.NewSigner(role, k.Ed25519, k.MLDSA65)
	if err != nil {
		return nil, "", ErrWrongKeyFile
	}
	return s, k.Owner, nil
}

// ReadPrivate reads a file only if it is private to this user.
func ReadPrivate(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkPrivateFile(info); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// PrepareDir creates a private directory, or accepts an existing one only if
// it is a real directory that nobody else can change.
func PrepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return ErrNotPrivate
	}
	return checkPrivateDir(info)
}

// create generates a key and saves both halves in dir. The public half is
// written first, so that the fingerprint is never lost after a private key
// exists. A repeat run fails with os.ErrExist and changes nothing.
func create(dir, keyName, pubName, owner, passphrase string, role statement.Role) (statement.PublicKey, error) {
	if err := CheckPassphrase(passphrase); err != nil {
		return statement.PublicKey{}, err
	}
	if err := PrepareDir(dir); err != nil {
		return statement.PublicKey{}, err
	}
	keyPath, pubPath := filepath.Join(dir, keyName), filepath.Join(dir, pubName)
	if _, err := os.Lstat(keyPath); err == nil {
		return statement.PublicKey{}, os.ErrExist
	}
	s, err := statement.GenerateSigner(role)
	if err != nil {
		return statement.PublicKey{}, err
	}
	pub, err := json.MarshalIndent(publicRecord(s, owner), "", "  ")
	if err != nil {
		return statement.PublicKey{}, err
	}
	if err := WriteNew(pubPath, append(pub, '\n'), 0o644); err != nil {
		return statement.PublicKey{}, err
	}
	if err := saveKey(keyPath, s, owner, passphrase); err != nil {
		_ = os.Remove(pubPath)
		return statement.PublicKey{}, err
	}
	return s.Public(), nil
}

// InitRoot creates the trust root in dir and returns its public key.
func InitRoot(dir, passphrase string) (statement.PublicKey, error) {
	return create(dir, RootKeyFile, RootPublic, rootOwner, passphrase, statement.RoleRoot)
}

// InitAdministrator creates an administrator key in dir and returns its public
// key. It can't sign anything agents accept until the root certifies it.
func InitAdministrator(dir, owner, passphrase string) (statement.PublicKey, error) {
	if !ValidOwner(owner) {
		return statement.PublicKey{}, ErrInvalidOwner
	}
	return create(dir, AdminKeyFile, AdminPublic, owner, passphrase, statement.RoleAdministrator)
}

// ReadPublic reads a public record from a file.
func ReadPublic(path string) (PublicRecord, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return PublicRecord{}, err
	}
	var r PublicRecord
	if err := strictJSON(data, &r); err != nil {
		return PublicRecord{}, fmt.Errorf("%w: %w", ErrInvalidPublic, err)
	}
	if r.Version != formatVersion {
		return PublicRecord{}, fmt.Errorf("%w: unsupported version %s", ErrInvalidPublic, strconv.Itoa(r.Version))
	}
	return r, nil
}

// AdministratorClaim is the payload of an administrator key statement.
type AdministratorClaim struct {
	Version   int       `json:"version"`
	Owner     string    `json:"owner"`
	Ed25519   []byte    `json:"ed25519"`
	MLDSA65   []byte    `json:"mldsa65"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

func sameHalf(a, b statement.PublicKey) bool {
	aEd, aML := a.Bytes()
	bEd, bML := b.Bytes()
	return bytes.Equal(aEd, bEd) || bytes.Equal(aML, bML)
}

// CertifyAdministrator has the trust root sign an administrator's public key.
// Both keys are compared with fingerprints obtained independently, so neither a
// swapped root directory nor a swapped request file can be signed.
func CertifyAdministrator(root *statement.Signer, pinnedRoot string, admin PublicRecord, expectedAdmin string, now time.Time, lifetime time.Duration) (*statement.Envelope, error) {
	if pinnedRoot == "" || root.Public().Fingerprint() != pinnedRoot {
		return nil, ErrWrongRoot
	}
	if lifetime <= 0 || lifetime > MaxAdministratorLifetime {
		return nil, ErrBadLifetime
	}
	if !ValidOwner(admin.Owner) {
		return nil, ErrInvalidOwner
	}
	key, err := admin.Key()
	if err != nil {
		return nil, err
	}
	if expectedAdmin == "" || key.Fingerprint() != expectedAdmin {
		return nil, ErrWrongAdministrator
	}
	if sameHalf(key, root.Public()) {
		return nil, ErrRootAsAdmin
	}
	notBefore := now.Add(-clockSkew).UTC()
	payload, err := json.Marshal(AdministratorClaim{
		Version:   formatVersion,
		Owner:     admin.Owner,
		Ed25519:   admin.Ed25519,
		MLDSA65:   admin.MLDSA65,
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(lifetime),
	})
	if err != nil {
		return nil, err
	}
	return statement.Sign(statement.TypeAdministratorKey, payload, root)
}

// VerifyAdministrator checks a certificate against the root, which must match
// the pinned fingerprint, and returns a verifier for the administrator's key.
func VerifyAdministrator(certificate []byte, root statement.PublicKey, pinned string, now time.Time) (statement.Verifier, AdministratorClaim, error) {
	if pinned == "" || root.Fingerprint() != pinned {
		return statement.Verifier{}, AdministratorClaim{}, ErrWrongRoot
	}
	e, err := statement.Parse(certificate)
	if err != nil {
		return statement.Verifier{}, AdministratorClaim{}, err
	}
	trusted := []statement.Verifier{{Key: root, Role: statement.RoleRoot, Owner: rootOwner}}
	got, err := statement.Verify(e, statement.TypeAdministratorKey, trusted, 1)
	if err != nil {
		return statement.Verifier{}, AdministratorClaim{}, err
	}
	var claim AdministratorClaim
	if err := strictJSON(got.Payload, &claim); err != nil {
		return statement.Verifier{}, AdministratorClaim{}, ErrInvalidClaim
	}
	if claim.Version != formatVersion || !ValidOwner(claim.Owner) || !claim.NotAfter.After(claim.NotBefore) {
		return statement.Verifier{}, AdministratorClaim{}, ErrInvalidClaim
	}
	if claim.NotAfter.Sub(claim.NotBefore) > MaxAdministratorLifetime {
		return statement.Verifier{}, AdministratorClaim{}, ErrInvalidClaim
	}
	key, err := statement.NewPublicKey(claim.Ed25519, claim.MLDSA65)
	if err != nil {
		return statement.Verifier{}, AdministratorClaim{}, ErrInvalidClaim
	}
	if sameHalf(key, root) {
		return statement.Verifier{}, AdministratorClaim{}, ErrRootAsAdmin
	}
	if now.Before(claim.NotBefore) {
		return statement.Verifier{}, AdministratorClaim{}, ErrNotYetValid
	}
	if !now.Before(claim.NotAfter) {
		return statement.Verifier{}, AdministratorClaim{}, ErrExpired
	}
	return statement.Verifier{Key: key, Role: statement.RoleAdministrator, Owner: claim.Owner}, claim, nil
}

// strictJSON decodes one object, rejecting unknown, duplicate, and differently
// cased fields as well as trailing data, so that no other reader can see a
// different value.
func strictJSON(data []byte, v any) error {
	if err := uniqueKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trust: trailing data")
	}
	return nil
}

func uniqueKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("trust: expected an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("trust: expected a field name")
		}
		// encoding/json matches names with Unicode case folding, so "\u017f" would
		// alias "s". Lower case ASCII names have no other form.
		if !fieldPattern.MatchString(key) {
			return errors.New("trust: field names must be lower case ASCII")
		}
		if seen[key] {
			return errors.New("trust: repeated field")
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}

// WriteCertificate saves a certificate to a new file.
func WriteCertificate(path string, e *statement.Envelope) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return WriteNew(path, append(data, '\n'), 0o644)
}
