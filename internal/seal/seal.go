// Package seal creates and opens sealed files and their delivery manifests, as
// defined in ADR 0010. A sealed file is the source file encrypted with age to
// the destination agent's hybrid recipient. The delivery manifest is the source
// agent's signed statement of the sealed file's size and SHA-256, and of the one
// delivery it belongs to.
//
// The destination never decrypts a sealed file until its size and hash match a
// verified manifest for the delivery it expects. Manifests never hold file
// names.
package seal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"filippo.io/age"

	"mmft.dev/mmft/internal/statement"
)

// FormatVersion identifies the sealed file format: age with one MLKEM768-X25519
// recipient. A new format, such as one for FIPS, needs a new version.
const FormatVersion = 1

// manifestVersion is the version of the manifest payload itself.
const manifestVersion = 1

// Bounds used to size the disk space check. An age header with one hybrid
// recipient is about 1.6 KB, and each 64 KiB chunk adds a 16-byte tag.
const (
	headerBound = 4096
	nonceSize   = 16
	chunkSize   = 64 << 10
	tagSize     = 16
)

// Errors returned by this package.
var (
	ErrNoSpace          = errors.New("seal: not enough free disk space")
	ErrSourceChanged    = errors.New("seal: source file changed while sealing")
	ErrInvalidManifest  = errors.New("seal: invalid delivery manifest")
	ErrManifestMismatch = errors.New("seal: delivery manifest is for a different delivery")
	ErrSizeMismatch     = errors.New("seal: sealed file size does not match the manifest")
	ErrHashMismatch     = errors.New("seal: sealed file hash does not match the manifest")
	ErrNotRegular       = errors.New("seal: source is not a regular file")
)

// freeSpace reports the bytes available to an unprivileged writer in dir. Tests
// replace it to simulate a full disk.
var freeSpace = freeBytes

// afterHashCheck runs between the first hash check and decryption. Tests replace
// it to change the sealed file in between.
var afterHashCheck = func() {}

// Sealed describes a sealed file in an agent's spool.
type Sealed struct {
	Path   string
	Size   int64
	SHA256 [32]byte
}

// MaxSealedSize returns an upper bound on the size of a sealed file for a
// plaintext of the given size.
func MaxSealedSize(plaintext int64) uint64 {
	chunks := (plaintext + chunkSize - 1) / chunkSize
	if chunks == 0 {
		chunks = 1
	}
	return uint64(headerBound + nonceSize + plaintext + chunks*tagSize) // #nosec G115 -- file sizes are not negative.
}

// Seal encrypts the file at src to recipient, with a fresh file key, into a new
// file in spoolDir. It first checks that spoolDir has room for the sealed copy,
// and fails with ErrNoSpace rather than filling the disk.
func Seal(src, spoolDir string, recipient *age.HybridRecipient) (s Sealed, err error) {
	in, err := os.Open(src) // #nosec G304 -- the source path comes from an approved flow.
	if err != nil {
		return Sealed{}, pathless(err)
	}
	defer func() { _ = in.Close() }()
	return File(in, spoolDir, recipient)
}

// File is Seal for a file the caller has already opened, for example
// without following a link.
func File(in *os.File, spoolDir string, recipient *age.HybridRecipient) (s Sealed, err error) {
	defer func() { err = pathless(err) }()
	if recipient == nil {
		return Sealed{}, errors.New("seal: no recipient")
	}
	info, err := in.Stat()
	if err != nil {
		return Sealed{}, err
	}
	if !info.Mode().IsRegular() {
		return Sealed{}, ErrNotRegular
	}
	size := info.Size()
	need := MaxSealedSize(size)
	free, err := freeSpace(spoolDir)
	if err != nil {
		return Sealed{}, fmt.Errorf("seal: check free space: %w", err)
	}
	if free < need {
		return Sealed{}, fmt.Errorf("%w: the spool needs %d bytes and %d are free", ErrNoSpace, need, free)
	}

	out, err := os.CreateTemp(spoolDir, "sealed-*.age")
	if err != nil {
		return Sealed{}, err
	}
	defer func() {
		if err != nil {
			_ = out.Close()
			_ = os.Remove(out.Name())
		}
	}()

	h := sha256.New()
	counted := &countWriter{w: io.MultiWriter(out, h)}
	w, err := age.Encrypt(counted, recipient)
	if err != nil {
		return Sealed{}, err
	}
	// Read one byte past the expected size, so a growing file is noticed.
	n, err := io.Copy(w, io.LimitReader(in, size+1))
	if err != nil {
		return Sealed{}, err
	}
	if n != size {
		return Sealed{}, ErrSourceChanged
	}
	if err := w.Close(); err != nil {
		return Sealed{}, err
	}
	if err := out.Sync(); err != nil {
		return Sealed{}, err
	}
	if err := out.Close(); err != nil {
		return Sealed{}, err
	}
	s = Sealed{Path: out.Name(), Size: counted.n}
	h.Sum(s.SHA256[:0])
	return s, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Delivery names the one delivery a sealed file belongs to. The destination
// builds it from its own assignment, never from the manifest. FlowID and
// FlowVersion are both empty for a manual run.
type Delivery struct {
	DeliveryID       string `json:"delivery_id"`
	FlowID           string `json:"flow_id,omitempty"`
	FlowVersion      int    `json:"flow_version,omitempty"`
	SourceAgent      string `json:"source_agent"`
	DestinationAgent string `json:"destination_agent"`
}

// Manifest is the payload of a delivery manifest.
type Manifest struct {
	Version int `json:"version"`
	Delivery
	FormatVersion int    `json:"format_version"`
	SealedSize    int64  `json:"sealed_size"`
	SealedSHA256  string `json:"sealed_sha256"`
}

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hashPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fieldPattern = regexp.MustCompile(`^[a-z0-9_]+$`)
)

func (d Delivery) valid() bool {
	if !uuidPattern.MatchString(d.DeliveryID) || !uuidPattern.MatchString(d.SourceAgent) ||
		!uuidPattern.MatchString(d.DestinationAgent) || d.SourceAgent == d.DestinationAgent {
		return false
	}
	if d.FlowID == "" {
		return d.FlowVersion == 0
	}
	return uuidPattern.MatchString(d.FlowID) && d.FlowVersion >= 1
}

// SignManifest has the source agent sign a delivery manifest for a sealed file.
func SignManifest(d Delivery, s Sealed, agent *statement.Signer) (*statement.Envelope, error) {
	if !d.valid() || s.Size <= 0 {
		return nil, ErrInvalidManifest
	}
	payload, err := json.Marshal(Manifest{
		Version:       manifestVersion,
		Delivery:      d,
		FormatVersion: FormatVersion,
		SealedSize:    s.Size,
		SealedSHA256:  hex.EncodeToString(s.SHA256[:]),
	})
	if err != nil {
		return nil, err
	}
	return statement.Sign(statement.TypeDeliveryManifest, payload, agent)
}

// VerifyManifest checks that a delivery manifest was signed by the source
// agent's identity key and names exactly the expected delivery. The source
// verifier's owner must be the expected source agent. It returns the manifest
// and the statement's identity.
func VerifyManifest(data []byte, source statement.Verifier, want Delivery) (Manifest, string, error) {
	if !want.valid() || source.Role != statement.RoleAgent || source.Owner != want.SourceAgent {
		return Manifest{}, "", ErrManifestMismatch
	}
	e, err := statement.Parse(data)
	if err != nil {
		return Manifest{}, "", err
	}
	got, err := statement.Verify(e, statement.TypeDeliveryManifest, []statement.Verifier{source}, 1)
	if err != nil {
		return Manifest{}, "", err
	}
	var m Manifest
	if err := strictJSON(got.Payload, &m); err != nil {
		return Manifest{}, "", ErrInvalidManifest
	}
	if m.Version != manifestVersion || m.FormatVersion != FormatVersion || !m.valid() ||
		m.SealedSize <= 0 || !hashPattern.MatchString(m.SealedSHA256) {
		return Manifest{}, "", ErrInvalidManifest
	}
	if m.Delivery != want {
		return Manifest{}, "", ErrManifestMismatch
	}
	return m, got.ID, nil
}

// Open checks a spooled sealed file against a verified manifest and only then
// decrypts it to a new temporary file in destDir, which it returns. The caller
// gives the file its final name. A changed, truncated, or swapped sealed file is
// never decrypted.
func Open(sealedPath string, m Manifest, identity *age.HybridIdentity, destDir string) (string, error) {
	if identity == nil {
		return "", errors.New("seal: no identity")
	}
	path, err := open(sealedPath, m, identity, destDir)
	return path, pathless(err)
}

// pathless removes the file path from an error, because a path can hold a
// file name, which is personal data and must not reach logs or the
// orchestrator. The operation and cause stay, so errors.Is still works.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("seal: %s: %w", pe.Op, pe.Err)
	}
	return err
}

func open(sealedPath string, m Manifest, identity age.Identity, destDir string) (path string, err error) {
	want, err := hex.DecodeString(m.SealedSHA256)
	if err != nil || len(want) != sha256.Size {
		return "", ErrInvalidManifest
	}
	in, err := os.Open(sealedPath) // #nosec G304 -- the path is in the agent's own spool.
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() != m.SealedSize {
		return "", ErrSizeMismatch
	}
	if err := checkHash(io.LimitReader(in, m.SealedSize+1), want); err != nil {
		return "", err
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	afterHashCheck()

	out, err := os.CreateTemp(destDir, ".mmft-*.partial")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = out.Close()
			_ = os.Remove(out.Name())
		}
	}()
	// Hash the bytes again as age reads them, so a sealed file that changes
	// after the first check is still refused and its output removed.
	h := sha256.New()
	tee := io.TeeReader(io.LimitReader(in, m.SealedSize+1), h)
	r, err := age.Decrypt(tee, identity)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, r); err != nil {
		return "", err
	}
	if _, err := io.Copy(h, tee); err != nil {
		return "", err
	}
	if !bytes.Equal(h.Sum(nil), want) {
		return "", ErrHashMismatch
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return filepath.Clean(out.Name()), nil
}

func checkHash(r io.Reader, want []byte) error {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), want) {
		return ErrHashMismatch
	}
	return nil
}

// strictJSON decodes one object, rejecting unknown, duplicate, and differently
// cased fields as well as trailing data, so that no other reader can see a
// different value. It follows the same rules as the trust package.
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
		return errors.New("seal: trailing data")
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
		return errors.New("seal: expected an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("seal: expected a field name")
		}
		// encoding/json matches names with Unicode case folding, so "\u017f" would
		// alias "s". Lower case ASCII names have no other form.
		if !fieldPattern.MatchString(key) {
			return errors.New("seal: field names must be lower case ASCII")
		}
		if seen[key] {
			return errors.New("seal: repeated field")
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}
