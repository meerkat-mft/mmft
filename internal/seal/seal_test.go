package seal

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"mmft.dev/mmft/internal/statement"
)

const (
	sourceID      = "0190f4a2-0000-7000-8000-000000000001"
	destinationID = "0190f4a2-0000-7000-8000-000000000002"
	deliveryA     = "0190f4a2-0000-7000-8000-00000000000a"
	deliveryB     = "0190f4a2-0000-7000-8000-00000000000b"
)

type fixture struct {
	identity *age.HybridIdentity
	agent    *statement.Signer
	source   statement.Verifier
	spool    string
	dest     string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := statement.GenerateSigner(statement.RoleAgent)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		identity: id,
		agent:    agent,
		source:   statement.Verifier{Key: agent.Public(), Role: statement.RoleAgent, Owner: sourceID},
		spool:    t.TempDir(),
		dest:     t.TempDir(),
	}
}

func delivery(id string) Delivery {
	return Delivery{DeliveryID: id, SourceAgent: sourceID, DestinationAgent: destinationID}
}

func writeSource(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// sealAndSign seals data for one delivery and returns the sealed file and the
// manifest as the destination would verify it.
func (f *fixture) sealAndSign(t *testing.T, data []byte, d Delivery) (Sealed, Manifest) {
	t.Helper()
	s, err := Seal(writeSource(t, data), f.spool, f.identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	e, err := SignManifest(d, s, f.agent)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := VerifyManifest(raw, f.source, d)
	if err != nil {
		t.Fatal(err)
	}
	return s, m
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s holds %d files, want none", dir, len(entries))
	}
}

// countingIdentity records whether decryption was attempted.
type countingIdentity struct {
	inner  age.Identity
	calls  int
	before func()
}

func (c *countingIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	c.calls++
	if c.before != nil {
		c.before()
	}
	return c.inner.Unwrap(stanzas)
}

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 7} {
		data := randomBytes(t, size)
		s, m := f.sealAndSign(t, data, delivery(deliveryA))
		if s.Size < 0 || uint64(s.Size) > MaxSealedSize(int64(size)) { // #nosec G115 -- checked above.
			t.Errorf("size %d: sealed %d bytes, bound %d", size, s.Size, MaxSealedSize(int64(size)))
		}
		path, err := Open(s.Path, m, f.identity, f.dest)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: plaintext differs", size)
		}
		if filepath.Dir(path) != filepath.Clean(f.dest) {
			t.Fatalf("opened into %s, want %s", path, f.dest)
		}
	}
}

func TestSealUsesFreshKey(t *testing.T) {
	f := newFixture(t)
	src := writeSource(t, []byte("same plaintext"))
	a, err := Seal(src, f.spool, f.identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(src, f.spool, f.identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256 == b.SHA256 {
		t.Fatal("two seals of one file have the same hash")
	}
}

func TestSpoolFileIsPrivate(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX permissions")
	}
	f := newFixture(t)
	s, _ := f.sealAndSign(t, []byte("x"), delivery(deliveryA))
	info, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("sealed file mode %v, want 0600", info.Mode().Perm())
	}
}

// TestTamperedFileIsNeverDecrypted proves the Done-when criterion of #17: a
// changed, truncated, or swapped sealed file is refused before any decryption.
func TestTamperedFileIsNeverDecrypted(t *testing.T) {
	f := newFixture(t)
	data := randomBytes(t, 3*chunkSize+100)
	other := randomBytes(t, 3*chunkSize+100)

	cases := []struct {
		name   string
		mutate func(t *testing.T, path string, sealed []byte, otherPath string)
		want   error
	}{
		{"changed header byte", func(t *testing.T, path string, b []byte, _ string) {
			b[30] ^= 1
			write(t, path, b)
		}, ErrHashMismatch},
		{"changed payload byte", func(t *testing.T, path string, b []byte, _ string) {
			b[len(b)/2] ^= 1
			write(t, path, b)
		}, ErrHashMismatch},
		{"changed last byte", func(t *testing.T, path string, b []byte, _ string) {
			b[len(b)-1] ^= 1
			write(t, path, b)
		}, ErrHashMismatch},
		{"truncated by one byte", func(t *testing.T, path string, b []byte, _ string) {
			write(t, path, b[:len(b)-1])
		}, ErrSizeMismatch},
		{"truncated at a chunk", func(t *testing.T, path string, b []byte, _ string) {
			write(t, path, b[:len(b)-100-tagSize])
		}, ErrSizeMismatch},
		{"empty", func(t *testing.T, path string, _ []byte, _ string) {
			write(t, path, nil)
		}, ErrSizeMismatch},
		{"extra byte", func(t *testing.T, path string, b []byte, _ string) {
			write(t, path, append(b, 0))
		}, ErrSizeMismatch},
		{"swapped for another delivery's sealed file", func(t *testing.T, path string, _ []byte, otherPath string) {
			b, err := os.ReadFile(otherPath)
			if err != nil {
				t.Fatal(err)
			}
			write(t, path, b)
		}, ErrHashMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, m := f.sealAndSign(t, data, delivery(deliveryA))
			o, _ := f.sealAndSign(t, other, delivery(deliveryB))
			sealed, err := os.ReadFile(s.Path)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, s.Path, sealed, o.Path)

			dest := t.TempDir()
			id := &countingIdentity{inner: f.identity}
			_, err = open(s.Path, m, id, dest)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if id.calls != 0 {
				t.Fatal("decryption was attempted")
			}
			assertEmpty(t, dest)
		})
	}
}

// A sealed file that changes after the hash check, while it is being decrypted,
// must still be refused, and no plaintext may be left behind.
func TestChangeDuringOpenIsRefused(t *testing.T) {
	f := newFixture(t)
	data := randomBytes(t, 3*chunkSize)
	s, m := f.sealAndSign(t, data, delivery(deliveryA))
	sealed, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	id := &countingIdentity{inner: f.identity, before: func() {
		changed := bytes.Clone(sealed)
		changed[len(changed)-1] ^= 1
		write(t, s.Path, changed)
	}}
	if _, err := open(s.Path, m, id, dest); err == nil {
		t.Fatal("opened a sealed file that changed during decryption")
	}
	assertEmpty(t, dest)
}

// Replacing the sealed file with another valid one after the first hash check
// must be caught by the second check, and the plaintext removed.
func TestSwapDuringOpenIsRefused(t *testing.T) {
	f := newFixture(t)
	data := randomBytes(t, 3*chunkSize)
	s, m := f.sealAndSign(t, data, delivery(deliveryA))
	o, _ := f.sealAndSign(t, data, delivery(deliveryB))
	other, err := os.ReadFile(o.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { afterHashCheck = func() {} })
	afterHashCheck = func() { write(t, s.Path, other) }

	dest := t.TempDir()
	if _, err := Open(s.Path, m, f.identity, dest); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("got %v, want ErrHashMismatch", err)
	}
	assertEmpty(t, dest)
}

// A source file that grows or shrinks after its size is checked is refused, and
// nothing is left in the spool.
func TestSourceChangeDuringSealIsRefused(t *testing.T) {
	change := map[string]func(t *testing.T, path string){
		"grown": func(t *testing.T, path string) {
			out, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = out.Close() }()
			if _, err := out.Write([]byte("more")); err != nil {
				t.Fatal(err)
			}
		},
		"truncated": func(t *testing.T, path string) {
			if err := os.Truncate(path, 10); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, fn := range change {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			src := writeSource(t, randomBytes(t, 1000))
			t.Cleanup(func() { freeSpace = freeBytes })
			freeSpace = func(dir string) (uint64, error) {
				fn(t, src)
				return freeBytes(dir)
			}
			if _, err := Seal(src, f.spool, f.identity.Recipient()); !errors.Is(err, ErrSourceChanged) {
				t.Fatalf("got %v, want ErrSourceChanged", err)
			}
			assertEmpty(t, f.spool)
		})
	}
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func signedManifest(t *testing.T, f *fixture, d Delivery) []byte {
	t.Helper()
	s, err := Seal(writeSource(t, []byte("data")), f.spool, f.identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	e, err := SignManifest(d, s, f.agent)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyManifestBindsDelivery(t *testing.T) {
	f := newFixture(t)
	d := delivery(deliveryA)
	d.FlowID = "0190f4a2-0000-7000-8000-0000000000f1"
	d.FlowVersion = 3
	raw := signedManifest(t, f, d)

	if _, id, err := VerifyManifest(raw, f.source, d); err != nil || len(id) != 64 {
		t.Fatalf("valid manifest: id %q, err %v", id, err)
	}

	mismatch := map[string]func(*Delivery){
		"delivery":          func(d *Delivery) { d.DeliveryID = deliveryB },
		"flow":              func(d *Delivery) { d.FlowID = "0190f4a2-0000-7000-8000-0000000000f2" },
		"flow version":      func(d *Delivery) { d.FlowVersion = 2 },
		"manual run":        func(d *Delivery) { d.FlowID, d.FlowVersion = "", 0 },
		"destination agent": func(d *Delivery) { d.DestinationAgent = "0190f4a2-0000-7000-8000-000000000003" },
	}
	for name, change := range mismatch {
		want := d
		change(&want)
		if _, _, err := VerifyManifest(raw, f.source, want); !errors.Is(err, ErrManifestMismatch) {
			t.Errorf("%s: got %v, want ErrManifestMismatch", name, err)
		}
	}
}

func TestVerifyManifestChecksSigner(t *testing.T) {
	f := newFixture(t)
	d := delivery(deliveryA)
	raw := signedManifest(t, f, d)

	other, err := statement.GenerateSigner(statement.RoleAgent)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := statement.Verifier{Key: other.Public(), Role: statement.RoleAgent, Owner: sourceID}
	if _, _, err := VerifyManifest(raw, wrongKey, d); !errors.Is(err, statement.ErrNotEnoughSigners) {
		t.Errorf("other agent's key: got %v", err)
	}

	wrongOwner := f.source
	wrongOwner.Owner = destinationID
	if _, _, err := VerifyManifest(raw, wrongOwner, d); !errors.Is(err, ErrManifestMismatch) {
		t.Errorf("verifier for another agent: got %v", err)
	}

	wrongRole := f.source
	wrongRole.Role = statement.RoleAdministrator
	if _, _, err := VerifyManifest(raw, wrongRole, d); !errors.Is(err, ErrManifestMismatch) {
		t.Errorf("non-agent role: got %v", err)
	}

	var e statement.Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"sealed_size":`), []byte(`"sealed_size":1`), 1)
	e.Payload = base64.StdEncoding.EncodeToString(payload)
	changed, err := json.Marshal(&e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyManifest(changed, f.source, d); !errors.Is(err, statement.ErrNotEnoughSigners) {
		t.Errorf("changed payload: got %v", err)
	}
}

func TestVerifyManifestRejectsBadPayloads(t *testing.T) {
	f := newFixture(t)
	d := delivery(deliveryA)
	hash := strings.Repeat("ab", 32)
	fields := func(formatVersion, size int, sum string) string {
		return fmt.Sprintf(`"version":1,"delivery_id":%q,"source_agent":%q,"destination_agent":%q,`+
			`"format_version":%d,"sealed_size":%d,"sealed_sha256":%q`,
			deliveryA, sourceID, destinationID, formatVersion, size, sum)
	}
	valid := fields(1, 10, hash)
	if _, _, err := VerifyManifest(sign(t, f, "{"+valid+"}"), f.source, d); err != nil {
		t.Fatalf("baseline payload: %v", err)
	}

	payloads := map[string]string{
		"file name":        "{" + valid + `,"file_name":"invoice.pdf"}`,
		"repeated field":   "{" + valid + `,"sealed_size":11}`,
		"upper case field": "{" + valid + `,"Sealed_Size":11}`,
		"unicode alias":    "{" + valid + `,"ſealed_ſize":11}`,
		"trailing data":    "{" + valid + "}{}",
		"format version":   "{" + fields(2, 10, hash) + "}",
		"short hash":       "{" + fields(1, 10, "abcd") + "}",
		"upper case hash":  "{" + fields(1, 10, strings.ToUpper(hash)) + "}",
		"zero size":        "{" + fields(1, 0, hash) + "}",
	}
	for name, p := range payloads {
		if _, _, err := VerifyManifest(sign(t, f, p), f.source, d); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("%s: got %v, want ErrInvalidManifest", name, err)
		}
	}
}

func sign(t *testing.T, f *fixture, payload string) []byte {
	t.Helper()
	e, err := statement.Sign(statement.TypeDeliveryManifest, []byte(payload), f.agent)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestManifestHoldsNoFileName(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(t.TempDir(), "quarterly-invoices.csv")
	write(t, src, []byte("data"))
	s, err := Seal(src, f.spool, f.identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(s.Path), []byte("quarterly")) {
		t.Fatalf("spool path %s reveals the file name", s.Path)
	}
	e, err := SignManifest(delivery(deliveryA), s, f.agent)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("quarterly")) {
		t.Fatalf("manifest holds the file name: %s", payload)
	}
}

func TestSignManifestRejectsInvalidDelivery(t *testing.T) {
	f := newFixture(t)
	s := Sealed{Size: 10}
	bad := map[string]Delivery{
		"not a uuid":       {DeliveryID: "x", SourceAgent: sourceID, DestinationAgent: destinationID},
		"same agents":      {DeliveryID: deliveryA, SourceAgent: sourceID, DestinationAgent: sourceID},
		"flow, no version": {DeliveryID: deliveryA, FlowID: deliveryB, SourceAgent: sourceID, DestinationAgent: destinationID},
		"version, no flow": {DeliveryID: deliveryA, FlowVersion: 1, SourceAgent: sourceID, DestinationAgent: destinationID},
	}
	for name, d := range bad {
		if _, err := SignManifest(d, s, f.agent); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestSealChecksFreeSpace(t *testing.T) {
	f := newFixture(t)
	data := randomBytes(t, 1000)
	need := MaxSealedSize(int64(len(data)))
	t.Cleanup(func() { freeSpace = freeBytes })

	freeSpace = func(string) (uint64, error) { return need - 1, nil }
	_, err := Seal(writeSource(t, data), f.spool, f.identity.Recipient())
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("got %v, want ErrNoSpace", err)
	}
	assertEmpty(t, f.spool)

	freeSpace = func(string) (uint64, error) { return need, nil }
	if _, err := Seal(writeSource(t, data), f.spool, f.identity.Recipient()); err != nil {
		t.Fatalf("exactly enough space: %v", err)
	}
}

func TestFreeBytes(t *testing.T) {
	n, err := freeBytes(t.TempDir())
	if err != nil || n == 0 {
		t.Fatalf("free bytes %d, err %v", n, err)
	}
	if _, err := freeBytes(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("no error for a missing directory")
	}
}
