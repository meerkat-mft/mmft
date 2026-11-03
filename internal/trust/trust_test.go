package trust

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"mmft.dev/mmft/internal/statement"
)

const (
	pass  = "correct horse battery staple"
	valid = 30 * 24 * time.Hour
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) {
	scryptWorkFactor = 10
	os.Exit(m.Run())
}

type lab struct {
	root     *statement.Signer
	rootPub  statement.PublicKey
	admin    PublicRecord
	adminFP  string
	adminDir string
}

func setup(t *testing.T) lab {
	t.Helper()
	rootDir, adminDir := t.TempDir(), t.TempDir()
	pub, err := InitRoot(rootDir, pass)
	if err != nil {
		t.Fatal(err)
	}
	root, owner, err := LoadKey(filepath.Join(rootDir, RootKeyFile), pass, statement.RoleRoot)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "root" {
		t.Fatalf("owner = %q", owner)
	}
	adminKey, err := InitAdministrator(adminDir, "sam.lee", pass)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := ReadPublic(filepath.Join(adminDir, AdminPublic))
	if err != nil {
		t.Fatal(err)
	}
	return lab{root: root, rootPub: pub, admin: admin, adminFP: adminKey.Fingerprint(), adminDir: adminDir}
}

func (l lab) certify(admin PublicRecord, adminFP string, lifetime time.Duration) (*statement.Envelope, error) {
	return CertifyAdministrator(l.root, l.rootPub.Fingerprint(), admin, adminFP, now, lifetime)
}

func certificate(t *testing.T, l lab, lifetime time.Duration) []byte {
	t.Helper()
	e, err := l.certify(l.admin, l.adminFP, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAdministratorKeyVerifiesBackToRoot(t *testing.T) {
	l := setup(t)
	v, claim, err := VerifyAdministrator(certificate(t, l, valid), l.rootPub, l.rootPub.Fingerprint(), now)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Owner != "sam.lee" || v.Owner != "sam.lee" || v.Role != statement.RoleAdministrator {
		t.Fatalf("verifier = %+v, claim = %+v", v, claim)
	}
	admin, owner, err := LoadKey(filepath.Join(l.adminDir, AdminKeyFile), pass, statement.RoleAdministrator)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "sam.lee" {
		t.Fatalf("owner = %q", owner)
	}
	e, err := statement.Sign(statement.TypeFlowVersion, []byte("flow"), admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statement.Verify(e, statement.TypeFlowVersion, []statement.Verifier{v}, 1); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAdministratorRejects(t *testing.T) {
	l := setup(t)
	cert := certificate(t, l, valid)
	other, err := statement.GenerateSigner(statement.RoleRoot)
	if err != nil {
		t.Fatal(err)
	}
	fp := l.rootPub.Fingerprint()
	start := now.Add(-clockSkew)

	tests := []struct {
		name   string
		root   statement.PublicKey
		pinned string
		at     time.Time
		want   error
	}{
		{"before it starts", l.rootPub, fp, start.Add(-time.Second), ErrNotYetValid},
		{"at expiry", l.rootPub, fp, start.Add(valid), ErrExpired},
		{"after expiry", l.rootPub, fp, start.Add(valid + time.Hour), ErrExpired},
		{"no pin", l.rootPub, "", now, ErrWrongRoot},
		{"wrong pin", l.rootPub, other.Public().Fingerprint(), now, ErrWrongRoot},
		{"different root that matches its pin", other.Public(), other.Public().Fingerprint(), now, statement.ErrNotEnoughSigners},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := VerifyAdministrator(cert, tt.root, tt.pinned, tt.at); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
	if _, _, err := VerifyAdministrator(cert, l.rootPub, fp, start); err != nil {
		t.Fatalf("first valid moment: %v", err)
	}
	if _, _, err := VerifyAdministrator(cert, l.rootPub, fp, now.Add(-time.Minute)); err != nil {
		t.Fatalf("verifier with a slow clock: %v", err)
	}
}

func TestOtherRootStatementsAreNotCertificates(t *testing.T) {
	l := setup(t)
	good := AdministratorClaim{Version: 1, Owner: "sam", Ed25519: l.admin.Ed25519, MLDSA65: l.admin.MLDSA65, NotBefore: now, NotAfter: now.Add(time.Hour)}
	payload, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	e, err := statement.Sign(statement.TypeRootRollover, payload, l.root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	if _, _, err := VerifyAdministrator(b, l.rootPub, l.rootPub.Fingerprint(), now); !errors.Is(err, statement.ErrWrongType) {
		t.Fatalf("err = %v", err)
	}
}

func signClaim(t *testing.T, l lab, payload []byte) []byte {
	t.Helper()
	e, err := statement.Sign(statement.TypeAdministratorKey, payload, l.root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	return b
}

func TestVerifyAdministratorRejectsBadClaims(t *testing.T) {
	l := setup(t)
	good := AdministratorClaim{Version: 1, Owner: "sam", Ed25519: l.admin.Ed25519, MLDSA65: l.admin.MLDSA65, NotBefore: now, NotAfter: now.Add(time.Hour)}
	encode := func(f func(*AdministratorClaim)) []byte {
		c := good
		f(&c)
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	base := encode(func(*AdministratorClaim) {})
	tests := map[string][]byte{
		"wrong version":     encode(func(c *AdministratorClaim) { c.Version = 2 }),
		"no owner":          encode(func(c *AdministratorClaim) { c.Owner = "" }),
		"root owner":        encode(func(c *AdministratorClaim) { c.Owner = "root" }),
		"upper-case owner":  encode(func(c *AdministratorClaim) { c.Owner = "Sam" }),
		"equal dates":       encode(func(c *AdministratorClaim) { c.NotAfter = c.NotBefore }),
		"inverted dates":    encode(func(c *AdministratorClaim) { c.NotAfter = now.Add(-time.Hour) }),
		"too long":          encode(func(c *AdministratorClaim) { c.NotAfter = now.Add(MaxAdministratorLifetime + time.Second) }),
		"bad key":           encode(func(c *AdministratorClaim) { c.Ed25519 = []byte{1} }),
		"unknown field":     append(bytes.TrimSuffix(bytes.Clone(base), []byte("}")), []byte(`,"role":"root"}`)...),
		"trailing bracket":  append(bytes.Clone(base), ']'),
		"trailing object":   append(bytes.Clone(base), []byte(" {}")...),
		"repeated owner":    append(bytes.TrimSuffix(bytes.Clone(base), []byte("}")), []byte(`,"owner":"mallory"}`)...),
		"cased owner field": append(bytes.TrimSuffix(bytes.Clone(base), []byte("}")), []byte(`,"OWNER":"mallory"}`)...),
		"aliased version":   append(bytes.TrimSuffix(bytes.Replace(base, []byte(`"version":1`), []byte(`"version":2`), 1), []byte("}")), []byte(`,"verſion":1}`)...),
		"payload not JSON":  []byte("not an object"),
	}
	if _, _, err := VerifyAdministrator(signClaim(t, l, base), l.rootPub, l.rootPub.Fingerprint(), now); err != nil {
		t.Fatalf("good claim: %v", err)
	}
	exact := encode(func(c *AdministratorClaim) { c.NotAfter = now.Add(MaxAdministratorLifetime) })
	if _, _, err := VerifyAdministrator(signClaim(t, l, exact), l.rootPub, l.rootPub.Fingerprint(), now); err != nil {
		t.Fatalf("exact lifetime limit: %v", err)
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := VerifyAdministrator(signClaim(t, l, payload), l.rootPub, l.rootPub.Fingerprint(), now); !errors.Is(err, ErrInvalidClaim) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestRootCannotBeAnAdministrator(t *testing.T) {
	l := setup(t)
	ed, ml := l.rootPub.Bytes()
	asAdmin := PublicRecord{Version: 1, Owner: "sam", Ed25519: ed, MLDSA65: ml}
	if _, err := l.certify(asAdmin, l.rootPub.Fingerprint(), time.Hour); !errors.Is(err, ErrRootAsAdmin) {
		t.Fatalf("certify: %v", err)
	}
	claim, err := json.Marshal(AdministratorClaim{Version: 1, Owner: "sam", Ed25519: ed, MLDSA65: ml, NotBefore: now, NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyAdministrator(signClaim(t, l, claim), l.rootPub, l.rootPub.Fingerprint(), now); !errors.Is(err, ErrRootAsAdmin) {
		t.Fatalf("verify: %v", err)
	}
	mixed := PublicRecord{Version: 1, Owner: "sam", Ed25519: ed, MLDSA65: l.admin.MLDSA65}
	key, err := mixed.Key()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.certify(mixed, key.Fingerprint(), time.Hour); !errors.Is(err, ErrRootAsAdmin) {
		t.Fatalf("shared half: %v", err)
	}
	mixed = PublicRecord{Version: 1, Owner: "sam", Ed25519: l.admin.Ed25519, MLDSA65: ml}
	key, err = mixed.Key()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.certify(mixed, key.Fingerprint(), time.Hour); !errors.Is(err, ErrRootAsAdmin) {
		t.Fatalf("shared ML-DSA half: %v", err)
	}
}

func TestCertifyChecksFingerprints(t *testing.T) {
	l := setup(t)
	if _, err := CertifyAdministrator(l.root, "", l.admin, l.adminFP, now, time.Hour); !errors.Is(err, ErrWrongRoot) {
		t.Fatalf("no root pin: %v", err)
	}
	if _, err := CertifyAdministrator(l.root, strings.Repeat("0", 64), l.admin, l.adminFP, now, time.Hour); !errors.Is(err, ErrWrongRoot) {
		t.Fatalf("wrong root pin: %v", err)
	}
	if _, err := l.certify(l.admin, "", time.Hour); !errors.Is(err, ErrWrongAdministrator) {
		t.Fatalf("no admin pin: %v", err)
	}
	if _, err := l.certify(l.admin, strings.Repeat("0", 64), time.Hour); !errors.Is(err, ErrWrongAdministrator) {
		t.Fatalf("swapped request: %v", err)
	}
}

func TestAdministratorCannotCertifyAdministrators(t *testing.T) {
	l := setup(t)
	admin, _, err := LoadKey(filepath.Join(l.adminDir, AdminKeyFile), pass, statement.RoleAdministrator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CertifyAdministrator(admin, admin.Public().Fingerprint(), l.admin, l.rootPub.Fingerprint(), now, time.Hour); err == nil {
		t.Fatal("administrator certified a key")
	}
}

func TestCertifyLimits(t *testing.T) {
	l := setup(t)
	for _, d := range []time.Duration{0, -time.Hour, MaxAdministratorLifetime + time.Second} {
		if _, err := l.certify(l.admin, l.adminFP, d); !errors.Is(err, ErrBadLifetime) {
			t.Errorf("lifetime %v: %v", d, err)
		}
	}
	e, err := l.certify(l.admin, l.adminFP, MaxAdministratorLifetime)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	if _, _, err := VerifyAdministrator(b, l.rootPub, l.rootPub.Fingerprint(), now); err != nil {
		t.Fatalf("longest certificate fails verification: %v", err)
	}
	for _, owner := range []string{"", "root"} {
		bad := l.admin
		bad.Owner = owner
		if _, err := l.certify(bad, l.adminFP, time.Hour); !errors.Is(err, ErrInvalidOwner) {
			t.Fatalf("owner %q: %v", owner, err)
		}
	}
	bad := l.admin
	bad.Ed25519 = []byte{1}
	if _, err := l.certify(bad, l.adminFP, time.Hour); !errors.Is(err, statement.ErrInvalidKey) {
		t.Fatalf("bad key: %v", err)
	}
}

func TestOwnerGrammar(t *testing.T) {
	for _, owner := range []string{"alex", "a", "sam.lee", "ops-1", "pipeline_a", "alex@example.com", strings.Repeat("a", 64)} {
		if !ValidOwner(owner) {
			t.Errorf("%q rejected", owner)
		}
	}
	for _, owner := range []string{
		"", "root", "Alex", "Root", " root", "alex ", " alex", "al\u200bex", "a\x00b", "alex\nowner: bob", ".alex", "-alex",
		"al ex", strings.Repeat("a", 65), "ålex",
	} {
		if ValidOwner(owner) {
			t.Errorf("%q accepted", owner)
		}
	}
}

func TestAdministratorOwnerIsValidated(t *testing.T) {
	for _, owner := range []string{"", "root", "Alex", "alex "} {
		dir := t.TempDir()
		if _, err := InitAdministrator(dir, owner, pass); !errors.Is(err, ErrInvalidOwner) {
			t.Errorf("owner %q: %v", owner, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("owner %q left files: %v", owner, entries)
		}
	}
}

func TestPrivateKeysAreNeverWrittenInTheClear(t *testing.T) {
	cases := []struct {
		name, key string
		role      statement.Role
		init      func(string) error
	}{
		{"root", RootKeyFile, statement.RoleRoot, func(d string) error { _, err := InitRoot(d, pass); return err }},
		{"administrator", AdminKeyFile, statement.RoleAdministrator, func(d string) error { _, err := InitAdministrator(d, "sam", pass); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := c.init(dir); err != nil {
				t.Fatal(err)
			}
			s, _, err := LoadKey(filepath.Join(dir, c.key), pass, c.role)
			if err != nil {
				t.Fatal(err)
			}
			edSeed, mlSeed := s.Seeds()
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 2 {
				t.Fatalf("files = %v", entries)
			}
			secrets := [][]byte{edSeed, mlSeed, []byte(hex.EncodeToString(edSeed)), []byte(hex.EncodeToString(mlSeed)), []byte(pass), []byte("ed25519_seed")}
			for _, entry := range entries {
				data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range secrets {
					if bytes.Contains(data, secret) {
						t.Fatalf("%s contains secret material", entry.Name())
					}
				}
			}
		})
	}
}

func TestKeyFilesUseTheProductionWorkFactor(t *testing.T) {
	if defaultWorkFactor != 18 {
		t.Fatalf("default work factor = %d", defaultWorkFactor)
	}
	dir := t.TempDir()
	if _, err := InitRoot(dir, pass); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, RootKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(key), "\n")
	if lines[0] != "age-encryption.org/v1" {
		t.Fatalf("header = %q", lines[0])
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 4 || fields[0] != "->" || fields[1] != "scrypt" {
		t.Fatalf("stanza = %q", lines[1])
	}
	if got, err := strconv.Atoi(fields[3]); err != nil || got != scryptWorkFactor {
		t.Fatalf("work factor = %q, want %d", fields[3], scryptWorkFactor)
	}
}

func TestKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := filepath.Join(t.TempDir(), "new")
	if _, err := InitRoot(dir, pass); err != nil {
		t.Fatal(err)
	}
	adminDir := filepath.Join(t.TempDir(), "new")
	if _, err := InitAdministrator(adminDir, "sam", pass); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		dir: 0o700, filepath.Join(dir, RootKeyFile): 0o600,
		adminDir: 0o700, filepath.Join(adminDir, AdminKeyFile): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
	}
}

func TestPublicFilesAreReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	if _, err := InitRoot(dir, pass); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, RootPublic))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("mode = %o", got)
	}
}

func TestUnsafeLocationsAreRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	for _, mode := range []os.FileMode{0o777, 0o770, 0o707} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := InitRoot(dir, pass); !errors.Is(err, ErrNotPrivate) {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := InitRoot(link, pass); !errors.Is(err, ErrNotPrivate) {
		t.Errorf("symlinked directory: %v", err)
	}

	dir := t.TempDir()
	if _, err := InitRoot(dir, pass); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, RootKeyFile)
	for _, mode := range []os.FileMode{0o640, 0o604, 0o666} {
		if err := os.Chmod(key, mode); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadKey(key, pass, statement.RoleRoot); !errors.Is(err, ErrNotPrivate) {
			t.Errorf("key mode %o: %v", mode, err)
		}
	}
}

func TestDanglingSymlinkIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "stolen")
	if err := os.Symlink(outside, filepath.Join(dir, RootKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := InitRoot(dir, pass); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrote through the link: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("files left behind: %v", entries)
	}
}

func TestExistingKeysAreNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	if _, err := InitRoot(dir, pass); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	key, pub := read(RootKeyFile), read(RootPublic)
	if _, err := InitRoot(dir, pass); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(key, read(RootKeyFile)) || !bytes.Equal(pub, read(RootPublic)) {
		t.Fatal("key files changed")
	}
}

func TestFailedKeyWriteLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, RootPublic), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InitRoot(dir, pass); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, RootKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan key: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

func TestPassphraseStrength(t *testing.T) {
	for _, p := range []string{"", "short", strings.Repeat("a", MinPassphraseBytes-1), strings.Repeat(" ", 32), strings.Repeat("\t", 32)} {
		dir := t.TempDir()
		if _, err := InitRoot(dir, p); !errors.Is(err, ErrWeakPassphrase) {
			t.Errorf("%q: %v", p, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%q left files: %v", p, entries)
		}
	}
	if err := CheckPassphrase(strings.Repeat("a", MinPassphraseBytes)); err != nil {
		t.Fatal(err)
	}
}

func TestReadPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pass")
	if err := os.WriteFile(path, []byte(pass+" \r\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPassphrase(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != pass+" " {
		t.Fatalf("passphrase = %q", got)
	}
	if runtime.GOOS != "windows" {
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadPassphrase(path); !errors.Is(err, ErrNotPrivate) {
				t.Errorf("mode %o: %v", mode, err)
			}
		}
	}
	if _, err := ReadPassphrase(dir); err == nil {
		t.Error("directory accepted")
	}
	secret := "this-was-the-passphrase-itself"
	if _, err := ReadPassphrase(secret); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("error repeats the argument: %v", err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxPassphrase+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassphrase(big); err == nil {
		t.Error("oversized file accepted")
	}
}

func sealedKey(t *testing.T, content []byte) string {
	t.Helper()
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(scryptWorkFactor)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadKeyChecks(t *testing.T) {
	dir := t.TempDir()
	if _, err := InitRoot(dir, pass); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, RootKeyFile)
	if _, _, err := LoadKey(path, pass+"x", statement.RoleRoot); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, _, err := LoadKey(path, pass, statement.RoleAdministrator); !errors.Is(err, ErrWrongKeyFile) {
		t.Fatalf("wrong role: %v", err)
	}
	seed := make([]byte, 32)
	good := keyFile{Version: 1, Role: int(statement.RoleRoot), Owner: "root", Ed25519: seed, MLDSA65: seed}
	encode := func(f func(*keyFile)) []byte {
		k := good
		f(&k)
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	base := encode(func(*keyFile) {})
	if _, _, err := LoadKey(sealedKey(t, base), pass, statement.RoleRoot); err != nil {
		t.Fatalf("good key: %v", err)
	}
	for name, content := range map[string][]byte{
		"wrong version": encode(func(k *keyFile) { k.Version = 2 }),
		"short seed":    encode(func(k *keyFile) { k.Ed25519 = []byte{1} }),
		"unknown field": append(bytes.TrimSuffix(bytes.Clone(base), []byte("}")), []byte(`,"x":1}`)...),
		"not JSON":      []byte("nope"),
	} {
		if _, _, err := LoadKey(sealedKey(t, content), pass, statement.RoleRoot); !errors.Is(err, ErrWrongKeyFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReadPublicRejects(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not JSON":         "{",
		"unknown field":    `{"version":1,"private":"x"}`,
		"wrong version":    `{"version":2}`,
		"trailing data":    `{"version":1} {}`,
		"trailing bracket": `{"version":1}]`,
		"repeated field":   `{"version":1,"owner":"a","owner":"b"}`,
		"cased field":      `{"version":1,"OWNER":"a"}`,
		"aliased field":    `{"version":2,"verſion":1}`,
		"not an object":    `[]`,
	} {
		path := filepath.Join(dir, "pub")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPublic(path); !errors.Is(err, ErrInvalidPublic) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
