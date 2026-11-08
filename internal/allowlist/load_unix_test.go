//go:build unix

package allowlist

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// stat is a file's owner and mode, as rootOnly sees them.
type stat struct {
	uid  uint32
	mode fs.FileMode
}

func (s stat) Name() string       { return "x" }
func (s stat) Size() int64        { return 0 }
func (s stat) Mode() fs.FileMode  { return s.mode }
func (s stat) ModTime() time.Time { return time.Time{} }
func (s stat) IsDir() bool        { return s.mode.IsDir() }
func (s stat) Sys() any           { return &syscall.Stat_t{Uid: s.uid} }

func TestOnlyRootMayChangeTheAllowlist(t *testing.T) {
	file := stat{0, 0o644}
	dir := stat{0, fs.ModeDir | 0o755}
	const agent = 999
	ok := []fs.FileInfo{file, dir, dir}
	if err := rootOnly(ok, agent); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		chain []fs.FileInfo
		euid  int
	}{
		"the agent runs as root":             {ok, 0},
		"the file is the agent's":            {[]fs.FileInfo{stat{agent, 0o444}, dir, dir}, agent},
		"the file is another user's":         {[]fs.FileInfo{stat{1, 0o644}, dir, dir}, agent},
		"group can write the file":           {[]fs.FileInfo{stat{0, 0o664}, dir, dir}, agent},
		"others can write the file":          {[]fs.FileInfo{stat{0, 0o646}, dir, dir}, agent},
		"its directory is the agent's":       {[]fs.FileInfo{file, stat{agent, fs.ModeDir | 0o755}, dir}, agent},
		"group can write its directory":      {[]fs.FileInfo{file, stat{0, fs.ModeDir | 0o775}, dir}, agent},
		"others can write a directory above": {[]fs.FileInfo{file, dir, stat{0, fs.ModeDir | fs.ModeSticky | 0o777}}, agent},
		"no owner":                           {[]fs.FileInfo{noOwner{file}, dir}, agent},
	} {
		if err := rootOnly(tc.chain, tc.euid); !errors.Is(err, ErrUnprotected) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

type noOwner struct{ stat }

func (noOwner) Sys() any { return nil }

// trustAll lets Load read files the test owns, and records what it checked.
func trustAll(t *testing.T) *[]fs.FileInfo {
	t.Helper()
	var seen []fs.FileInfo
	protected = func(chain []fs.FileInfo, _ int) error {
		seen = chain
		return nil
	}
	t.Cleanup(func() { protected = rootOnly })
	return &seen
}

func TestLoad(t *testing.T) {
	seen := trustAll(t)
	d := dirs(t, "etc", "out")
	path := filepath.Join(d["etc"], "allowlist.yaml")
	doc := "version: 1\napprovals: 1\nread: [" + d["out"] + "]\n"
	write(t, path, doc)
	a, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.Hash() != sha256.Sum256([]byte(doc)) {
		t.Error("the hash is not of the file's bytes")
	}
	if root, err := a.Dir(d["out"], Read); err != nil {
		t.Fatal(err)
	} else {
		_ = root.Close()
	}
	// The file and every directory up to the root were checked.
	resolved, _ := filepath.EvalSymlinks(path)
	want := 1
	for p := filepath.Dir(resolved); ; p = filepath.Dir(p) {
		want++
		if p == filepath.Dir(p) {
			break
		}
	}
	if len(*seen) != want || !(*seen)[0].Mode().IsRegular() || !(*seen)[len(*seen)-1].IsDir() {
		t.Fatalf("checked %d entries, want %d", len(*seen), want)
	}
}

func TestLoadWithoutAFileDeniesEverything(t *testing.T) {
	trustAll(t)
	d := dirs(t, "etc", "out")
	for name, path := range map[string]string{
		"no file":      filepath.Join(d["etc"], "allowlist.yaml"),
		"no directory": filepath.Join(d[""], "missing", "allowlist.yaml"),
	} {
		a, err := Load(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		denies(t, a, d["out"])
		if a.Hash() != sha256.Sum256(nil) {
			t.Errorf("%s: wrong hash", name)
		}
	}
}

func TestLoadRefusesUnsafeFiles(t *testing.T) {
	trustAll(t)
	d := dirs(t, "etc")
	target := filepath.Join(d["etc"], "real.yaml")
	write(t, target, "")
	link := filepath.Join(d["etc"], "allowlist.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); !errors.Is(err, ErrUnprotected) {
		t.Errorf("a linked file: got %v", err)
	}
	if _, err := Load(d["etc"]); !errors.Is(err, ErrUnprotected) {
		t.Errorf("a directory: got %v", err)
	}
	fifo := filepath.Join(d["etc"], "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(fifo); !errors.Is(err, ErrUnprotected) {
		t.Errorf("a fifo: got %v", err)
	}
	if _, err := Load("allowlist.yaml"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a relative path: got %v", err)
	}

	// The real check refuses a file the test, not root, owns.
	protected = rootOnly
	if _, err := Load(target); !errors.Is(err, ErrUnprotected) {
		t.Errorf("a file owned by the agent: got %v", err)
	}
}
