package allowlist

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	agentA = "0190a0b0-0000-7000-8000-00000000000a"
	agentB = "0190a0b0-0000-7000-8000-00000000000b"
)

// dirs makes directories under a fresh temporary directory and returns their
// paths, keyed by name and by the name of each parent, such as "out" for
// "out/sub".
func dirs(t *testing.T, names ...string) map[string]string {
	t.Helper()
	base := t.TempDir()
	out := map[string]string{"": base}
	for _, n := range names {
		if err := os.MkdirAll(filepath.Join(base, n), 0o700); err != nil {
			t.Fatal(err)
		}
		for p := n; p != "."; p = filepath.Dir(p) {
			out[p] = filepath.Join(base, p)
		}
	}
	return out
}

func parse(t *testing.T, doc string) *Allowlist {
	t.Helper()
	a, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyAllowlistDeniesEverything(t *testing.T) {
	d := dirs(t, "x")
	for name, doc := range map[string]string{
		"no bytes":      "",
		"comments only": "# nothing allowed yet\n",
		"empty mapping": "{}\n",
	} {
		t.Run(name, func(t *testing.T) {
			a := parse(t, doc)
			denies(t, a, d["x"])
			if a.Hash() != sha256.Sum256([]byte(doc)) {
				t.Error("the hash is not of the file's bytes")
			}
		})
	}
	t.Run("nil", func(t *testing.T) {
		var a *Allowlist
		denies(t, a, d["x"])
		if a.Hash() != sha256.Sum256(nil) {
			t.Error("a nil allowlist has the wrong hash")
		}
	})
}

func denies(t *testing.T, a *Allowlist, dir string) {
	t.Helper()
	for _, access := range []Access{Read, Write} {
		if _, err := a.Dir(dir, access); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("access %d: got %v", access, err)
		}
	}
	if a.MaySendTo(agentB, "lab") || a.MayReceiveFrom(agentB, "lab") {
		t.Error("a peer is allowed")
	}
	if a.Approvals() != 0 || a.Includes(dir) {
		t.Error("the allowlist is not empty")
	}
}

func TestParseRefusesWhatItCantReadExactly(t *testing.T) {
	d := dirs(t, "x")
	file := filepath.Join(d[""], "file")
	write(t, file, "")
	ok := "version: 1\napprovals: 1\n"
	for name, doc := range map[string]string{
		"unknown field":       ok + "reed: [" + d["x"] + "]\n",
		"repeated field":      ok + "approvals: 2\n",
		"other version":       "version: 2\napprovals: 1\n",
		"no version":          "approvals: 1\n",
		"no approvals":        "version: 1\nread: [" + d["x"] + "]\n",
		"negative approvals":  "version: 1\napprovals: -1\n",
		"quoted number":       "version: 1\napprovals: \"2\"\n",
		"relative path":       ok + "read: [srv/outbox]\n",
		"dot-dot path":        ok + "read: [" + d["x"] + "/../x]\n",
		"trailing separator":  ok + "read: [" + d["x"] + "/]\n",
		"null path":           ok + "read: [~]\n",
		"null value":          ok + "read:\n",
		"anchor":              "version: &v 1\napprovals: *v\n",
		"tag":                 ok + "read: [!!str " + d["x"] + "]\n",
		"missing directory":   ok + "write: [" + filepath.Join(d[""], "missing") + "]\n",
		"file as directory":   ok + "read: [" + file + "]\n",
		"peer with both":      ok + "send_to: [{agent: " + agentB + ", workspace: lab}]\n",
		"peer with neither":   ok + "send_to: [{}]\n",
		"peer unknown field":  ok + "send_to: [{name: agent-b}]\n",
		"peer bad agent":      ok + "receive_from: [{agent: agent-b}]\n",
		"peer bad workspace":  ok + "receive_from: [{workspace: \"a b\"}]\n",
		"two documents":       ok + "---\n" + ok,
		"not a mapping":       "- " + d["x"] + "\n",
		"read is not a list":  ok + "read: " + d["x"] + "\n",
		"hidden character":    ok + "read: [\"" + d["x"] + "\\u202e\"]\n",
		"later entry missing": ok + "read: [" + d["x"] + ", " + filepath.Join(d[""], "missing") + "]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if a, err := Parse([]byte(doc)); !errors.Is(err, ErrInvalid) {
				a.Close()
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := Parse([]byte(ok + strings.Repeat("#", maxBytes))); !errors.Is(err, ErrInvalid) {
		t.Errorf("an oversized file: got %v", err)
	}
}

func TestDirAllowsOnlyWhatIsListed(t *testing.T) {
	d := dirs(t, "out", "out/sub", "outbox", "in", "secret")
	a := parse(t, fmt.Sprintf("version: 1\napprovals: 1\nread: [%s]\nwrite: [%s]\n", d["out"], d["in"]))

	for _, p := range []string{d["out"], d["out/sub"]} {
		root, err := a.Dir(p, Read)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		_ = root.Close()
	}
	if _, err := a.Dir(d["in"], Write); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path   string
		access Access
	}{
		"read is not write":          {d["out"], Write},
		"write is not read":          {d["in"], Read},
		"a sibling sharing a prefix": {d["outbox"], Read},
		"the parent":                 {d[""], Read},
		"another directory":          {d["secret"], Read},
		"dot-dot back in":            {d["out"] + "/../out", Read},
		"dot-dot out":                {d["out"] + "/../secret", Read},
		"relative":                   {"out", Read},
		"trailing separator":         {d["out"] + "/", Read},
		"doubled separator":          {d["out"] + "//sub", Read},
		"empty":                      {"", Read},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := a.Dir(tc.path, tc.access); !errors.Is(err, ErrNotAllowed) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestDirResolvesLinksBeforeTheCheck(t *testing.T) {
	d := dirs(t, "out", "out/sub", "secret")
	a := parse(t, fmt.Sprintf("version: 1\napprovals: 1\nread: [%s]\n", d["out"]))
	// A link inside the entry that leads out of it is denied.
	escape := filepath.Join(d["out"], "escape")
	if err := os.Symlink(d["secret"], escape); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Dir(escape, Read); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a link out of the entry: got %v", err)
	}
	// A link outside the entry that leads into it is allowed, because the
	// resolved path is what is checked.
	in := filepath.Join(d["secret"], "in")
	if err := os.Symlink(d["out/sub"], in); err != nil {
		t.Fatal(err)
	}
	root, err := a.Dir(in, Read)
	if err != nil {
		t.Fatalf("a link into the entry: %v", err)
	}
	_ = root.Close()
	// An entry written through a link is held as its resolved directory.
	link := filepath.Join(d[""], "link")
	if err := os.Symlink(d["out"], link); err != nil {
		t.Fatal(err)
	}
	b := parse(t, fmt.Sprintf("version: 1\napprovals: 1\nread: [%s]\n", link))
	if root, err := b.Dir(d["out/sub"], Read); err != nil {
		t.Fatalf("under a linked entry: %v", err)
	} else {
		_ = root.Close()
	}
}

// swapAfterCheck replaces path with a link to target once the check has
// passed. The link is relative, as an attacker would make it, because the
// directory handle refuses any absolute link outright, which would hide
// whether the opened file is compared with the checked one.
func swapAfterCheck(t *testing.T, path, target string) {
	t.Helper()
	moved := path + ".moved"
	rel, err := filepath.Rel(filepath.Dir(path), target)
	if err != nil {
		t.Fatal(err)
	}
	afterCheck = func() {
		if err := os.Rename(path, moved); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(rel, path); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterCheck = func() {} })
}

func TestDirRefusesALinkSwappedInAfterTheCheck(t *testing.T) {
	for name, target := range map[string]string{
		"to a directory outside the entry": "secret",
		"to another directory inside it":   "out/other",
	} {
		t.Run(name, func(t *testing.T) {
			d := dirs(t, "out/sub", "out/other", "secret")
			a := parse(t, fmt.Sprintf("version: 1\napprovals: 1\nwrite: [%s]\n", d["out"]))
			swapAfterCheck(t, d["out/sub"], d[target])
			root, err := a.Dir(d["out/sub"], Write)
			if !errors.Is(err, ErrSwapped) {
				if root != nil {
					_ = root.Close()
				}
				t.Fatalf("got %v", err)
			}
		})
	}
	// A parent directory swapped for a link out of the entry.
	t.Run("a parent directory", func(t *testing.T) {
		d := dirs(t, "out/mid/sub", "secret/sub")
		a := parse(t, fmt.Sprintf("version: 1\napprovals: 1\nread: [%s]\n", d["out"]))
		swapAfterCheck(t, d["out/mid"], d["secret"])
		if _, err := a.Dir(d["out/mid/sub"], Read); !errors.Is(err, ErrSwapped) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestOpenRegularRefusesLinksAndSwaps(t *testing.T) {
	d := dirs(t, "out", "secret")
	write(t, filepath.Join(d["out"], "report.csv"), "report")
	write(t, filepath.Join(d["out"], "other.csv"), "other")
	write(t, filepath.Join(d["secret"], "key"), "secret")
	if err := os.Symlink(filepath.Join(d["secret"], "key"), filepath.Join(d["out"], "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d["out"], "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	a := parse(t, fmt.Sprintf("version: 1\napprovals: 1\nread: [%s]\n", d["out"]))
	root, err := a.Dir(d["out"], Read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	f, err := OpenRegular(root, "report.csv")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	_ = f.Close()
	if string(got) != "report" {
		t.Fatalf("read %q", got)
	}
	for _, name := range []string{"link", "dir"} {
		if _, err := OpenRegular(root, name); !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := OpenRegular(root, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: got %v", err)
	}
	for target, path := range map[string]string{"outside": filepath.Join(d["secret"], "key"), "inside": filepath.Join(d["out"], "other.csv")} {
		t.Run("swapped for a link "+target, func(t *testing.T) {
			swapAfterCheck(t, filepath.Join(d["out"], "report.csv"), path)
			t.Cleanup(func() {
				_ = os.Remove(filepath.Join(d["out"], "report.csv"))
				_ = os.Rename(filepath.Join(d["out"], "report.csv.moved"), filepath.Join(d["out"], "report.csv"))
			})
			f, err := OpenRegular(root, "report.csv")
			if !errors.Is(err, ErrSwapped) {
				if f != nil {
					_ = f.Close()
				}
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestErrorsHoldNoPath(t *testing.T) {
	d := dirs(t, "out")
	a := parse(t, fmt.Sprintf("version: 1\napprovals: 1\nread: [%s]\n", d["out"]))
	missing := filepath.Join(d["out"], "private-name")
	if _, err := a.Dir(missing, Read); err == nil || strings.Contains(err.Error(), "private-name") {
		t.Errorf("got %v", err)
	}
	root, err := a.Dir(d["out"], Read)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := OpenRegular(root, "private-name"); err == nil || strings.Contains(err.Error(), "private-name") {
		t.Errorf("got %v", err)
	}
}

func TestPeers(t *testing.T) {
	a := parse(t, fmt.Sprintf("version: 1\napprovals: 2\nsend_to: [{agent: %s}]\nreceive_from: [{workspace: finance}]\n", agentB))
	if a.Approvals() != 2 {
		t.Errorf("approvals %d", a.Approvals())
	}
	for name, tc := range map[string]struct {
		got, want bool
	}{
		"send to the listed agent":          {a.MaySendTo(agentB, "lab"), true},
		"send to another agent":             {a.MaySendTo(agentA, "lab"), false},
		"send to the listed workspace only": {a.MaySendTo(agentA, "finance"), false},
		"receive from the workspace":        {a.MayReceiveFrom(agentA, "finance"), true},
		"receive from another workspace":    {a.MayReceiveFrom(agentA, "lab"), false},
		"receive from the send-only agent":  {a.MayReceiveFrom(agentB, "lab"), false},
		"no workspace":                      {a.MaySendTo(agentB, ""), false},
		"no agent":                          {a.MayReceiveFrom("", "finance"), false},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %v", name, tc.got)
		}
	}
}

func TestIncludes(t *testing.T) {
	d := dirs(t, "out", "in/sub", "spool")
	a := parse(t, fmt.Sprintf("version: 1\napprovals: 1\nread: [%s]\nwrite: [%s]\n", d["out"], d["in"]))
	for p, want := range map[string]bool{d["out"]: true, d["in/sub"]: true, d["spool"]: false, d[""]: false} {
		if a.Includes(p) != want {
			t.Errorf("%s: got %v", p, !want)
		}
	}
}
