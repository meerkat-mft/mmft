// Package allowlist reads and enforces an agent allowlist: the directories an
// agent may read and write, the agents it may send to and receive from, and how
// many administrators must approve a flow. It is a file on the agent's host
// that the orchestrator can't change. See ADR 0013 and ADR 0024.
//
// Every path is checked in its canonical absolute form with its links
// resolved, and then opened through a directory handle that the agent holds
// open for each allowlist entry. A link swapped in after the check can't lead
// out of the entry, and the opened file or directory must be the one checked.
package allowlist

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"mmft.dev/mmft/internal/flow"
	"mmft.dev/mmft/internal/trust"
)

// DefaultPath is where the agent reads its allowlist on Linux.
const DefaultPath = "/etc/mmft/allowlist.yaml"

// maxBytes bounds the allowlist file, which is written by hand or by a
// deployment tool.
const maxBytes = 1 << 20

// Access is what the agent wants to do in a directory.
type Access int

// The two kinds of access an entry can allow.
const (
	Read Access = iota + 1
	Write
)

var (
	// ErrInvalid is returned for an allowlist that doesn't parse or names
	// something unusable. The agent refuses to start.
	ErrInvalid = errors.New("allowlist: invalid")
	// ErrUnprotected is returned for an allowlist file that someone other
	// than root could change, or an agent running as root. The agent refuses
	// to start.
	ErrUnprotected = errors.New("allowlist: the file must be owned by root, writable only by root, in directories writable only by root, and the agent must not run as root")
	// ErrNotAllowed is returned for a path outside the allowlist.
	ErrNotAllowed = errors.New("allowlist: the path is not allowed")
	// ErrSwapped is returned when what was opened is not what was checked.
	ErrSwapped = errors.New("allowlist: the path changed between the check and the open")
	// ErrNotRegular is returned for a file that is a link or not a regular
	// file.
	ErrNotRegular = errors.New("allowlist: not a regular file")
)

// document is version 1 of the file. Field names are exact, and unknown or
// repeated fields are refused.
type document struct {
	Version     int      `yaml:"version"`
	Read        []string `yaml:"read"`
	Write       []string `yaml:"write"`
	SendTo      []peer   `yaml:"send_to"`
	ReceiveFrom []peer   `yaml:"receive_from"`
	Approvals   int      `yaml:"approvals"`
}

// peer allows one agent by ID, or every agent in one workspace.
type peer struct {
	Agent     string `yaml:"agent"`
	Workspace string `yaml:"workspace"`
}

func (d document) empty() bool {
	return d.Version == 0 && d.Approvals == 0 && len(d.Read) == 0 && len(d.Write) == 0 &&
		len(d.SendTo) == 0 && len(d.ReceiveFrom) == 0
}

// entry is one allowed directory, with its links resolved, held open.
type entry struct {
	path string
	root *os.Root
}

// Allowlist is a loaded allowlist. A nil or empty Allowlist denies
// everything.
type Allowlist struct {
	read, write         []entry
	sendTo, receiveFrom []peer
	approvals           int
	hash                [32]byte
}

// Parse reads an allowlist from the bytes of its file, and opens each
// directory it names. No bytes, or a document with no fields, give an
// allowlist that denies everything. Otherwise the version must be 1 and at
// least one approval is required.
func Parse(data []byte) (*Allowlist, error) {
	a := &Allowlist{hash: sha256.Sum256(data)}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, maxBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var d document
	switch err := dec.Decode(&d); {
	case errors.Is(err, io.EOF):
		return a, nil
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	var more yaml.Node
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: the file must hold one document", ErrInvalid)
	}
	// The decoder drops a null list item without an error, so the nodes are
	// checked as written too.
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := plain(&doc); err != nil {
		return nil, err
	}
	if d.empty() {
		return a, nil
	}
	if d.Version != 1 {
		return nil, fmt.Errorf("%w: version must be 1", ErrInvalid)
	}
	if d.Approvals < 1 {
		return nil, fmt.Errorf("%w: approvals must be at least 1", ErrInvalid)
	}
	a.approvals = d.Approvals
	for _, peers := range [][]peer{d.SendTo, d.ReceiveFrom} {
		for _, p := range peers {
			if err := p.check(); err != nil {
				return nil, err
			}
		}
	}
	a.sendTo, a.receiveFrom = d.SendTo, d.ReceiveFrom
	var err error
	if a.read, err = openEntries(d.Read); err != nil {
		a.Close()
		return nil, err
	}
	if a.write, err = openEntries(d.Write); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

// plain refuses nulls, anchors, aliases, and explicit tags, so each value
// means what it says where it is written.
func plain(n *yaml.Node) error {
	switch {
	case n.Kind == yaml.AliasNode || n.Anchor != "":
		return fmt.Errorf("%w: line %d: anchors and aliases are not allowed", ErrInvalid, n.Line)
	case n.Kind == yaml.ScalarNode && n.Tag == "!!null":
		return fmt.Errorf("%w: line %d: null is not allowed", ErrInvalid, n.Line)
	case n.Style&yaml.TaggedStyle != 0:
		return fmt.Errorf("%w: line %d: tags are not allowed", ErrInvalid, n.Line)
	}
	for _, c := range n.Content {
		if err := plain(c); err != nil {
			return err
		}
	}
	return nil
}

func (p peer) check() error {
	switch {
	case p.Agent != "" && p.Workspace != "":
		return fmt.Errorf("%w: a peer names an agent or a workspace, not both", ErrInvalid)
	case p.Agent != "":
		if !trust.ValidAgentID(p.Agent) {
			return fmt.Errorf("%w: %q is not an agent ID", ErrInvalid, p.Agent)
		}
	case p.Workspace != "":
		if !trust.ValidName(p.Workspace) {
			return fmt.Errorf("%w: %q is not a workspace name", ErrInvalid, p.Workspace)
		}
	default:
		return fmt.Errorf("%w: a peer needs an agent or a workspace", ErrInvalid)
	}
	return nil
}

// openEntries resolves each directory's links and holds it open. A directory
// that doesn't exist is refused, so a mistake shows when the agent starts.
func openEntries(paths []string) ([]entry, error) {
	var out []entry
	for _, p := range paths {
		e, err := openEntry(p)
		if err != nil {
			for _, o := range out {
				_ = o.root.Close()
			}
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func openEntry(p string) (entry, error) {
	if !filepath.IsAbs(p) {
		return entry{}, fmt.Errorf("%w: %q must be an absolute path", ErrInvalid, p)
	}
	if err := flow.CheckPath(p); err != nil {
		return entry{}, fmt.Errorf("%w: %q: %w", ErrInvalid, p, err)
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return entry{}, fmt.Errorf("%w: %q must be an existing directory", ErrInvalid, p)
	}
	checked, err := os.Lstat(resolved)
	if err != nil || !checked.IsDir() {
		return entry{}, fmt.Errorf("%w: %q must be an existing directory", ErrInvalid, p)
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return entry{}, fmt.Errorf("%w: %q must be an existing directory", ErrInvalid, p)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(checked, opened) {
		_ = root.Close()
		return entry{}, fmt.Errorf("%w: %q changed while it was opened", ErrInvalid, p)
	}
	return entry{path: resolved, root: root}, nil
}

// Close releases the directories the allowlist holds open.
func (a *Allowlist) Close() {
	if a == nil {
		return
	}
	for _, e := range append(a.read, a.write...) {
		_ = e.root.Close()
	}
}

// Hash is the SHA-256 of the allowlist file's bytes, or of no bytes when there
// is no file. The agent reports it to the orchestrator.
func (a *Allowlist) Hash() [32]byte {
	if a == nil {
		return sha256.Sum256(nil)
	}
	return a.hash
}

// Approvals is how many administrators must approve a flow version. It is 0
// for an empty allowlist, which allows no flow.
func (a *Allowlist) Approvals() int {
	if a == nil {
		return 0
	}
	return a.approvals
}

// MaySendTo reports whether the agent may send to an agent whose identity it
// has verified.
func (a *Allowlist) MaySendTo(agentID, workspace string) bool {
	return a != nil && allowed(a.sendTo, agentID, workspace)
}

// MayReceiveFrom reports whether the agent may receive from an agent whose
// identity it has verified.
func (a *Allowlist) MayReceiveFrom(agentID, workspace string) bool {
	return a != nil && allowed(a.receiveFrom, agentID, workspace)
}

func allowed(peers []peer, agentID, workspace string) bool {
	if agentID == "" || workspace == "" {
		return false
	}
	for _, p := range peers {
		if p.Agent == agentID || p.Workspace == workspace {
			return true
		}
	}
	return false
}

// afterCheck runs between a check and the open that follows it. Tests replace
// it to swap a link in between.
var afterCheck = func() {}

// Dir checks a directory against the allowlist and opens it. The path must be
// in its canonical absolute form. Its links are resolved, and the result must
// be an entry for access or under one. The directory is opened through the
// entry's handle, so a link swapped in after the check can't lead outside the
// entry, and it must be the directory that was checked. Errors never hold the
// path.
func (a *Allowlist) Dir(path string, access Access) (*os.Root, error) {
	if a == nil || !filepath.IsAbs(path) || flow.CheckPath(path) != nil {
		return nil, ErrNotAllowed
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, pathless(err)
	}
	e, rel, ok := a.within(resolved, access)
	if !ok {
		return nil, ErrNotAllowed
	}
	checked, err := e.root.Lstat(rel)
	if err != nil {
		return nil, pathless(err)
	}
	if !checked.IsDir() {
		return nil, ErrSwapped
	}
	afterCheck()
	dir, err := e.root.OpenRoot(rel)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSwapped, pathless(err))
	}
	opened, err := dir.Stat(".")
	if err != nil || !os.SameFile(checked, opened) {
		_ = dir.Close()
		return nil, ErrSwapped
	}
	return dir, nil
}

// Includes reports whether a path, with its links resolved, is an entry or
// under one, for either access. The agent keeps its spool out of the
// allowlist, so no flow can reach sealed files in flight.
func (a *Allowlist) Includes(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	_, _, r := a.within(resolved, Read)
	_, _, w := a.within(resolved, Write)
	return r || w
}

// within finds the entry for access that holds a resolved path, by whole path
// segments, and returns the path relative to it.
func (a *Allowlist) within(resolved string, access Access) (entry, string, bool) {
	if a == nil {
		return entry{}, "", false
	}
	entries := a.read
	if access == Write {
		entries = a.write
	}
	for _, e := range entries {
		rel, err := filepath.Rel(e.path, resolved)
		if err == nil && filepath.IsLocal(rel) {
			return e, rel, true
		}
	}
	return entry{}, "", false
}

// OpenRegular opens a file by name in a directory from Dir. It must be a
// regular file, not a link, and the file opened must be the one checked.
func OpenRegular(dir *os.Root, name string) (*os.File, error) {
	checked, err := dir.Lstat(name)
	if err != nil {
		return nil, pathless(err)
	}
	if !checked.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	afterCheck()
	f, err := dir.Open(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSwapped, pathless(err))
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(checked, opened) {
		_ = f.Close()
		return nil, ErrSwapped
	}
	return f, nil
}

// pathless removes the path from an error, because a path can hold a file
// name, which must not reach logs or the orchestrator. errors.Is still works.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("allowlist: %s: %w", pe.Op, pe.Err)
	}
	return err
}
