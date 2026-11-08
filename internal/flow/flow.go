// Package flow parses and validates the payload of a flow version statement,
// as defined in ADR 0022. The API, the CLI, and the agent all use it, so a flow
// version is judged the same way everywhere.
//
// A flow version is a tree of cards in a flat list. Each card names its parent,
// so a card can't have two parents and a join can't be written. Parse rejects
// everything else that isn't a tree: loops, a missing or second root, and
// unknown parents.
//
// The payload has exactly one encoding for each value. Field names are lower
// case ASCII and appear once at every depth, and paths are absolute and in
// their one canonical form, so the bytes an administrator approves mean one
// thing to every reader.
package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
)

const (
	// PayloadVersion is the only payload version this package reads.
	PayloadVersion = 1
	// MaxCards is the most cards a flow version may hold.
	MaxCards = 200
	// MaxPathBytes is the longest path a card may name.
	MaxPathBytes = 1024
)

// Card types in payload version 1.
const (
	TypeSource      = "source"
	TypeDestination = "destination"
)

// maxDepth is the deepest nesting of objects and arrays a payload may have.
// Version 1 needs three: the payload, its cards, and a card.
const maxDepth = 3

var (
	cardIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	fieldPattern  = regexp.MustCompile(`^[a-z0-9_]+$`)
	drivePattern  = regexp.MustCompile(`^[A-Z]:\\`)
)

// Version is the payload of a flow version statement.
type Version struct {
	Version     int    `json:"version"`
	FlowID      string `json:"flow_id"`
	Workspace   string `json:"workspace"`
	FlowVersion int64  `json:"flow_version"`
	// Agents is every agent the cards name, sorted and without repeats, so an
	// agent can see whether it takes part before reading the cards.
	Agents []string `json:"agents"`
	Cards  []Card   `json:"cards"`
}

// Card is one card of a flow version. Parent is nil only for the root.
type Card struct {
	ID     string  `json:"id"`
	Type   string  `json:"type"`
	Parent *string `json:"parent,omitempty"`
	Agent  string  `json:"agent"`
	Path   string  `json:"path"`
}

// Error says which field of a payload is wrong, and why.
type Error struct {
	Field  string
	Reason string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return "flow: " + e.Reason
	}
	return "flow: " + e.Field + ": " + e.Reason
}

func fail(field, format string, a ...any) error {
	return &Error{Field: field, Reason: fmt.Sprintf(format, a...)}
}

// Parse decodes and validates a flow version payload. It returns the first
// problem it finds as an *Error.
func Parse(payload []byte) (*Version, error) {
	var v Version
	if err := decode(payload, &v); err != nil {
		return nil, err
	}
	if err := v.validate(); err != nil {
		return nil, err
	}
	return &v, nil
}

// Retirement is the payload of a flow retirement statement, as ADR 0024
// defines. It names the flow and its workspace, and stops the flow for good.
type Retirement struct {
	Version   int    `json:"version"`
	FlowID    string `json:"flow_id"`
	Workspace string `json:"workspace"`
}

// ParseRetirement decodes and validates a flow retirement payload, with the
// same strict decoding as a flow version.
func ParseRetirement(payload []byte) (*Retirement, error) {
	var r Retirement
	if err := decode(payload, &r); err != nil {
		return nil, err
	}
	switch {
	case r.Version != PayloadVersion:
		return nil, fail("version", "unsupported payload version %d", r.Version)
	case !trust.ValidAgentID(r.FlowID):
		return nil, fail("flow_id", "not a valid ID")
	case !trust.ValidName(r.Workspace):
		return nil, fail("workspace", "not a valid workspace name")
	}
	return &r, nil
}

// decode reads one payload object strictly into v.
func decode(payload []byte, v any) error {
	if len(payload) > statement.MaxPayloadBytes {
		return fail("", "payload is larger than %d bytes", statement.MaxPayloadBytes)
	}
	if err := checkKeys(payload); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail("", "%v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fail("", "trailing data after the payload")
	}
	return nil
}

// checkKeys walks the whole payload and requires every field name, at every
// depth, to be lower case ASCII and to appear once in its object. The standard
// decoder would otherwise take the last of two repeated fields and match names
// without regard to case, so two readers could see different values.
func checkKeys(payload []byte) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return fail("", "%v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fail("", "the payload must be a JSON object")
	}
	return walk(dec, '{', 1)
}

// walk checks the rest of an object or array whose opening token has been read.
// It refuses null values, which would give an absent field a second form.
func walk(dec *json.Decoder, open json.Delim, depth int) error {
	if depth > maxDepth {
		return fail("", "nested deeper than %d levels", maxDepth)
	}
	seen := map[string]bool{}
	for dec.More() {
		if open == '{' {
			tok, err := dec.Token()
			if err != nil {
				return fail("", "%v", err)
			}
			key, ok := tok.(string)
			if !ok {
				return fail("", "expected a field name")
			}
			// encoding/json matches names with Unicode case folding, so "\u017f"
			// would alias "s". Lower case ASCII names have no other form.
			if !fieldPattern.MatchString(key) {
				return fail("", "field name %q must be lower case ASCII", key)
			}
			if seen[key] {
				return fail("", "field %q appears twice in one object", key)
			}
			seen[key] = true
		}
		tok, err := dec.Token()
		if err != nil {
			return fail("", "%v", err)
		}
		if tok == nil {
			return fail("", "null is not allowed: leave the field out")
		}
		if d, ok := tok.(json.Delim); ok {
			if err := walk(dec, d, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return fail("", "%v", err)
	}
	return nil
}

func (v *Version) validate() error {
	if v.Version != PayloadVersion {
		return fail("version", "unsupported payload version %d", v.Version)
	}
	if !trust.ValidAgentID(v.FlowID) {
		return fail("flow_id", "not a valid ID")
	}
	if !trust.ValidName(v.Workspace) {
		return fail("workspace", "not a valid workspace name")
	}
	if v.FlowVersion < 1 {
		return fail("flow_version", "must be 1 or more")
	}
	if err := v.validateCards(); err != nil {
		return err
	}
	return v.validateAgents()
}

func (v *Version) validateCards() error {
	if len(v.Cards) == 0 {
		return fail("cards", "a flow needs a source card")
	}
	if len(v.Cards) > MaxCards {
		return fail("cards", "more than %d cards", MaxCards)
	}
	index := make(map[string]int, len(v.Cards))
	for i, c := range v.Cards {
		f := fmt.Sprintf("cards[%d]", i)
		if !cardIDPattern.MatchString(c.ID) {
			return fail(f+".id", "must be 1 to 32 lower case letters, digits, and hyphens, starting with a letter")
		}
		if j, ok := index[c.ID]; ok {
			return fail(f+".id", "cards[%d] already uses the ID %q", j, c.ID)
		}
		index[c.ID] = i
		if c.Type != TypeSource && c.Type != TypeDestination {
			return fail(f+".type", "unknown card type %q", c.Type)
		}
		if !trust.ValidAgentID(c.Agent) {
			return fail(f+".agent", "a %s card needs a valid agent ID", c.Type)
		}
		if err := checkPath(c.Path); err != nil {
			return fail(f+".path", "%v", err)
		}
	}
	if err := v.checkTree(index); err != nil {
		return err
	}
	return v.checkTypes(index)
}

// checkTree requires the cards to form one tree: one root, every parent a card
// in the flow, and every card reachable from the root.
func (v *Version) checkTree(index map[string]int) error {
	root := -1
	for i, c := range v.Cards {
		f := fmt.Sprintf("cards[%d]", i)
		if c.Parent == nil {
			if root >= 0 {
				return fail(f, "a second root card, after cards[%d]", root)
			}
			root = i
			continue
		}
		if _, ok := index[*c.Parent]; !ok {
			return fail(f+".parent", "no card %q", *c.Parent)
		}
	}
	if root < 0 {
		return fail("cards", "no root card: every card has a parent")
	}
	// With one root and one parent each, a card that never reaches the root
	// is part of a loop.
	for i := range v.Cards {
		at := i
		for steps := 0; v.Cards[at].Parent != nil; steps++ {
			if steps >= len(v.Cards) {
				return fail(fmt.Sprintf("cards[%d].parent", i), "the cards' parents form a loop")
			}
			at = index[*v.Cards[at].Parent]
		}
	}
	return nil
}

// checkTypes applies the rules of payload version 1: the root is the one
// source, and each destination follows it directly, on another agent.
func (v *Version) checkTypes(index map[string]int) error {
	type place struct{ agent, path string }
	seen := map[place]int{}
	var source Card
	for _, c := range v.Cards {
		if c.Parent == nil {
			source = c
		}
	}
	if source.Type != TypeSource {
		return fail(fmt.Sprintf("cards[%d].type", index[source.ID]), "the root card must be a source")
	}
	for i, c := range v.Cards {
		f := fmt.Sprintf("cards[%d]", i)
		if c.Parent == nil {
			continue
		}
		if c.Type == TypeSource {
			return fail(f+".parent", "a source card is always the root")
		}
		if *c.Parent != source.ID {
			return fail(f+".parent", "a destination must follow the source card")
		}
		// A delivery always moves between two agents. See seal.Delivery.
		if c.Agent == source.Agent {
			return fail(f+".agent", "a destination can't be on the source card's agent")
		}
		p := place{c.Agent, c.Path}
		if j, ok := seen[p]; ok {
			return fail(f, "the same agent and path as cards[%d]", j)
		}
		seen[p] = i
	}
	if len(seen) == 0 {
		return fail("cards", "a flow needs at least one destination card")
	}
	return nil
}

// validateAgents requires Agents to be exactly the agents the cards name,
// sorted and without repeats.
func (v *Version) validateAgents() error {
	var want []string
	for _, c := range v.Cards {
		want = append(want, c.Agent)
	}
	slices.Sort(want)
	want = slices.Compact(want)
	for i, a := range v.Agents {
		if !trust.ValidAgentID(a) {
			return fail(fmt.Sprintf("agents[%d]", i), "not a valid agent ID")
		}
		if i > 0 && a <= v.Agents[i-1] {
			return fail("agents", "must be sorted, without repeats")
		}
	}
	if !slices.Equal(v.Agents, want) {
		return fail("agents", "must list exactly the agents the cards name")
	}
	return nil
}

// checkPath requires an absolute path in its one canonical form: a POSIX path,
// or a Windows path on a drive. Anything that two systems or two readers could
// take differently is refused, so the path an administrator approves is the
// path that runs. Whether the agent may use it is the allowlist's decision.
func checkPath(p string) error {
	if p == "" {
		return errors.New("a card needs a path")
	}
	if len(p) > MaxPathBytes {
		return fmt.Errorf("longer than %d bytes", MaxPathBytes)
	}
	if !utf8.ValidString(p) {
		return errors.New("not valid UTF-8")
	}
	for _, r := range p {
		if hidden(r) {
			return fmt.Errorf("contains the hidden character %U", r)
		}
	}
	switch {
	case strings.HasPrefix(p, "/"):
		return checkSegments(p[1:], "/", posixSegment)
	case drivePattern.MatchString(p):
		return checkSegments(p[3:], `\`, windowsSegment)
	case len(p) >= 2 && p[1] == ':' && 'a' <= p[0] && p[0] <= 'z':
		return errors.New("a Windows drive letter must be upper case")
	default:
		return errors.New("must be absolute: start with / or a drive such as C:\\")
	}
}

// hidden reports characters that would change how a path looks when printed:
// control characters, line breaks, and the marks that reorder text.
func hidden(r rune) bool {
	return r < 0x20 || r == 0x7f || (0x80 <= r && r < 0xa0) ||
		r == 0x200e || r == 0x200f || r == 0x2028 || r == 0x2029 ||
		(0x202a <= r && r <= 0x202e) || (0x2066 <= r && r <= 0x2069)
}

// checkSegments checks the part of a path after its root. An empty rest is the
// root itself.
func checkSegments(rest, sep string, segment func(string) error) error {
	if rest == "" {
		return nil
	}
	for s := range strings.SplitSeq(rest, sep) {
		if s == "" {
			return fmt.Errorf("has an empty segment: a doubled or trailing %s", sep)
		}
		if s == "." || s == ".." {
			return fmt.Errorf("has a %q segment", s)
		}
		if err := segment(s); err != nil {
			return err
		}
	}
	return nil
}

func posixSegment(string) error { return nil }

// windowsSegment refuses names Windows would read differently from how they
// are written: it drops trailing dots and spaces, treats / as a separator, and
// gives meaning to the other reserved characters.
func windowsSegment(s string) error {
	if i := strings.IndexAny(s, `/<>:"|?*`); i >= 0 {
		return fmt.Errorf("contains %q, which Windows doesn't allow in a name", s[i])
	}
	if strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
		return errors.New("a Windows name can't end in a dot or a space")
	}
	return nil
}
