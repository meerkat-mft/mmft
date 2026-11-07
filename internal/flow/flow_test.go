package flow

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// invalid maps each fixture in testdata/invalid to the reason it must fail.
var invalid = map[string]string{
	"loop":                          `cards[1].parent: the cards' parents form a loop`,
	"no-root":                       `cards: no root card`,
	"two-roots":                     `cards[2]: a second root card, after cards[0]`,
	"unknown-parent":                `cards[2].parent: no card "pickup2"`,
	"repeated-card-id":              `cards[2].id: cards[1] already uses the ID "ledger"`,
	"unknown-card-type":             `cards[2].type: unknown card type "condition"`,
	"destination-without-agent":     `cards[2].agent: a destination card needs a valid agent ID`,
	"agents-mismatch":               `agents: must list exactly the agents the cards name`,
	"agents-unsorted":               `agents: must be sorted, without repeats`,
	"relative-path":                 `cards[1].path: must be absolute`,
	"dot-dot-path":                  `cards[1].path: has a ".." segment`,
	"trailing-slash":                `cards[1].path: has an empty segment`,
	"lower-case-drive":              `cards[1].path: a Windows drive letter must be upper case`,
	"windows-trailing-dot":          `cards[1].path: a Windows name can't end in a dot or a space`,
	"hidden-character":              `cards[1].path: contains the hidden character U+202E`,
	"unknown-version":               `version: unsupported payload version 2`,
	"unknown-field":                 `unknown field "name"`,
	"root-is-destination":           `cards[0].type: the root card must be a source`,
	"destination-after-destination": `cards[2].parent: a destination must follow the source card`,
	"destination-on-source-agent":   `cards[2].agent: a destination can't be on the source card's agent`,
	"same-destination-twice":        `cards[2]: the same agent and path as cards[1]`,
	"flow-version-zero":             `flow_version: must be 1 or more`,
	"invalid-workspace":             `workspace: not a valid workspace name`,
	"null-parent":                   `null is not allowed`,
	"too-deep":                      `nested deeper than 3 levels`,
	"repeated-field-in-card":        `field "path" appears twice in one object`,
	"upper-case-field-in-card":      `field name "Path" must be lower case ASCII`,
	"trailing-data":                 `trailing data after the payload`,
	"no-destination":                `cards: a flow needs at least one destination card`,
}

func fixtures(t *testing.T, kind string) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", kind, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(filepath.Base(p), ".json")] = data
	}
	return out
}

func TestValidFixtures(t *testing.T) {
	valid := fixtures(t, "valid")
	if len(valid) == 0 {
		t.Fatal("no valid fixtures")
	}
	for name, data := range valid {
		t.Run(name, func(t *testing.T) {
			v, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if v.Version != PayloadVersion || len(v.Cards) < 2 || len(v.Agents) < 2 {
				t.Errorf("parsed %+v", v)
			}
		})
	}
}

func TestInvalidFixtures(t *testing.T) {
	files := fixtures(t, "invalid")
	for name := range files {
		if _, ok := invalid[name]; !ok {
			t.Errorf("testdata/invalid/%s.json has no expected reason", name)
		}
	}
	for name, want := range invalid {
		t.Run(name, func(t *testing.T) {
			data, ok := files[name]
			if !ok {
				t.Fatalf("testdata/invalid/%s.json is missing", name)
			}
			_, err := Parse(data)
			if err == nil {
				t.Fatal("Parse accepted it")
			}
			var fe *Error
			if !errors.As(err, &fe) {
				t.Fatalf("error %v is not an *Error", err)
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q, want it to contain %q", err, want)
			}
		})
	}
}

// base returns the two-destination fixture as a value to change in a test.
func base(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixtures(t, "valid")["two-destinations"], &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func parseValue(t *testing.T, m map[string]any) error {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(data)
	return err
}

func TestTooManyCards(t *testing.T) {
	m := base(t)
	cards := m["cards"].([]any)
	for i := len(cards); i <= MaxCards; i++ {
		cards = append(cards, map[string]any{
			"id": fmt.Sprintf("extra-%d", i), "type": "destination", "parent": "pickup",
			"agent": "0190f9c3-2b7d-7e01-8000-00000000000b", "path": fmt.Sprintf("/srv/inbox-%d", i),
		})
	}
	m["cards"] = cards
	if err := parseValue(t, m); err == nil || !strings.Contains(err.Error(), "more than 200 cards") {
		t.Fatalf("got %v", err)
	}
}

func TestPaths(t *testing.T) {
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/", true},
		{"/srv/inbox", true},
		{"/srv/in box/a.b", true},
		{`/srv/back\slash`, true},
		{`C:\`, true},
		{`C:\Exports\Out box`, true},
		{"", false},
		{"//srv", false},
		{"/srv//inbox", false},
		{"/srv/./inbox", false},
		{"/srv/..", false},
		{"/srv/inbox\n", false},
		{"/srv/in\u2066box", false},
		{"/srv/\xff", false},
		{"/" + strings.Repeat("a", MaxPathBytes), false},
		{`C:`, false},
		{`C:\\Exports`, false},
		{`C:\Exports\`, false},
		{`C:\Exports/Outbox`, false},
		{`C:\Exports\Out:box`, false},
		{`C:\Exports\Outbox `, false},
		{`C:\Exports\..`, false},
		{`\\server\share`, false},
		{`relative\path`, false},
	} {
		err := checkPath(tc.path)
		if (err == nil) != tc.ok {
			t.Errorf("checkPath(%q) = %v, want ok %v", tc.path, err, tc.ok)
		}
	}
}

// A field repeated deep inside a card must be caught, not only at the top.
func TestRepeatedFieldsAtEveryDepth(t *testing.T) {
	for _, payload := range []string{
		`{"version":1,"version":1}`,
		`{"cards":[{"id":"a","id":"b"}]}`,
	} {
		if err := checkKeys([]byte(payload)); err == nil || !strings.Contains(err.Error(), "appears twice") {
			t.Errorf("checkKeys(%s) = %v", payload, err)
		}
	}
}
