package flow

import (
	"slices"
	"strings"
	"testing"
)

func parsed(t *testing.T, name string) *Version {
	t.Helper()
	v, err := Parse(fixtures(t, "valid")[name])
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCompareFindsEveryKindOfChange(t *testing.T) {
	from := parsed(t, "two-destinations")
	to := parsed(t, "two-destinations")
	// Drop "archive", move "ledger", and add "audit" on a new agent.
	to.Cards = []Card{to.Cards[0], to.Cards[1], {ID: "audit", Type: TypeDestination, Parent: to.Cards[1].Parent,
		Agent: "0190f9c3-2b7d-7e01-8000-00000000000d", Path: "/srv/audit"}}
	to.Cards[1].Path = "/srv/inbox-2"
	to.Agents = []string{from.Agents[0], from.Agents[1], "0190f9c3-2b7d-7e01-8000-00000000000d"}

	d := Compare(from, to)
	if len(d.CardsAdded) != 1 || d.CardsAdded[0].ID != "audit" {
		t.Errorf("added %+v", d.CardsAdded)
	}
	if len(d.CardsRemoved) != 1 || d.CardsRemoved[0].ID != "archive" {
		t.Errorf("removed %+v", d.CardsRemoved)
	}
	want := []CardChange{{ID: "ledger", Field: "path", From: "/srv/inbox", To: "/srv/inbox-2"}}
	if !slices.Equal(d.CardsChanged, want) {
		t.Errorf("changed %+v", d.CardsChanged)
	}
	if !slices.Equal(d.AgentsAdded, []string{"0190f9c3-2b7d-7e01-8000-00000000000d"}) || !slices.Equal(d.AgentsRemoved, []string{from.Agents[2]}) {
		t.Errorf("agents +%v -%v", d.AgentsAdded, d.AgentsRemoved)
	}
}

func TestCompareWithNothingApprovedAddsEverything(t *testing.T) {
	to := parsed(t, "one-destination")
	d := Compare(nil, to)
	if len(d.CardsAdded) != 2 || len(d.AgentsAdded) != 2 || d.CardsRemoved == nil || len(d.CardsChanged) != 0 {
		t.Errorf("diff %+v", d)
	}
	if same := Compare(to, to); len(same.CardsAdded)+len(same.CardsRemoved)+len(same.CardsChanged)+len(same.AgentsAdded) != 0 {
		t.Errorf("a version against itself: %+v", same)
	}
}

func TestParseRetirement(t *testing.T) {
	r, err := ParseRetirement([]byte(`{"version":1,"flow_id":"0190f9c3-2b7d-7e01-8000-0000000000f1","workspace":"finance"}`))
	if err != nil || r.Workspace != "finance" {
		t.Fatalf("valid: %+v %v", r, err)
	}
	for _, bad := range []string{
		`{"version":2,"flow_id":"0190f9c3-2b7d-7e01-8000-0000000000f1","workspace":"finance"}`,
		`{"version":1,"flow_id":"not-an-id","workspace":"finance"}`,
		`{"version":1,"flow_id":"0190f9c3-2b7d-7e01-8000-0000000000f1","workspace":"fin ance"}`,
		`{"version":1,"flow_id":"0190f9c3-2b7d-7e01-8000-0000000000f1","workspace":"finance","workspace":"other"}`,
		`{"version":1,"flow_id":"0190f9c3-2b7d-7e01-8000-0000000000f1","workspace":"finance","name":"x"}`,
		`{"version":1,"flow_id":"0190f9c3-2b7d-7e01-8000-0000000000f1","workspace":"finance"} {}`,
	} {
		if _, err := ParseRetirement([]byte(bad)); err == nil || !strings.HasPrefix(err.Error(), "flow: ") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
