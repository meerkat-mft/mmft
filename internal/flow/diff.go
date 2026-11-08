package flow

import "slices"

// Diff is what changed from one flow version to another, as an administrator
// reviews it before approving. Cards are matched by ID.
type Diff struct {
	AgentsAdded   []string     `json:"agents_added"`
	AgentsRemoved []string     `json:"agents_removed"`
	CardsAdded    []Card       `json:"cards_added"`
	CardsRemoved  []Card       `json:"cards_removed"`
	CardsChanged  []CardChange `json:"cards_changed"`
}

// CardChange is one field of a card that differs between two versions. An
// empty parent is the root.
type CardChange struct {
	ID    string `json:"id"`
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// Compare returns what changed from one version to the next. With no earlier
// version, everything in to is added.
func Compare(from, to *Version) Diff {
	d := Diff{AgentsAdded: []string{}, AgentsRemoved: []string{}, CardsAdded: []Card{}, CardsRemoved: []Card{}, CardsChanged: []CardChange{}}
	if from == nil {
		from = &Version{}
	}
	for _, a := range to.Agents {
		if !slices.Contains(from.Agents, a) {
			d.AgentsAdded = append(d.AgentsAdded, a)
		}
	}
	for _, a := range from.Agents {
		if !slices.Contains(to.Agents, a) {
			d.AgentsRemoved = append(d.AgentsRemoved, a)
		}
	}
	old := map[string]Card{}
	for _, c := range from.Cards {
		old[c.ID] = c
	}
	seen := map[string]bool{}
	for _, c := range to.Cards {
		seen[c.ID] = true
		was, ok := old[c.ID]
		if !ok {
			d.CardsAdded = append(d.CardsAdded, c)
			continue
		}
		for _, f := range [][3]string{
			{"type", was.Type, c.Type},
			{"parent", parentOf(was), parentOf(c)},
			{"agent", was.Agent, c.Agent},
			{"path", was.Path, c.Path},
		} {
			if f[1] != f[2] {
				d.CardsChanged = append(d.CardsChanged, CardChange{ID: c.ID, Field: f[0], From: f[1], To: f[2]})
			}
		}
	}
	for _, c := range from.Cards {
		if !seen[c.ID] {
			d.CardsRemoved = append(d.CardsRemoved, c)
		}
	}
	return d
}

func parentOf(c Card) string {
	if c.Parent == nil {
		return ""
	}
	return *c.Parent
}
