package statement

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata")

func signer(t testing.TB, r Role) *Signer {
	t.Helper()
	s, err := GenerateSigner(r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verifier(s *Signer) Verifier {
	return Verifier{Key: s.Public(), Role: s.role, Owner: s.Public().Fingerprint()}
}

func trust(signers ...*Signer) []Verifier {
	var out []Verifier
	for _, s := range signers {
		out = append(out, verifier(s))
	}
	return out
}

func sign(t testing.TB, typ Type, payload string, s *Signer) *Envelope {
	t.Helper()
	e, err := Sign(typ, []byte(payload), s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func clone(t testing.TB, e *Envelope) *Envelope {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLimitsArePinned(t *testing.T) {
	if MaxPayloadBytes != 1048576 || MaxSignatures != 8 || maxEnvelopeBytes != 1572864 {
		t.Fatal("limits changed")
	}
}

func TestPAEMatchesDSSESpecification(t *testing.T) {
	got := pae("http://example.com/HelloWorld", []byte("hello world"))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if string(got) != want {
		t.Fatalf("pae = %q, want %q", got, want)
	}
}

// vector is a stored statement, so that a change to the wire format, signature
// context, parameter set, or fingerprint fails even if signing and verifying
// change together.
type vector struct {
	EdSeed      string    `json:"ed_seed"`
	MLSeed      string    `json:"ml_seed"`
	Fingerprint string    `json:"fingerprint"`
	ID          string    `json:"id"`
	Envelope    *Envelope `json:"envelope"`
}

func TestStoredVector(t *testing.T) {
	const path = "testdata/vector.json"
	edSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	mlSeed := bytes.Repeat([]byte{0x22}, 32)
	s, err := NewSigner(RoleAdministrator, edSeed, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		e := sign(t, TypeFlowVersion, `{"flow":"invoices-nl","version":7}`, s)
		v, err := Verify(e, TypeFlowVersion, trust(s), 1)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(vector{hex.EncodeToString(edSeed), hex.EncodeToString(mlSeed), s.Public().Fingerprint(), v.ID, e}, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want vector
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if got := s.Public().Fingerprint(); got != want.Fingerprint {
		t.Fatalf("fingerprint = %s, want %s", got, want.Fingerprint)
	}
	v, err := Verify(want.Envelope, TypeFlowVersion, trust(s), 1)
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != want.ID {
		t.Fatalf("id = %s, want %s", v.ID, want.ID)
	}
	if string(v.Payload) != `{"flow":"invoices-nl","version":7}` {
		t.Fatalf("payload = %q", v.Payload)
	}
}

func TestRoundTrip(t *testing.T) {
	admin := signer(t, RoleAdministrator)
	payload := `{"flow":"invoices-nl","version":7}`
	got, err := Verify(clone(t, sign(t, TypeFlowVersion, payload, admin)), TypeFlowVersion, trust(admin), 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != payload {
		t.Fatalf("payload = %q", got.Payload)
	}
	if len(got.Signers) != 1 || got.Signers[0].Owner != verifier(admin).Owner {
		t.Fatalf("signers = %+v", got.Signers)
	}
}

func TestVerifyRejects(t *testing.T) {
	admin := signer(t, RoleAdministrator)
	other := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "payload", admin)

	tests := []struct {
		name    string
		mutate  func(*Envelope)
		trusted []Verifier
		want    error
	}{
		{"missing ML-DSA signature", func(e *Envelope) { e.Signatures = e.Signatures[:1] }, nil, ErrNotEnoughSigners},
		{"missing Ed25519 signature", func(e *Envelope) { e.Signatures = e.Signatures[1:] }, nil, ErrNotEnoughSigners},
		{"no signatures", func(e *Envelope) { e.Signatures = nil }, nil, ErrNotEnoughSigners},
		{"changed payload", func(e *Envelope) { e.Payload = base64.StdEncoding.EncodeToString([]byte("Payload")) }, nil, ErrNotEnoughSigners},
		{"changed payload type", func(e *Envelope) { e.PayloadType = string(TypeRevocation) }, nil, ErrWrongType},
		{"payload with bad base64", func(e *Envelope) { e.Payload = "!!!" }, nil, ErrMalformed},
		{"payload with line break", func(e *Envelope) { e.Payload = e.Payload[:4] + "\n" + e.Payload[4:] }, nil, ErrMalformed},
		{"payload with carriage return", func(e *Envelope) { e.Payload = e.Payload[:4] + "\r" + e.Payload[4:] }, nil, ErrMalformed},
		{"payload with non-zero padding bits", func(e *Envelope) { e.Payload = "cGF5bG9hZB==" }, nil, ErrMalformed},
		{"payload in URL-safe base64", func(e *Envelope) { e.Payload = "-_-_" }, nil, ErrMalformed},
		{"signature with bad base64", func(e *Envelope) { e.Signatures[0].Sig = "!!!" }, nil, ErrMalformed},
		{"signature with line break", func(e *Envelope) { e.Signatures[0].Sig = e.Signatures[0].Sig[:4] + "\n" + e.Signatures[0].Sig[4:] }, nil, ErrMalformed},
		{"oversized signature", func(e *Envelope) { e.Signatures[0].Sig = strings.Repeat("A", maxSigEncoded+4) }, nil, ErrTooLarge},
		{"too many signatures", func(e *Envelope) {
			for len(e.Signatures) <= MaxSignatures {
				e.Signatures = append(e.Signatures, e.Signatures[0])
			}
		}, nil, ErrTooLarge},
		{"untrusted signer", func(*Envelope) {}, trust(other), ErrNotEnoughSigners},
		{"key id claims a trusted key", func(e *Envelope) { e.Signatures[0].KeyID = other.Public().Fingerprint() }, trust(other), ErrNotEnoughSigners},
		{"no trusted keys", func(*Envelope) {}, []Verifier{}, ErrNotEnoughSigners},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := *clone(t, e)
			c.Signatures = slices.Clone(c.Signatures)
			tt.mutate(&c)
			trusted := tt.trusted
			if trusted == nil {
				trusted = trust(admin)
			}
			if _, err := Verify(&c, TypeFlowVersion, trusted, 1); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSignaturesAreFoundInAnyOrder(t *testing.T) {
	a := signer(t, RoleAdministrator)
	b := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", b)
	if err := Countersign(e, a); err != nil {
		t.Fatal(err)
	}
	e.Signatures = []Signature{e.Signatures[3], e.Signatures[1], e.Signatures[0], e.Signatures[2]}
	if _, err := Verify(e, TypeFlowVersion, trust(a), 1); err != nil {
		t.Fatal(err)
	}
}

func TestSignaturesFromDifferentKeysDoNotCombine(t *testing.T) {
	a := signer(t, RoleAdministrator)
	b := signer(t, RoleAdministrator)
	ea := sign(t, TypeFlowVersion, "x", a)
	eb := sign(t, TypeFlowVersion, "x", b)
	mixed := clone(t, ea)
	mixed.Signatures = []Signature{ea.Signatures[0], eb.Signatures[1]}
	if _, err := Verify(mixed, TypeFlowVersion, trust(a, b), 1); !errors.Is(err, ErrNotEnoughSigners) {
		t.Fatalf("err = %v", err)
	}
}

func TestSignatureDoesNotTransferBetweenTypes(t *testing.T) {
	agent := signer(t, RoleAgent)
	moved := clone(t, sign(t, TypeDeliveryManifest, "x", agent))
	moved.PayloadType = string(TypeDeliveryReceipt)
	if _, err := Verify(moved, TypeDeliveryReceipt, trust(agent), 1); !errors.Is(err, ErrNotEnoughSigners) {
		t.Fatalf("err = %v", err)
	}
}

// TestRoleTable is the signer table from ADR 0012, written out in full so that
// any change to allowedRoles fails, including the negative cases.
func TestRoleTable(t *testing.T) {
	table := map[Type][]Role{
		TypeRootRollover:        {RoleRoot},
		TypeAdministratorKey:    {RoleRoot},
		TypeAdministratorRevoke: {RoleRoot},
		TypeFlowVersion:         {RoleAdministrator},
		TypeFlowRetirement:      {RoleAdministrator},
		TypeAutomationKey:       {RoleAdministrator},
		TypeCheckpointKey:       {RoleAdministrator},
		TypeAgentIdentity:       {RoleAdministrator, RoleAutomation},
		TypeRevocation:          {RoleAdministrator},
		TypeDeliveryManifest:    {RoleAgent},
		TypeDeliveryReceipt:     {RoleAgent},
		TypeAuditBatch:          {RoleAgent},
		TypeAuditCheckpoint:     {RoleCheckpoint},
		TypeEnrollmentRequest:   {RoleAgent},
	}
	if len(allowedRoles) != len(table) {
		t.Fatalf("allowedRoles has %d types, want %d", len(allowedRoles), len(table))
	}
	roles := []Role{RoleRoot, RoleAdministrator, RoleAutomation, RoleAgent, RoleCheckpoint}
	seen := map[Type]bool{}
	for typ, want := range table {
		if seen[typ] {
			t.Fatalf("duplicate type %s", typ)
		}
		seen[typ] = true
		for _, r := range roles {
			s := signer(t, r)
			allowed := slices.Contains(want, r)
			_, err := Sign(typ, []byte("x"), s)
			if allowed && err != nil {
				t.Errorf("%s: role %d could not sign: %v", typ, r, err)
			}
			if !allowed && !errors.Is(err, ErrRoleNotAllowed) {
				t.Errorf("%s: role %d signed, err = %v", typ, r, err)
			}
		}
	}
}

func TestPayloadTypesAreDistinct(t *testing.T) {
	seen := map[Type]bool{}
	for typ := range allowedRoles {
		if seen[typ] || !strings.HasPrefix(string(typ), "application/vnd.mmft.") || !strings.HasSuffix(string(typ), "+json;v=1") {
			t.Errorf("bad type %s", typ)
		}
		seen[typ] = true
	}
}

func TestVerifierRoleIsChecked(t *testing.T) {
	admin := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", admin)
	v := verifier(admin)
	v.Role = RoleAutomation
	if _, err := Verify(e, TypeFlowVersion, []Verifier{v}, 1); !errors.Is(err, ErrNotEnoughSigners) {
		t.Fatalf("err = %v", err)
	}
}

func TestCallerCanEnforceAutomationScope(t *testing.T) {
	a := signer(t, RoleAutomation)
	b := signer(t, RoleAutomation)
	trusted := []Verifier{
		{Key: a.Public(), Role: RoleAutomation, Owner: "workspace-a"},
		{Key: b.Public(), Role: RoleAutomation, Owner: "workspace-b"},
	}
	got, err := Verify(sign(t, TypeAgentIdentity, `{"workspace":"workspace-b"}`, a), TypeAgentIdentity, trusted, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Signers) != 1 || got.Signers[0].Owner != "workspace-a" {
		t.Fatalf("signers = %+v", got.Signers)
	}
}

func TestSecondApprover(t *testing.T) {
	a := signer(t, RoleAdministrator)
	b := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", a)
	if _, err := Verify(e, TypeFlowVersion, trust(a, b), 2); !errors.Is(err, ErrNotEnoughSigners) {
		t.Fatalf("one approver met a threshold of two: %v", err)
	}
	if err := Countersign(e, b); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(e, TypeFlowVersion, trust(a, b), 2); err != nil {
		t.Fatal(err)
	}
}

func TestCountersignCap(t *testing.T) {
	e := sign(t, TypeFlowVersion, "x", signer(t, RoleAdministrator))
	for range 3 {
		if err := Countersign(e, signer(t, RoleAdministrator)); err != nil {
			t.Fatal(err)
		}
	}
	if err := Countersign(e, signer(t, RoleAdministrator)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("fifth approver: %v", err)
	}
}

func TestThresholdCountsOwners(t *testing.T) {
	a := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", a)
	if err := Countersign(e, a); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(e, TypeFlowVersion, trust(a, a), 2); !errors.Is(err, ErrNotEnoughSigners) {
		t.Fatalf("same key twice: %v", err)
	}

	// One administrator's old and new keys, trusted together during renewal.
	old, renewed := signer(t, RoleAdministrator), signer(t, RoleAdministrator)
	e = sign(t, TypeFlowVersion, "x", old)
	if err := Countersign(e, renewed); err != nil {
		t.Fatal(err)
	}
	trusted := []Verifier{
		{Key: old.Public(), Role: RoleAdministrator, Owner: "alex"},
		{Key: renewed.Public(), Role: RoleAdministrator, Owner: "alex"},
	}
	if _, err := Verify(e, TypeFlowVersion, trusted, 2); !errors.Is(err, ErrNotEnoughSigners) {
		t.Fatalf("one owner met a threshold of two: %v", err)
	}
}

func TestTrustedSetRejectsAmbiguousKeys(t *testing.T) {
	a := signer(t, RoleAdministrator)
	b := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", a)
	edA, mlA := a.Public().Bytes()
	edB, mlB := b.Public().Bytes()
	sharedEd, err := NewPublicKey(edA, mlB)
	if err != nil {
		t.Fatal(err)
	}
	sharedML, err := NewPublicKey(edB, mlA)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]Verifier{
		"shared Ed25519 key": {verifier(a), {Key: sharedEd, Role: RoleAdministrator, Owner: "x"}},
		"shared ML-DSA key":  {verifier(a), {Key: sharedML, Role: RoleAdministrator, Owner: "x"}},
		"key with two owners": {
			{Key: a.Public(), Role: RoleAdministrator, Owner: "x"},
			{Key: a.Public(), Role: RoleAdministrator, Owner: "y"},
		},
		"key without an owner": {{Key: a.Public(), Role: RoleAdministrator}},
	}
	for name, trusted := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(e, TypeFlowVersion, trusted, 1); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	a := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", a)
	if _, err := Verify(e, TypeFlowVersion, trust(a), 0); !errors.Is(err, ErrInvalidThreshold) {
		t.Fatalf("threshold zero: %v", err)
	}
	if _, err := Verify(e, TypeFlowVersion, trust(a), -1); !errors.Is(err, ErrInvalidThreshold) {
		t.Fatalf("negative threshold: %v", err)
	}
	if _, err := Verify(e, Type("application/unknown"), trust(a), 1); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("unknown type: %v", err)
	}
	if _, err := Verify(nil, TypeFlowVersion, trust(a), 1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("nil envelope: %v", err)
	}
	if _, err := Verify(e, TypeFlowVersion, []Verifier{{Role: RoleAdministrator, Owner: "x"}}, 1); !errors.Is(err, ErrNotEnoughSigners) {
		t.Fatalf("empty key: %v", err)
	}
}

func TestCallerMistakesReturnErrors(t *testing.T) {
	s := signer(t, RoleAdministrator)
	if err := Countersign(nil, s); !errors.Is(err, ErrMalformed) {
		t.Fatalf("nil envelope: %v", err)
	}
	if err := Countersign(&Envelope{}, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil signer: %v", err)
	}
	if _, err := Sign(TypeFlowVersion, nil, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Sign nil signer: %v", err)
	}
	var zero PublicKey
	if ed, ml := zero.Bytes(); ed != nil || ml != nil {
		t.Fatal("zero key has bytes")
	}
	if zero.Fingerprint() != "" {
		t.Fatal("zero key has a fingerprint")
	}
	if _, err := NewSigner(RoleAgent, make([]byte, 5), make([]byte, 32)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short Ed25519 seed: %v", err)
	}
	if _, err := NewSigner(RoleAgent, make([]byte, 32), make([]byte, 5)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short ML-DSA seed: %v", err)
	}
}

func TestPayloadLimitsAreExact(t *testing.T) {
	a := signer(t, RoleAdministrator)
	if _, err := Sign(TypeFlowVersion, make([]byte, MaxPayloadBytes+1), a); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Sign: %v", err)
	}
	maxed, err := Sign(TypeFlowVersion, make([]byte, MaxPayloadBytes), a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(maxed, TypeFlowVersion, trust(a), 1); err != nil {
		t.Fatalf("exact limit: %v", err)
	}
	// One to two bytes over still fits the encoded length of the limit.
	for _, n := range []int{MaxPayloadBytes + 1, MaxPayloadBytes + 2} {
		over := &Envelope{Payload: base64.StdEncoding.EncodeToString(make([]byte, n)), PayloadType: string(TypeFlowVersion)}
		if _, err := Verify(over, TypeFlowVersion, trust(a), 1); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if err := Countersign(over, a); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Countersign %d bytes: %v", n, err)
		}
	}
	huge := &Envelope{Payload: strings.Repeat("A", 2*MaxPayloadBytes), PayloadType: string(TypeFlowVersion)}
	if err := Countersign(huge, a); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Countersign huge: %v", err)
	}
}

func TestLargestLegitimateEnvelopeParses(t *testing.T) {
	e, err := Sign(TypeFlowVersion, make([]byte, MaxPayloadBytes), signer(t, RoleAdministrator))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := Countersign(e, signer(t, RoleAdministrator)); err != nil {
			t.Fatal(err)
		}
	}
	clone(t, e)
}

func TestParseRejects(t *testing.T) {
	const ok = `"payload":"eA==","payloadType":"t","signatures":[{"sig":"eA=="}]`
	tests := map[string]string{
		"empty":                     ``,
		"not an object":             `[]`,
		"null":                      `null`,
		"truncated":                 `{` + ok,
		"trailing object":           `{` + ok + `}{}`,
		"trailing text":             `{` + ok + `} x`,
		"missing payload":           `{"payloadType":"t","signatures":[]}`,
		"missing payload type":      `{"payload":"","signatures":[]}`,
		"missing signatures":        `{"payload":"","payloadType":"t"}`,
		"missing sig":               `{"payload":"","payloadType":"t","signatures":[{}]}`,
		"duplicate payload":         `{` + ok + `,"payload":"eQ=="}`,
		"duplicate payload type":    `{` + ok + `,"payloadType":"u"}`,
		"duplicate signatures":      `{` + ok + `,"signatures":[]}`,
		"duplicate sig":             `{"payload":"","payloadType":"t","signatures":[{"sig":"","sig":""}]}`,
		"duplicate keyid":           `{"payload":"","payloadType":"t","signatures":[{"sig":"","keyid":"","keyid":""}]}`,
		"cased payload":             `{` + ok + `,"PAYLOAD":"eQ=="}`,
		"cased payload type":        `{` + ok + `,"PayloadType":"u"}`,
		"cased signatures":          `{` + ok + `,"Signatures":[]}`,
		"cased sig":                 `{"payload":"","payloadType":"t","signatures":[{"SIG":""}]}`,
		"cased keyid":               `{"payload":"","payloadType":"t","signatures":[{"sig":"","KeyId":""}]}`,
		"payload is a number":       `{"payload":1,"payloadType":"t","signatures":[]}`,
		"payload type is null":      `{"payload":"","payloadType":null,"signatures":[]}`,
		"signatures is an object":   `{"payload":"","payloadType":"t","signatures":{}}`,
		"signature is a string":     `{"payload":"","payloadType":"t","signatures":["x"]}`,
		"sig is a number":           `{"payload":"","payloadType":"t","signatures":[{"sig":1}]}`,
		"keyid is an object":        `{"payload":"","payloadType":"t","signatures":[{"sig":"","keyid":{}}]}`,
		"unknown field malformed":   `{` + ok + `,"x":}`,
		"signature object unclosed": `{"payload":"","payloadType":"t","signatures":[{"sig":""`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestParseIgnoresUnknownFields(t *testing.T) {
	in := `{"x":{"a":[1]},"payload":"eA==","payloadType":"t","signatures":[{"y":1,"sig":"eA=="}]}`
	e, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if e.Payload != "eA==" || e.PayloadType != "t" || len(e.Signatures) != 1 || e.Signatures[0].Sig != "eA==" {
		t.Fatalf("envelope = %+v", e)
	}
}

func TestParseLimits(t *testing.T) {
	if _, err := Parse(make([]byte, maxEnvelopeBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large envelope: %v", err)
	}
	sigs := strings.TrimSuffix(strings.Repeat(`{"sig":""},`, MaxSignatures+1), ",")
	in := fmt.Sprintf(`{"payload":"","payloadType":"t","signatures":[%s]}`, sigs)
	if _, err := Parse([]byte(in)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("too many signatures: %v", err)
	}
	flood := `{"payload":"","payloadType":"t","signatures":[` + strings.Repeat(`{},`, maxEnvelopeBytes/4) + `{}]}`
	allocs := testing.AllocsPerRun(1, func() { _, _ = Parse([]byte(flood)) })
	if allocs > 1000 {
		t.Fatalf("flood caused %.0f allocations", allocs)
	}
}

func TestIDIgnoresSignatures(t *testing.T) {
	a := signer(t, RoleAdministrator)
	b := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", a)
	first, err := Verify(e, TypeFlowVersion, trust(a), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := Countersign(e, b); err != nil {
		t.Fatal(err)
	}
	second, err := Verify(e, TypeFlowVersion, trust(a), 1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Verify(sign(t, TypeFlowVersion, "y", a), TypeFlowVersion, trust(a), 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.ID == other.ID || len(first.ID) != 64 {
		t.Fatalf("ids: %s %s %s", first.ID, second.ID, other.ID)
	}
}

func TestPublicKeyEncoding(t *testing.T) {
	s := signer(t, RoleAgent)
	ed, ml := s.Public().Bytes()
	k, err := NewPublicKey(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	if k.Fingerprint() != s.Public().Fingerprint() {
		t.Fatal("fingerprint changed after encoding")
	}
	if _, err := NewPublicKey(ed[:31], ml); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short Ed25519 key: %v", err)
	}
	if _, err := NewPublicKey(ed, ml[:100]); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short ML-DSA key: %v", err)
	}

	otherEd, otherML := signer(t, RoleAgent).Public().Bytes()
	k2, err := NewPublicKey(otherEd, ml)
	if err != nil {
		t.Fatal(err)
	}
	k3, err := NewPublicKey(ed, otherML)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Fingerprint() == k.Fingerprint() {
		t.Fatal("fingerprint ignores the Ed25519 key")
	}
	if k3.Fingerprint() == k.Fingerprint() {
		t.Fatal("fingerprint ignores the ML-DSA key")
	}

	// The key must not alias caller memory, in either direction.
	in := bytes.Clone(ed)
	k4, err := NewPublicKey(in, ml)
	if err != nil {
		t.Fatal(err)
	}
	before := k4.Fingerprint()
	in[0] ^= 1
	if k4.Fingerprint() != before {
		t.Fatal("key aliases its input")
	}
	out, _ := k4.Bytes()
	out[0] ^= 1
	if k4.Fingerprint() != before {
		t.Fatal("Bytes aliases the key")
	}
}

func TestSmallOrderEd25519KeysAreRejected(t *testing.T) {
	_, ml := signer(t, RoleAgent).Public().Bytes()
	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1
	zeroY := make([]byte, ed25519.PublicKeySize)
	negOne, _ := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	orderEight, _ := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	for name, key := range map[string][]byte{"identity": identity, "y zero": zeroY, "negative one": negOne, "order eight": orderEight} {
		if _, err := NewPublicKey(key, ml); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUnknownSignatureSizesAreIgnored(t *testing.T) {
	a := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", a)
	e.Signatures = append(e.Signatures, Signature{Sig: base64.StdEncoding.EncodeToString(make([]byte, 10))})
	if _, err := Verify(e, TypeFlowVersion, trust(a), 1); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidEd25519SignatureDoesNotHideValidOne(t *testing.T) {
	a := signer(t, RoleAdministrator)
	e := sign(t, TypeFlowVersion, "x", a)
	junkEd := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	junkML := base64.StdEncoding.EncodeToString(make([]byte, 3309))
	e.Signatures = append([]Signature{{Sig: junkEd}, {Sig: junkML}}, e.Signatures...)
	if _, err := Verify(e, TypeFlowVersion, trust(a), 1); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedKeysDiffer(t *testing.T) {
	a, b := signer(t, RoleAgent), signer(t, RoleAgent)
	if a.Public().Fingerprint() == b.Public().Fingerprint() {
		t.Fatal("generated keys match")
	}
}

func FuzzParseAndVerify(f *testing.F) {
	a := signer(f, RoleAdministrator)
	seed, _ := json.Marshal(sign(f, TypeFlowVersion, "seed", a))
	f.Add(seed)
	f.Add([]byte(`{"payload":"","payloadType":"","signatures":[]}`))
	f.Add([]byte(`null`))
	trusted := trust(a)
	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := Parse(data)
		if err != nil {
			return
		}
		got, err := Verify(env, TypeFlowVersion, trusted, 1)
		if err == nil && string(got.Payload) != "seed" {
			t.Fatalf("forged payload accepted: %q", got.Payload)
		}
	})
}
