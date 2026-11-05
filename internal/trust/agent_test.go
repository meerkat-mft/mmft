//go:build !windows

// These tests store private keys, which Windows refuses until its access
// control lists are checked. See perm_windows.go.

package trust

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"mmft.dev/mmft/internal/statement"
)

const (
	oneUse = "one-use-value-for-tests"
)

type testAgent struct {
	signer *statement.Signer
	keys   AgentKeys
}

func newAgent(t *testing.T) testAgent {
	t.Helper()
	s, err := statement.GenerateSigner(statement.RoleAgent)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ed, ml := s.Public().Bytes()
	return testAgent{signer: s, keys: AgentKeys{Ed25519: ed, MLDSA65: ml, Recipient: id.Recipient().String()}}
}

func TestFingerprintCoversEveryKey(t *testing.T) {
	a, b := newAgent(t), newAgent(t)
	fp := a.keys.Fingerprint()
	if len(fp) != 64 {
		t.Fatalf("fingerprint = %q", fp)
	}
	if a.keys.Fingerprint() != fp {
		t.Fatal("fingerprint is not stable")
	}
	for name, k := range map[string]AgentKeys{
		"ed25519":   {Ed25519: b.keys.Ed25519, MLDSA65: a.keys.MLDSA65, Recipient: a.keys.Recipient},
		"mldsa65":   {Ed25519: a.keys.Ed25519, MLDSA65: b.keys.MLDSA65, Recipient: a.keys.Recipient},
		"recipient": {Ed25519: a.keys.Ed25519, MLDSA65: a.keys.MLDSA65, Recipient: b.keys.Recipient},
	} {
		if got := k.Fingerprint(); got == fp || got == "" {
			t.Errorf("changing %s gave fingerprint %q", name, got)
		}
	}
}

func TestAgentIDComesFromTheKeys(t *testing.T) {
	a, b := newAgent(t), newAgent(t)
	id := a.keys.AgentID()
	if !ValidAgentID(id) || id != a.keys.AgentID() {
		t.Fatalf("ID %q is not a stable UUID", id)
	}
	if id[14] != '8' || !strings.ContainsRune("89ab", rune(id[19])) {
		t.Fatalf("ID %q is not a version 8 UUID", id)
	}
	// Apart from the version digit (12) and the variant digit (16), which
	// the UUID format sets, the ID is the fingerprint's first 32 hex digits.
	fp, hexID := a.keys.Fingerprint(), strings.ReplaceAll(id, "-", "")
	for i := range 32 {
		if i != 12 && i != 16 && hexID[i] != fp[i] {
			t.Fatalf("ID %q does not come from fingerprint %s", id, fp)
		}
	}
	if b.keys.AgentID() == id {
		t.Fatal("two key sets share an ID")
	}
	swapped := a.keys
	swapped.Recipient = b.keys.Recipient
	if swapped.AgentID() == id {
		t.Fatal("a swapped recipient keeps the ID")
	}
	if (AgentKeys{}).AgentID() != "" {
		t.Fatal("invalid keys have an ID")
	}
}

func TestAgentKeysRejectWeakOrInvalidRecipients(t *testing.T) {
	a := newAgent(t)
	classic, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]string{
		"classical": classic.Recipient().String(),
		"empty":     "",
		"garbage":   "age1pq1notakey",
		"upper":     strings.ToUpper(a.keys.Recipient),
	} {
		k := a.keys
		k.Recipient = r
		if k.Validate() == nil || k.Fingerprint() != "" {
			t.Errorf("%s recipient was accepted", name)
		}
	}
}

func prove(t *testing.T, a testAgent, csr []byte) []byte {
	t.Helper()
	e, err := ProveEnrollment(a.signer, oneUse, "lab", "agent-a", a.keys.Recipient, csr)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	return b
}

func TestEnrollmentProof(t *testing.T) {
	a, other := newAgent(t), newAgent(t)
	csr := []byte("certificate request")
	proof := prove(t, a, csr)
	if err := CheckEnrollment(proof, oneUse, a.keys.AgentID(), "lab", "agent-a", a.keys, csr); err != nil {
		t.Fatal(err)
	}

	swapped := func(f func(*AgentKeys)) AgentKeys {
		k := a.keys
		f(&k)
		return k
	}
	id := a.keys.AgentID()
	cases := map[string]struct {
		proof     []byte
		token     string
		id        string
		workspace string
		name      string
		keys      AgentKeys
		csr       []byte
	}{
		"other agent's keys":   {proof, oneUse, id, "lab", "agent-a", other.keys, csr},
		"swapped ed25519":      {proof, oneUse, id, "lab", "agent-a", swapped(func(k *AgentKeys) { k.Ed25519 = other.keys.Ed25519 }), csr},
		"swapped recipient":    {proof, oneUse, id, "lab", "agent-a", swapped(func(k *AgentKeys) { k.Recipient = other.keys.Recipient }), csr},
		"other token":          {proof, "another-token", id, "lab", "agent-a", a.keys, csr},
		"other agent ID":       {proof, oneUse, other.keys.AgentID(), "lab", "agent-a", a.keys, csr},
		"no agent ID":          {proof, oneUse, "", "lab", "agent-a", a.keys, csr},
		"other workspace":      {proof, oneUse, id, "prod", "agent-a", a.keys, csr},
		"other name":           {proof, oneUse, id, "lab", "agent-b", a.keys, csr},
		"other csr":            {proof, oneUse, id, "lab", "agent-a", a.keys, []byte("another request")},
		"signed by other keys": {prove(t, other, csr), oneUse, id, "lab", "agent-a", a.keys, csr},
		"garbage":              {[]byte("{}"), oneUse, id, "lab", "agent-a", a.keys, csr},
	}
	for name, c := range cases {
		if err := CheckEnrollment(c.proof, c.token, c.id, c.workspace, c.name, c.keys, c.csr); err == nil {
			t.Errorf("%s: proof accepted", name)
		}
	}
}

func TestEnrollmentProofNeedsTheAgentRole(t *testing.T) {
	admin, err := statement.GenerateSigner(statement.RoleAdministrator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProveEnrollment(admin, oneUse, "lab", "agent-a", newAgent(t).keys.Recipient, nil); !errors.Is(err, statement.ErrRoleNotAllowed) {
		t.Fatalf("err = %v", err)
	}
}

func adminSigner(t *testing.T, l lab) *statement.Signer {
	t.Helper()
	s, _, err := LoadKey(filepath.Join(l.adminDir, AdminKeyFile), pass, statement.RoleAdministrator)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func request(a testAgent) AgentRequest {
	return AgentRequest{
		AgentID: a.keys.AgentID(), Workspace: "lab", AgentName: "agent-a", Keys: a.keys,
		ExpectedFingerprint: a.keys.Fingerprint(), ExpectedID: a.keys.AgentID(), ExpectedWorkspace: "lab", ExpectedName: "agent-a",
	}
}

func identity(t *testing.T, l lab, req AgentRequest) []byte {
	t.Helper()
	e, err := CertifyAgent(adminSigner(t, l), certificate(t, l, valid), l.rootPub, l.rootPub.Fingerprint(), req, now, valid)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	return b
}

func TestAgentIdentityVerifiesBackToRoot(t *testing.T) {
	l, a := setup(t), newAgent(t)
	claim, v, err := VerifyAgent(identity(t, l, request(a)), l.rootPub.Fingerprint(), now)
	if err != nil {
		t.Fatal(err)
	}
	if claim.AgentID != a.keys.AgentID() || claim.Workspace != "lab" || claim.AgentName != "agent-a" || claim.EnrollmentFingerprint != a.keys.Fingerprint() {
		t.Fatalf("claim = %+v", claim)
	}
	if claim.Keys().Fingerprint() != a.keys.Fingerprint() || v.Key.Fingerprint() != a.signer.Public().Fingerprint() {
		t.Fatal("verified keys differ from the agent's")
	}
	if v.Role != statement.RoleAgent || v.Owner != a.keys.AgentID() {
		t.Fatalf("verifier = %+v", v)
	}
}

func TestCertifyAgentRefusesMismatches(t *testing.T) {
	l, a, other := setup(t), newAgent(t), newAgent(t)
	cert := certificate(t, l, valid)
	admin := adminSigner(t, l)
	cases := map[string]func(*AgentRequest){
		"swapped keys":      func(r *AgentRequest) { r.Keys = other.keys },
		"swapped recipient": func(r *AgentRequest) { r.Keys.Recipient = other.keys.Recipient },
		"other id":          func(r *AgentRequest) { r.AgentID = "019a3f2e-7c11-7d3e-9f7b-000000000000" },
		// The orchestrator and host agree, but the ID isn't the keys' own.
		"id not from keys": func(r *AgentRequest) {
			r.AgentID, r.ExpectedID = other.keys.AgentID(), other.keys.AgentID()
		},
		"other workspace": func(r *AgentRequest) { r.Workspace = "prod" },
		"other name":      func(r *AgentRequest) { r.AgentName = "agent-b" },
		"no expectation":  func(r *AgentRequest) { r.ExpectedFingerprint = "" },
	}
	for name, change := range cases {
		req := request(a)
		change(&req)
		if _, err := CertifyAgent(admin, cert, l.rootPub, l.rootPub.Fingerprint(), req, now, valid); !errors.Is(err, ErrWrongAgent) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestCertifyAgentChecksItsOwnChain(t *testing.T) {
	l, a := setup(t), newAgent(t)
	cert := certificate(t, l, valid)
	other := setup(t)
	if _, err := CertifyAgent(adminSigner(t, l), cert, l.rootPub, other.rootPub.Fingerprint(), request(a), now, valid); !errors.Is(err, ErrWrongRoot) {
		t.Errorf("wrong pin: err = %v", err)
	}
	if _, err := CertifyAgent(adminSigner(t, other), cert, l.rootPub, l.rootPub.Fingerprint(), request(a), now, valid); !errors.Is(err, ErrWrongCertificate) {
		t.Errorf("other administrator: err = %v", err)
	}
	for _, d := range []time.Duration{0, clockSkew, MaxAgentLifetime + time.Hour} {
		if _, err := CertifyAgent(adminSigner(t, l), cert, l.rootPub, l.rootPub.Fingerprint(), request(a), now, d); !errors.Is(err, ErrBadLifetime) {
			t.Errorf("lifetime %v: err = %v", d, err)
		}
	}
	shortest, err := CertifyAgent(adminSigner(t, l), cert, l.rootPub, l.rootPub.Fingerprint(), request(a), now, clockSkew+time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	shortestBytes, _ := json.Marshal(shortest)
	if _, _, err := VerifyAgent(shortestBytes, l.rootPub.Fingerprint(), now); err != nil {
		t.Errorf("shortest lifetime does not verify when signed: %v", err)
	}
	shared := request(a)
	adminEd, _ := adminSigner(t, l).Public().Bytes()
	shared.Keys.Ed25519 = adminEd
	shared.ExpectedFingerprint = shared.Keys.Fingerprint()
	shared.AgentID, shared.ExpectedID = shared.Keys.AgentID(), shared.Keys.AgentID()
	if _, err := CertifyAgent(adminSigner(t, l), cert, l.rootPub, l.rootPub.Fingerprint(), shared, now, valid); !errors.Is(err, ErrAgentSharesKey) {
		t.Errorf("shared key: err = %v", err)
	}
}

func TestVerifyAgentRejects(t *testing.T) {
	l, a := setup(t), newAgent(t)
	good := identity(t, l, request(a))
	other := setup(t)

	if _, _, err := VerifyAgent(good, other.rootPub.Fingerprint(), now); !errors.Is(err, ErrWrongRoot) {
		t.Errorf("other pin: err = %v", err)
	}
	if _, _, err := VerifyAgent(good, l.rootPub.Fingerprint(), now.Add(-time.Hour)); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("too early: err = %v", err)
	}
	if _, _, err := VerifyAgent(good, l.rootPub.Fingerprint(), now.Add(valid)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: err = %v", err)
	}

	// The identity's own window is checked while the certificate is still valid.
	cert := certificate(t, l, valid)
	later, err := CertifyAgent(adminSigner(t, l), cert, l.rootPub, l.rootPub.Fingerprint(), request(a), now.Add(time.Hour), valid)
	if err != nil {
		t.Fatal(err)
	}
	laterBytes, _ := json.Marshal(later)
	if _, _, err := VerifyAgent(laterBytes, l.rootPub.Fingerprint(), now.Add(10*time.Minute)); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("identity not yet valid: err = %v", err)
	}
	short, err := CertifyAgent(adminSigner(t, l), cert, l.rootPub, l.rootPub.Fingerprint(), request(a), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	shortBytes, _ := json.Marshal(short)
	if _, _, err := VerifyAgent(shortBytes, l.rootPub.Fingerprint(), now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Errorf("identity expired: err = %v", err)
	}

	// A chain swapped for another root's, which matches a different pin, must not
	// verify the original signature.
	var e statement.Envelope
	if err := json.Unmarshal(good, &e); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(e.Payload)
	var claim IdentityClaim
	if err := json.Unmarshal(payload, &claim); err != nil {
		t.Fatal(err)
	}
	claim.RootEd25519, claim.RootMLDSA65 = other.rootPub.Bytes()
	claim.AdministratorCertificate = certificate(t, other, valid)
	swapped, _ := json.Marshal(claim)
	e.Payload = base64.StdEncoding.EncodeToString(swapped)
	tampered, _ := json.Marshal(e)
	if _, _, err := VerifyAgent(tampered, other.rootPub.Fingerprint(), now); !errors.Is(err, statement.ErrNotEnoughSigners) {
		t.Errorf("swapped chain: err = %v", err)
	}

	// An identity signed by the agent itself is not an identity.
	self, err := statement.Sign(statement.TypeEnrollmentRequest, payload, a.signer)
	if err != nil {
		t.Fatal(err)
	}
	selfBytes, _ := json.Marshal(self)
	if _, _, err := VerifyAgent(selfBytes, l.rootPub.Fingerprint(), now); !errors.Is(err, statement.ErrWrongType) {
		t.Errorf("wrong type: err = %v", err)
	}
}

func TestCheckIdentity(t *testing.T) {
	l, a := setup(t), newAgent(t)
	good := identity(t, l, request(a))
	claim, id, err := CheckIdentity(good, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 64 {
		t.Fatalf("id = %q", id)
	}
	if claim.AgentID != a.keys.AgentID() || claim.Keys().Fingerprint() != a.keys.Fingerprint() {
		t.Fatalf("claim = %+v", claim)
	}
	if _, _, err := CheckIdentity(good, now.Add(valid)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: err = %v", err)
	}
	if _, _, err := CheckIdentity([]byte(`{}`), now); !errors.Is(err, ErrInvalidIdentity) {
		t.Errorf("not an envelope: err = %v", err)
	}
	var e statement.Envelope
	if err := json.Unmarshal(good, &e); err != nil {
		t.Fatal(err)
	}
	// Reordered signatures and other formatting give the same ID.
	e.Signatures[0], e.Signatures[1] = e.Signatures[1], e.Signatures[0]
	reordered, _ := json.MarshalIndent(e, "", "  ")
	if _, again, err := CheckIdentity(reordered, now); err != nil || again != id {
		t.Errorf("reordered: id = %q, %v; want %q", again, err, id)
	}
	e.Signatures = e.Signatures[:1]
	half, _ := json.Marshal(e)
	if _, _, err := CheckIdentity(half, now); err == nil {
		t.Error("an identity with one signature was accepted")
	}
}

// A verifier refuses an identity whose ID or enrollment fingerprint doesn't
// match its keys, even one an administrator really signed.
func TestVerifyAgentChecksTheIDBinding(t *testing.T) {
	l, a, other := setup(t), newAgent(t), newAgent(t)
	var e statement.Envelope
	if err := json.Unmarshal(identity(t, l, request(a)), &e); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(e.Payload)
	for name, change := range map[string]func(*IdentityClaim){
		"another agent's ID":     func(c *IdentityClaim) { c.AgentID = other.keys.AgentID() },
		"other enrollment print": func(c *IdentityClaim) { c.EnrollmentFingerprint = other.keys.Fingerprint() },
		"no enrollment print":    func(c *IdentityClaim) { c.EnrollmentFingerprint = "" },
	} {
		var c IdentityClaim
		if err := json.Unmarshal(payload, &c); err != nil {
			t.Fatal(err)
		}
		change(&c)
		changed, _ := json.Marshal(c)
		signed, err := statement.Sign(statement.TypeAgentIdentity, changed, adminSigner(t, l))
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(signed)
		if _, _, err := VerifyAgent(data, l.rootPub.Fingerprint(), now); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
