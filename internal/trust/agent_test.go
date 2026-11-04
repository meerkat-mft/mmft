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
	testAgentID = "019a3f2e-7c11-7d3e-9f7b-2c1d4e5f6a7b"
	oneUse      = "one-use-value-for-tests"
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
	e, err := ProveEnrollment(a.signer, oneUse, "agent-a", a.keys.Recipient, csr)
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
	if err := CheckEnrollment(proof, oneUse, "agent-a", a.keys, csr); err != nil {
		t.Fatal(err)
	}

	swapped := func(f func(*AgentKeys)) AgentKeys {
		k := a.keys
		f(&k)
		return k
	}
	cases := map[string]struct {
		proof []byte
		token string
		name  string
		keys  AgentKeys
		csr   []byte
	}{
		"other agent's keys":   {proof, oneUse, "agent-a", other.keys, csr},
		"swapped ed25519":      {proof, oneUse, "agent-a", swapped(func(k *AgentKeys) { k.Ed25519 = other.keys.Ed25519 }), csr},
		"swapped recipient":    {proof, oneUse, "agent-a", swapped(func(k *AgentKeys) { k.Recipient = other.keys.Recipient }), csr},
		"other token":          {proof, "another-token", "agent-a", a.keys, csr},
		"other name":           {proof, oneUse, "agent-b", a.keys, csr},
		"other csr":            {proof, oneUse, "agent-a", a.keys, []byte("another request")},
		"signed by other keys": {prove(t, other, csr), oneUse, "agent-a", a.keys, csr},
		"garbage":              {[]byte("{}"), oneUse, "agent-a", a.keys, csr},
	}
	for name, c := range cases {
		if err := CheckEnrollment(c.proof, c.token, c.name, c.keys, c.csr); err == nil {
			t.Errorf("%s: proof accepted", name)
		}
	}
}

func TestEnrollmentProofNeedsTheAgentRole(t *testing.T) {
	admin, err := statement.GenerateSigner(statement.RoleAdministrator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProveEnrollment(admin, oneUse, "agent-a", newAgent(t).keys.Recipient, nil); !errors.Is(err, statement.ErrRoleNotAllowed) {
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
		AgentID: testAgentID, Workspace: "lab", AgentName: "agent-a", Keys: a.keys,
		ExpectedFingerprint: a.keys.Fingerprint(), ExpectedID: testAgentID, ExpectedName: "agent-a",
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
	if claim.AgentID != testAgentID || claim.Workspace != "lab" || claim.AgentName != "agent-a" {
		t.Fatalf("claim = %+v", claim)
	}
	if claim.Keys().Fingerprint() != a.keys.Fingerprint() || v.Key.Fingerprint() != a.signer.Public().Fingerprint() {
		t.Fatal("verified keys differ from the agent's")
	}
	if v.Role != statement.RoleAgent || v.Owner != testAgentID {
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
		"other name":        func(r *AgentRequest) { r.AgentName = "agent-b" },
		"no expectation":    func(r *AgentRequest) { r.ExpectedFingerprint = "" },
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
