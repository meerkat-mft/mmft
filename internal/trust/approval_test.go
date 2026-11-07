package trust

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"mmft.dev/mmft/internal/statement"
)

// approvalKeys is a root and administrators certified by it, in memory.
type approvalKeys struct {
	root   *statement.Signer
	admins []*statement.Signer
	certs  []json.RawMessage
}

func newApprovalKeys(t *testing.T, owners ...string) approvalKeys {
	t.Helper()
	root, err := statement.GenerateSigner(statement.RoleRoot)
	if err != nil {
		t.Fatal(err)
	}
	k := approvalKeys{root: root}
	for _, owner := range owners {
		admin, err := statement.GenerateSigner(statement.RoleAdministrator)
		if err != nil {
			t.Fatal(err)
		}
		ed, ml := admin.Public().Bytes()
		e, err := CertifyAdministrator(root, root.Public().Fingerprint(),
			PublicRecord{Version: 1, Owner: owner, Ed25519: ed, MLDSA65: ml}, admin.Public().Fingerprint(), now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := json.Marshal(e)
		k.admins = append(k.admins, admin)
		k.certs = append(k.certs, cert)
	}
	return k
}

// approval signs payload with every administrator and bundles the result.
func (k approvalKeys) approval(t *testing.T, payload []byte) []byte {
	t.Helper()
	e, err := statement.Sign(statement.TypeFlowVersion, payload, k.admins[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range k.admins[1:] {
		if err := statement.Countersign(e, a); err != nil {
			t.Fatal(err)
		}
	}
	return k.bundle(t, e, k.certs)
}

func (k approvalKeys) bundle(t *testing.T, e *statement.Envelope, certs []json.RawMessage) []byte {
	t.Helper()
	signed, _ := json.Marshal(e)
	ed, ml := k.root.Public().Bytes()
	data, err := json.Marshal(Approval{Statement: signed, AdministratorCertificates: certs, RootEd25519: ed, RootMLDSA65: ml})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var flowPayload = []byte(`{"version":1}`)

func TestApprovalVerifies(t *testing.T) {
	k := newApprovalKeys(t, "sam.lee")
	data := k.approval(t, flowPayload)
	got, err := CheckApproval(data, statement.TypeFlowVersion, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != string(flowPayload) || len(got.Signers) != 1 || got.Signers[0].Owner != "sam.lee" {
		t.Errorf("verified %+v", got)
	}
	if _, err := VerifyApproval(data, statement.TypeFlowVersion, k.root.Public().Fingerprint(), 1, now); err != nil {
		t.Errorf("VerifyApproval against the pin: %v", err)
	}
}

func TestApprovalCountsAdministrators(t *testing.T) {
	k := newApprovalKeys(t, "sam.lee", "kim.ito")
	data := k.approval(t, flowPayload)
	if _, err := VerifyApproval(data, statement.TypeFlowVersion, k.root.Public().Fingerprint(), 2, now); err != nil {
		t.Fatalf("two administrators: %v", err)
	}
	one := newApprovalKeys(t, "sam.lee")
	if _, err := VerifyApproval(one.approval(t, flowPayload), statement.TypeFlowVersion, one.root.Public().Fingerprint(), 2, now); !errors.Is(err, statement.ErrNotEnoughSigners) {
		t.Errorf("one administrator for two: %v", err)
	}
}

func TestApprovalRefusals(t *testing.T) {
	k := newApprovalKeys(t, "sam.lee")
	other := newApprovalKeys(t, "kim.ito")
	signedBy := func(s *statement.Signer) *statement.Envelope {
		e, err := statement.Sign(statement.TypeFlowVersion, flowPayload, s)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	retirement, err := statement.Sign(statement.TypeFlowRetirement, flowPayload, k.admins[0])
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		data []byte
		pin  string
	}{
		// The signer's certificate is missing, so its key isn't trusted.
		"signer without a certificate": {k.bundle(t, signedBy(other.admins[0]), k.certs), ""},
		// The certificate was issued by another root than the one carried.
		"certificate from another root": {k.bundle(t, signedBy(other.admins[0]), other.certs), ""},
		"no certificates":               {k.bundle(t, signedBy(k.admins[0]), nil), ""},
		"another statement type":        {k.bundle(t, retirement, k.certs), ""},
		"root that doesn't match the pin": {
			k.approval(t, flowPayload), other.root.Public().Fingerprint(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			if tc.pin == "" {
				_, err = CheckApproval(tc.data, statement.TypeFlowVersion, now)
			} else {
				_, err = VerifyApproval(tc.data, statement.TypeFlowVersion, tc.pin, 1, now)
			}
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestApprovalNeedsACurrentCertificate(t *testing.T) {
	k := newApprovalKeys(t, "sam.lee")
	if _, err := CheckApproval(k.approval(t, flowPayload), statement.TypeFlowVersion, now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired certificate: %v", err)
	}
}

func TestApprovalIsDecodedStrictly(t *testing.T) {
	k := newApprovalKeys(t, "sam.lee")
	data := k.approval(t, flowPayload)
	for name, bad := range map[string][]byte{
		"unknown field":  append(slices.Clone(data[:len(data)-1]), []byte(`,"note":"x"}`)...),
		"trailing data":  append(append([]byte{}, data...), []byte(`{}`)...),
		"not an object":  []byte(`[]`),
		"too many certs": k.bundle(t, nil, make([]json.RawMessage, MaxApprovalCertificates+1)),
	} {
		if _, err := CheckApproval(bad, statement.TypeFlowVersion, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
