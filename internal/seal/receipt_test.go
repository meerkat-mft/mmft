package seal

import (
	"encoding/json"
	"errors"
	"testing"

	"mmft.dev/mmft/internal/statement"
)

// receiptFixture has a destination signer and a manifest for a sealed file.
func receiptFixture(t *testing.T) (*statement.Signer, statement.Verifier, Manifest, Sealed) {
	t.Helper()
	dest, err := statement.GenerateSigner(statement.RoleAgent)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	d := delivery(deliveryA)
	s, err := Seal(writeSource(t, []byte("receipt test")), f.spool, f.identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	e, err := SignManifest(d, s, f.agent)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := VerifyManifest(raw, f.source, d)
	if err != nil {
		t.Fatal(err)
	}
	return dest, statement.Verifier{Key: dest.Public(), Role: statement.RoleAgent, Owner: destinationID}, m, s
}

func signedReceipt(t *testing.T, signer *statement.Signer, d Delivery, s Sealed) []byte {
	t.Helper()
	e, err := SignReceipt(d, s, signer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReceiptRoundTrips(t *testing.T) {
	signer, dest, m, s := receiptFixture(t)
	d := delivery(deliveryA)
	r, id, err := VerifyReceipt(signedReceipt(t, signer, d, s), dest, d, m)
	if err != nil || len(id) != 64 {
		t.Fatalf("id %q, err %v", id, err)
	}
	if r.Result != ResultSucceeded || r.SealedSHA256 != m.SealedSHA256 || r.SealedSize != m.SealedSize {
		t.Fatalf("receipt %+v does not match manifest %+v", r, m)
	}
}

func TestReceiptMustMatchTheDeliveryAndFile(t *testing.T) {
	signer, dest, m, s := receiptFixture(t)
	d := delivery(deliveryA)
	raw := signedReceipt(t, signer, d, s)

	other := d
	other.DeliveryID = deliveryB
	if _, _, err := VerifyReceipt(raw, dest, other, m); !errors.Is(err, ErrReceiptMismatch) {
		t.Errorf("another delivery: got %v", err)
	}
	changed := s
	changed.SHA256[0] ^= 1
	if _, _, err := VerifyReceipt(signedReceipt(t, signer, d, changed), dest, d, m); !errors.Is(err, ErrReceiptMismatch) {
		t.Errorf("another sealed file: got %v", err)
	}
	shorter := s
	shorter.Size--
	if _, _, err := VerifyReceipt(signedReceipt(t, signer, d, shorter), dest, d, m); !errors.Is(err, ErrReceiptMismatch) {
		t.Errorf("another size: got %v", err)
	}
}

func TestReceiptMustBeSignedByTheDestination(t *testing.T) {
	signer, dest, m, s := receiptFixture(t)
	d := delivery(deliveryA)
	raw := signedReceipt(t, signer, d, s)

	other, err := statement.GenerateSigner(statement.RoleAgent)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := statement.Verifier{Key: other.Public(), Role: statement.RoleAgent, Owner: destinationID}
	if _, _, err := VerifyReceipt(raw, wrongKey, d, m); !errors.Is(err, statement.ErrNotEnoughSigners) {
		t.Errorf("another key: got %v", err)
	}
	// The source can't sign the destination's receipt.
	source := dest
	source.Owner = sourceID
	if _, _, err := VerifyReceipt(raw, source, d, m); !errors.Is(err, ErrReceiptMismatch) {
		t.Errorf("the source's verifier: got %v", err)
	}
	// A manifest is not a receipt.
	f := newFixture(t)
	if _, _, err := VerifyReceipt(signedManifest(t, f, d), statement.Verifier{Key: f.agent.Public(), Role: statement.RoleAgent, Owner: destinationID}, d, m); !errors.Is(err, statement.ErrWrongType) {
		t.Errorf("a manifest: got %v", err)
	}
}
