package seal

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	"mmft.dev/mmft/internal/statement"
)

// receiptVersion is the version of the receipt payload.
const receiptVersion = 1

// ResultSucceeded is the only receipt result in M1: the destination holds the
// file. Failures are reported with an error code instead.
const ResultSucceeded = "succeeded"

// ErrReceiptMismatch is returned when a receipt is for another delivery or
// another sealed file.
var ErrReceiptMismatch = errors.New("seal: delivery receipt does not match the delivery")

// Receipt is the payload of a delivery receipt: the destination agent's signed
// statement of the sealed file it received, as it hashed it itself, and the
// result. Like a manifest, it never holds a file name. See ADR 0014.
type Receipt struct {
	Version int `json:"version"`
	Delivery
	SealedSize   int64  `json:"sealed_size"`
	SealedSHA256 string `json:"sealed_sha256"`
	Result       string `json:"result"`
}

// SignReceipt has the destination agent sign a receipt for a sealed file it
// checked against the manifest and opened.
func SignReceipt(d Delivery, s Sealed, agent *statement.Signer) (*statement.Envelope, error) {
	if !d.valid() || s.Size <= 0 {
		return nil, ErrInvalidManifest
	}
	payload, err := json.Marshal(Receipt{
		Version:      receiptVersion,
		Delivery:     d,
		SealedSize:   s.Size,
		SealedSHA256: hex.EncodeToString(s.SHA256[:]),
		Result:       ResultSucceeded,
	})
	if err != nil {
		return nil, err
	}
	return statement.Sign(statement.TypeDeliveryReceipt, payload, agent)
}

// VerifyReceipt checks that a receipt was signed by the destination agent's
// identity key, names exactly the expected delivery, and covers the sealed
// file the manifest describes. It returns the receipt and the statement's ID.
func VerifyReceipt(data []byte, destination statement.Verifier, want Delivery, manifest Manifest) (Receipt, string, error) {
	if !want.valid() || destination.Role != statement.RoleAgent || destination.Owner != want.DestinationAgent {
		return Receipt{}, "", ErrReceiptMismatch
	}
	e, err := statement.Parse(data)
	if err != nil {
		return Receipt{}, "", err
	}
	got, err := statement.Verify(e, statement.TypeDeliveryReceipt, []statement.Verifier{destination}, 1)
	if err != nil {
		return Receipt{}, "", err
	}
	var r Receipt
	if err := strictJSON(got.Payload, &r); err != nil {
		return Receipt{}, "", ErrInvalidManifest
	}
	if r.Version != receiptVersion || !r.valid() || r.SealedSize <= 0 ||
		!hashPattern.MatchString(r.SealedSHA256) || r.Result != ResultSucceeded {
		return Receipt{}, "", ErrInvalidManifest
	}
	if r.Delivery != want || r.SealedSize != manifest.SealedSize || r.SealedSHA256 != manifest.SealedSHA256 {
		return Receipt{}, "", ErrReceiptMismatch
	}
	return r, got.ID, nil
}
