package trust

import (
	"encoding/json"
	"errors"
	"time"

	"mmft.dev/mmft/internal/statement"
)

// MaxApprovalCertificates bounds the certificates an approval carries. It
// matches the most signatures one statement may have.
const MaxApprovalCertificates = statement.MaxSignatures

// ErrInvalidApproval reports an approval that is malformed or doesn't verify.
var ErrInvalidApproval = errors.New("trust: invalid approval")

// Approval is a statement signed by administrators, with the certificates of
// its signers and the root key that issued them, as ADR 0023 defines. The
// certificates travel beside the statement rather than in its payload, because
// who will sign isn't known when the payload is built. Each is signed by the
// root, so it needs no other protection.
type Approval struct {
	Statement                 json.RawMessage   `json:"statement"`
	AdministratorCertificates []json.RawMessage `json:"administrator_certificates"`
	RootEd25519               []byte            `json:"root_ed25519"`
	RootMLDSA65               []byte            `json:"root_mldsa65"`
}

// VerifyApproval verifies an approval of the wanted type against the pinned
// root: the root key must match the pin, each certificate must verify against
// it, and required distinct administrators must have signed the statement.
func VerifyApproval(data []byte, want statement.Type, pinnedRoot string, required int, now time.Time) (*statement.Verified, error) {
	var a Approval
	if err := strictJSON(data, &a); err != nil {
		return nil, ErrInvalidApproval
	}
	if len(a.AdministratorCertificates) == 0 || len(a.AdministratorCertificates) > MaxApprovalCertificates {
		return nil, ErrInvalidApproval
	}
	root, err := statement.NewPublicKey(a.RootEd25519, a.RootMLDSA65)
	if err != nil {
		return nil, ErrInvalidApproval
	}
	var signers []statement.Verifier
	for _, cert := range a.AdministratorCertificates {
		v, _, err := VerifyAdministrator(cert, root, pinnedRoot, now)
		if err != nil {
			return nil, err
		}
		signers = append(signers, v)
	}
	e, err := statement.Parse(a.Statement)
	if err != nil {
		return nil, err
	}
	return statement.Verify(e, want, signers, required)
}

// CheckApproval verifies an approval against the root key it carries, and
// requires one administrator's signature. The orchestrator uses it to refuse a
// malformed or forged approval before storing it. Like CheckIdentity, it proves
// nothing about trust, because the orchestrator pins no root. Agents verify
// with VerifyApproval, against their own pin and their own approver count.
func CheckApproval(data []byte, want statement.Type, now time.Time) (*statement.Verified, error) {
	var a Approval
	if err := strictJSON(data, &a); err != nil {
		return nil, ErrInvalidApproval
	}
	root, err := statement.NewPublicKey(a.RootEd25519, a.RootMLDSA65)
	if err != nil {
		return nil, ErrInvalidApproval
	}
	return VerifyApproval(data, want, root.Fingerprint(), 1, now)
}
