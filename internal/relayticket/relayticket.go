// Package relayticket issues and checks relay tickets, as ADR 0020 defines. The
// orchestrator signs a ticket for each side of a delivery, and the relay checks
// it without a database or a call back to the orchestrator.
package relayticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"google.golang.org/protobuf/proto"

	relayv1 "mmft.dev/mmft/gen/relay/v1"
)

const (
	// KeyFile holds the orchestrator's ticket key, beside the connection CA.
	KeyFile = "relay-ticket.key"
	// Lifetime is how long a ticket can be used to open or reopen a stream.
	Lifetime = 15 * time.Minute

	version  = 1
	maxBytes = 1024
	// signingContext separates ticket signatures from anything else the key
	// could ever sign.
	signingContext = "mmft relay ticket v1\x00"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Errors returned by this package.
var (
	ErrInvalid = errors.New("relayticket: invalid ticket")
	ErrExpired = errors.New("relayticket: the ticket has expired")
	ErrBadKey  = errors.New("relayticket: invalid ticket key")
)

// Role is the side of a delivery a ticket allows.
type Role = relayv1.TicketRole

// The two roles.
const (
	Send    = relayv1.TicketRole_TICKET_ROLE_SEND
	Receive = relayv1.TicketRole_TICKET_ROLE_RECEIVE
)

// Ticket lets Holder take one side of a delivery with Peer until ExpiresAt.
type Ticket struct {
	DeliveryID string
	Role       Role
	Holder     string
	Peer       string
	ExpiresAt  time.Time
}

func (t Ticket) check() error {
	if t.Role != Send && t.Role != Receive {
		return fmt.Errorf("%w: unknown role", ErrInvalid)
	}
	for _, id := range []string{t.DeliveryID, t.Holder, t.Peer} {
		if !uuidPattern.MatchString(id) {
			return fmt.Errorf("%w: malformed ID", ErrInvalid)
		}
	}
	if t.Holder == t.Peer {
		return fmt.Errorf("%w: an agent can't deliver to itself", ErrInvalid)
	}
	return nil
}

// Issue signs a ticket.
func Issue(key ed25519.PrivateKey, t Ticket) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrBadKey
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	payload, err := proto.Marshal(&relayv1.TicketPayload{
		Version:       version,
		DeliveryId:    t.DeliveryID,
		Role:          t.Role,
		HolderAgentId: t.Holder,
		PeerAgentId:   t.Peer,
		ExpiresAt:     t.ExpiresAt.Unix(),
	})
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, signed(payload))
	return proto.Marshal(&relayv1.SignedTicket{Payload: payload, Signature: sig})
}

// Verify checks a ticket's signature and expiry, and returns what it allows.
func Verify(pub ed25519.PublicKey, data []byte, now time.Time) (Ticket, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Ticket{}, ErrBadKey
	}
	if len(data) > maxBytes {
		return Ticket{}, fmt.Errorf("%w: too long", ErrInvalid)
	}
	var st relayv1.SignedTicket
	if err := proto.Unmarshal(data, &st); err != nil {
		return Ticket{}, fmt.Errorf("%w: malformed", ErrInvalid)
	}
	if !ed25519.Verify(pub, signed(st.GetPayload()), st.GetSignature()) {
		return Ticket{}, fmt.Errorf("%w: bad signature", ErrInvalid)
	}
	var p relayv1.TicketPayload
	if err := proto.Unmarshal(st.GetPayload(), &p); err != nil {
		return Ticket{}, fmt.Errorf("%w: malformed", ErrInvalid)
	}
	if p.GetVersion() != version {
		return Ticket{}, fmt.Errorf("%w: unknown version", ErrInvalid)
	}
	t := Ticket{
		DeliveryID: p.GetDeliveryId(),
		Role:       p.GetRole(),
		Holder:     p.GetHolderAgentId(),
		Peer:       p.GetPeerAgentId(),
		ExpiresAt:  time.Unix(p.GetExpiresAt(), 0),
	}
	if err := t.check(); err != nil {
		return Ticket{}, err
	}
	if !now.Before(t.ExpiresAt) {
		return Ticket{}, ErrExpired
	}
	return t, nil
}

func signed(payload []byte) []byte {
	return append([]byte(signingContext), payload...)
}

// LoadOrCreateKey reads the ticket key from dir, creating it first if it
// doesn't exist.
func LoadOrCreateKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(filepath.Clean(dir), KeyFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return createKey(path)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, ErrBadKey
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrBadKey
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrBadKey
	}
	return key, nil
}

func createKey(path string) (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return key, f.Close()
}

// PublicKey returns the hex public key that the relay is configured with.
func PublicKey(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

// ParsePublicKey reads a hex public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrBadKey
	}
	return ed25519.PublicKey(b), nil
}
