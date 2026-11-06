package relayticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	relayv1 "mmft.dev/mmft/gen/relay/v1"
)

var (
	now      = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	delivery = "0190a0b0-0000-7000-8000-000000000001"
	agentA   = "0190a0b0-0000-7000-8000-00000000000a"
	agentB   = "0190a0b0-0000-7000-8000-00000000000b"
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func valid() Ticket {
	return Ticket{DeliveryID: delivery, Role: Send, Holder: agentA, Peer: agentB, ExpiresAt: now.Add(Lifetime)}
}

func pub(key ed25519.PrivateKey) ed25519.PublicKey { return key.Public().(ed25519.PublicKey) }

func TestTicketRoundTrips(t *testing.T) {
	key := newKey(t)
	data, err := Issue(key, valid())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(pub(key), data, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ExpiresAt.Equal(valid().ExpiresAt) {
		t.Fatalf("expiry %v, want %v", got.ExpiresAt, valid().ExpiresAt)
	}
	got.ExpiresAt = valid().ExpiresAt
	if got != valid() {
		t.Fatalf("got %+v, want %+v", got, valid())
	}
}

func TestExpiredTicketIsRefused(t *testing.T) {
	key := newKey(t)
	data, err := Issue(key, valid())
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(Lifetime), now.Add(Lifetime + time.Second)} {
		if _, err := Verify(pub(key), data, at); !errors.Is(err, ErrExpired) {
			t.Fatalf("at %v: got %v, want ErrExpired", at, err)
		}
	}
}

func TestTicketFromAnotherKeyIsRefused(t *testing.T) {
	data, err := Issue(newKey(t), valid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub(newKey(t)), data, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

// resign replaces a ticket's payload and signs the result with sign.
func resign(t *testing.T, data []byte, edit func(*relayv1.TicketPayload), sign func([]byte) []byte) []byte {
	t.Helper()
	var st relayv1.SignedTicket
	if err := proto.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	var p relayv1.TicketPayload
	if err := proto.Unmarshal(st.Payload, &p); err != nil {
		t.Fatal(err)
	}
	edit(&p)
	payload, err := proto.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	st.Payload = payload
	if sign != nil {
		st.Signature = sign(payload)
	}
	out, err := proto.Marshal(&st)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestChangedTicketIsRefused(t *testing.T) {
	key := newKey(t)
	data, err := Issue(key, valid())
	if err != nil {
		t.Fatal(err)
	}
	edits := map[string]func(*relayv1.TicketPayload){
		"role":     func(p *relayv1.TicketPayload) { p.Role = Receive },
		"holder":   func(p *relayv1.TicketPayload) { p.HolderAgentId = agentB; p.PeerAgentId = agentA },
		"delivery": func(p *relayv1.TicketPayload) { p.DeliveryId = "0190a0b0-0000-7000-8000-000000000002" },
		"expiry":   func(p *relayv1.TicketPayload) { p.ExpiresAt += 3600 },
	}
	for name, edit := range edits {
		if _, err := Verify(pub(key), resign(t, data, edit, nil), now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestSignatureWithoutTheContextIsRefused(t *testing.T) {
	key := newKey(t)
	data, err := Issue(key, valid())
	if err != nil {
		t.Fatal(err)
	}
	bare := resign(t, data, func(*relayv1.TicketPayload) {}, func(payload []byte) []byte { return ed25519.Sign(key, payload) })
	if _, err := Verify(pub(key), bare, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestBadTicketsAreRefused(t *testing.T) {
	key := newKey(t)
	data, err := Issue(key, valid())
	if err != nil {
		t.Fatal(err)
	}
	sign := func(payload []byte) []byte { return ed25519.Sign(key, signed(payload)) }
	cases := map[string][]byte{
		"garbage":   []byte("not a ticket"),
		"too long":  make([]byte, maxBytes+1),
		"version":   resign(t, data, func(p *relayv1.TicketPayload) { p.Version = 2 }, sign),
		"no role":   resign(t, data, func(p *relayv1.TicketPayload) { p.Role = relayv1.TicketRole_TICKET_ROLE_UNSPECIFIED }, sign),
		"self":      resign(t, data, func(p *relayv1.TicketPayload) { p.PeerAgentId = agentA }, sign),
		"bad ID":    resign(t, data, func(p *relayv1.TicketPayload) { p.HolderAgentId = "agent-a" }, sign),
		"no expiry": resign(t, data, func(p *relayv1.TicketPayload) { p.ExpiresAt = 0 }, sign),
	}
	for name, ticket := range cases {
		if _, err := Verify(pub(key), ticket, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIssueRefusesABadTicket(t *testing.T) {
	bad := valid()
	bad.Peer = bad.Holder
	if _, err := Issue(newKey(t), bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestKeyIsCreatedOnceAndKept(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
	again, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(again) {
		t.Fatal("the key changed")
	}
	got, err := ParsePublicKey(PublicKey(first))
	if err != nil || !got.Equal(first.Public()) {
		t.Fatalf("public key did not round-trip: %v", err)
	}
}

func TestDamagedKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(dir); !errors.Is(err, ErrBadKey) {
		t.Fatalf("got %v, want ErrBadKey", err)
	}
	for _, s := range []string{"", "zz", "00"} {
		if _, err := ParsePublicKey(s); !errors.Is(err, ErrBadKey) {
			t.Errorf("%q: got %v, want ErrBadKey", s, err)
		}
	}
}

func TestTicketExpiringTooFarAheadIsRefused(t *testing.T) {
	key := newKey(t)
	ok := valid()
	ok.ExpiresAt = now.Add(Lifetime + clockSkew)
	data, err := Issue(key, ok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub(key), data, now); err != nil {
		t.Fatalf("a ticket at the limit was refused: %v", err)
	}
	long := valid()
	long.ExpiresAt = now.Add(Lifetime + clockSkew + time.Second)
	data, err = Issue(key, long)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub(key), data, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestConcurrentFirstCallsShareOneKey(t *testing.T) {
	for range 20 {
		dir := t.TempDir()
		keys := make([]ed25519.PrivateKey, 8)
		errs := make([]error, 8)
		var wg sync.WaitGroup
		for i := range keys {
			wg.Add(1)
			go func() {
				defer wg.Done()
				keys[i], errs[i] = LoadOrCreateKey(dir)
			}()
		}
		wg.Wait()
		for i := range keys {
			if errs[i] != nil {
				t.Fatalf("call %d: %v", i, errs[i])
			}
			if !keys[i].Equal(keys[0]) {
				t.Fatalf("call %d got a different key", i)
			}
		}
	}
}
