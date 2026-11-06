package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	relayv1 "mmft.dev/mmft/gen/relay/v1"
	"mmft.dev/mmft/internal/connca"
	"mmft.dev/mmft/internal/relayticket"
)

// syncBuffer is a log writer that tests can read while the relay writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testRelay is a running relay with the CA and ticket key it trusts.
type testRelay struct {
	ca   *connca.Authority
	key  ed25519.PrivateKey
	addr string
	fp   []byte
	log  *syncBuffer
}

type testAgent struct {
	id   string
	cert tls.Certificate
}

func newCA(t *testing.T) *connca.Authority {
	t.Helper()
	ca, err := connca.Create(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func startRelay(t *testing.T, limits Limits, now func() time.Time) *testRelay {
	t.Helper()
	ca := newCA(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "relay")
	fp, err := CreateIdentity(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Fingerprint(identity), fp) {
		t.Fatal("the loaded identity has another fingerprint")
	}
	block, _ := pem.Decode(ca.CertificatePEM())
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	log := &syncBuffer{}
	s, err := New(Config{Identity: identity, ConnectionCA: caCert, TicketKey: key.Public().(ed25519.PublicKey), Limits: limits, Log: log, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return &testRelay{ca: ca, key: key, addr: lis.Addr().String(), fp: fp, log: log}
}

func newAgent(t *testing.T, ca *connca.Authority) testAgent {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	der, err := ca.SignAgent(csr, id, time.Now(), connca.ConnectionLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return testAgent{id: id, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
}

func (r *testRelay) agent(t *testing.T) testAgent { return newAgent(t, r.ca) }

func (r *testRelay) client(t *testing.T, a testAgent) relayv1.RelayServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(r.addr, grpc.WithTransportCredentials(credentials.NewTLS(PinnedClient(r.fp, a.cert))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return relayv1.NewRelayServiceClient(conn)
}

func newDelivery() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (r *testRelay) ticket(t *testing.T, delivery string, role relayticket.Role, holder, peer testAgent) []byte {
	t.Helper()
	return issue(t, r.key, relayticket.Ticket{DeliveryID: delivery, Role: role, Holder: holder.id, Peer: peer.id, ExpiresAt: time.Now().Add(relayticket.Lifetime)})
}

func issue(t *testing.T, key ed25519.PrivateKey, tk relayticket.Ticket) []byte {
	t.Helper()
	data, err := relayticket.Issue(key, tk)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func openSend(t *testing.T, c relayv1.RelayServiceClient, ticket []byte, delivery string, total uint64) relayv1.RelayService_SendClient {
	t.Helper()
	stream, err := c.Send(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	// A refused open shows up at the next receive, so its error is ignored.
	_ = stream.Send(&relayv1.SendRequest{Message: &relayv1.SendRequest_Open{Open: &relayv1.SendOpen{Ticket: ticket, DeliveryId: delivery, TotalBytes: total}}})
	return stream
}

func openReceive(t *testing.T, c relayv1.RelayServiceClient, ticket []byte, delivery string, offset uint64) relayv1.RelayService_ReceiveClient {
	t.Helper()
	stream, err := c.Receive(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&relayv1.ReceiveRequest{Message: &relayv1.ReceiveRequest_Open{Open: &relayv1.ReceiveOpen{Ticket: ticket, DeliveryId: delivery, ResumeOffset: offset}}})
	return stream
}

// sendAll sends data from the relay's start offset in small chunks, and
// returns the start offset, the last acknowledgement, and how the stream ended.
func sendAll(stream relayv1.RelayService_SendClient, data []byte, chunk int) (start, acked uint64, err error) {
	resp, err := stream.Recv()
	if err != nil {
		return 0, 0, err
	}
	start = resp.GetStartOffset()
	step := uint64(chunk) //nolint:gosec // chunk sizes in tests are positive
	for off := start; off < uint64(len(data)); off += step {
		end := min(off+step, uint64(len(data)))
		if err := stream.Send(&relayv1.SendRequest{Message: &relayv1.SendRequest_Data{Data: data[off:end]}}); err != nil {
			break
		}
	}
	_ = stream.CloseSend()
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return start, acked, nil
		}
		if err != nil {
			return start, acked, err
		}
		acked = resp.GetAcknowledgedBytes()
	}
}

// receiveAll appends what arrives to have, acknowledging each chunk.
func receiveAll(stream relayv1.RelayService_ReceiveClient, have []byte) ([]byte, error) {
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return have, nil
		}
		if err != nil {
			return have, err
		}
		have = append(have, resp.GetData()...)
		_ = stream.Send(&relayv1.ReceiveRequest{Message: &relayv1.ReceiveRequest_WrittenBytes{WrittenBytes: uint64(len(have))}})
	}
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
}

type sendResult struct {
	start, acked uint64
	err          error
}

func runSend(stream relayv1.RelayService_SendClient, data []byte, chunk int) chan sendResult {
	got := make(chan sendResult, 1)
	go func() {
		start, acked, err := sendAll(stream, data, chunk)
		got <- sendResult{start, acked, err}
	}()
	return got
}

func TestRelayForwardsTheBytes(t *testing.T) {
	data := make([]byte, 100_000)
	_, _ = rand.Read(data)
	for _, senderFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("sender first %v", senderFirst), func(t *testing.T) {
			r := startRelay(t, Limits{}, nil)
			a, b := r.agent(t), r.agent(t)
			d := newDelivery()
			var sent chan sendResult
			if senderFirst {
				sent = runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, uint64(len(data))), data, 4096)
				time.Sleep(50 * time.Millisecond)
			}
			recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 0)
			if !senderFirst {
				time.Sleep(50 * time.Millisecond)
				sent = runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, uint64(len(data))), data, 4096)
			}
			got, err := receiveAll(recv, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("received %d bytes that differ from the %d sent", len(got), len(data))
			}
			res := <-sent
			if res.err != nil || res.start != 0 || res.acked != uint64(len(data)) {
				t.Fatalf("sender: start %d, acked %d, err %v", res.start, res.acked, res.err)
			}
			if !strings.Contains(r.log.String(), `"event":"delivery forwarded"`) {
				t.Fatalf("no finished event in log:\n%s", r.log.String())
			}
		})
	}
}

func TestRelayResumesFromTheReceiversOffset(t *testing.T) {
	r := startRelay(t, Limits{}, nil)
	a, b := r.agent(t), r.agent(t)
	d := newDelivery()
	data := []byte("the sealed bytes of a file, in two parts")
	have := bytes.Clone(data[:10])
	recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, uint64(len(have)))
	sent := runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, uint64(len(data))), data, 7)
	got, err := receiveAll(recv, have)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q", got)
	}
	if res := <-sent; res.err != nil || res.start != 10 || res.acked != uint64(len(data)) {
		t.Fatalf("sender: start %d, acked %d, err %v", res.start, res.acked, res.err)
	}
}

func TestReceiverWithTheWholeFileFinishesAtOnce(t *testing.T) {
	r := startRelay(t, Limits{}, nil)
	a, b := r.agent(t), r.agent(t)
	d := newDelivery()
	data := []byte("already here")
	recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, uint64(len(data)))
	sent := runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, uint64(len(data))), data, 4)
	if _, err := receiveAll(recv, data); err != nil {
		t.Fatal(err)
	}
	if res := <-sent; res.err != nil || res.acked != uint64(len(data)) {
		t.Fatalf("sender: acked %d, err %v", res.acked, res.err)
	}
}

func TestOneSideAloneTimesOut(t *testing.T) {
	r := startRelay(t, Limits{PairWait: 100 * time.Millisecond}, nil)
	a, b := r.agent(t), r.agent(t)
	d := newDelivery()
	_, err := receiveAll(openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 0), nil)
	wantCode(t, err, codes.DeadlineExceeded)
}

func TestTicketsAreChecked(t *testing.T) {
	now := time.Now()
	r := startRelay(t, Limits{PairWait: 2 * time.Second}, func() time.Time { return now })
	a, b, c := r.agent(t), r.agent(t), r.agent(t)
	d := newDelivery()
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	expired := issue(t, r.key, relayticket.Ticket{DeliveryID: d, Role: relayticket.Receive, Holder: b.id, Peer: a.id, ExpiresAt: now})
	forged := issue(t, otherKey, relayticket.Ticket{DeliveryID: d, Role: relayticket.Receive, Holder: b.id, Peer: a.id, ExpiresAt: now.Add(time.Minute)})
	cases := map[string]struct {
		agent    testAgent
		ticket   []byte
		delivery string
	}{
		"another agent's ticket":    {c, r.ticket(t, d, relayticket.Receive, b, a), d},
		"a send ticket on Receive":  {b, r.ticket(t, d, relayticket.Send, b, a), d},
		"another delivery":          {b, r.ticket(t, d, relayticket.Receive, b, a), newDelivery()},
		"an expired ticket":         {b, expired, d},
		"a ticket from another key": {b, forged, d},
		"no ticket":                 {b, nil, d},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := receiveAll(openReceive(t, r.client(t, tc.agent), tc.ticket, tc.delivery, 0), nil)
			wantCode(t, err, codes.PermissionDenied)
		})
	}
	t.Run("a receive ticket on Send", func(t *testing.T) {
		_, _, err := sendAll(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Receive, a, b), d, 1), []byte("x"), 1)
		wantCode(t, err, codes.PermissionDenied)
	})
}

func TestTicketsForDifferentPairsDontMeet(t *testing.T) {
	r := startRelay(t, Limits{PairWait: 2 * time.Second}, nil)
	a, b, c := r.agent(t), r.agent(t), r.agent(t)
	d := newDelivery()
	recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 0)
	time.Sleep(50 * time.Millisecond)
	// c holds a genuine send ticket for this delivery, but to another agent.
	_, _, err := sendAll(openSend(t, r.client(t, c), r.ticket(t, d, relayticket.Send, c, a), d, 1), []byte("x"), 1)
	wantCode(t, err, codes.PermissionDenied)
	// The waiting receiver is undisturbed and still pairs with the real sender.
	sent := runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, 3), []byte("abc"), 1)
	got, err := receiveAll(recv, nil)
	if err != nil || string(got) != "abc" {
		t.Fatalf("got %q, %v", got, err)
	}
	if res := <-sent; res.err != nil {
		t.Fatal(res.err)
	}
}

func TestAgentsFromAnotherCAAreRefused(t *testing.T) {
	r := startRelay(t, Limits{}, nil)
	outsider := newAgent(t, newCA(t))
	stream, err := r.client(t, outsider).Receive(testContext(t))
	if err == nil {
		_, err = stream.Recv()
	}
	wantCode(t, err, codes.Unavailable)
}

func TestAgentsRefuseTheWrongRelay(t *testing.T) {
	r := startRelay(t, Limits{}, nil)
	a := r.agent(t)
	wrong := bytes.Clone(r.fp)
	wrong[0] ^= 1
	conn, err := grpc.NewClient(r.addr, grpc.WithTransportCredentials(credentials.NewTLS(PinnedClient(wrong, a.cert))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	stream, err := relayv1.NewRelayServiceClient(conn).Receive(testContext(t))
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil || !strings.Contains(err.Error(), ErrWrongRelay.Error()) {
		t.Fatalf("got %v, want %v", err, ErrWrongRelay)
	}
}

func TestSenderMustSendExactlyItsTotal(t *testing.T) {
	r := startRelay(t, Limits{}, nil)
	a, b := r.agent(t), r.agent(t)
	for name, total := range map[string]uint64{"too much": 3, "too little": 10} {
		t.Run(name, func(t *testing.T) {
			d := newDelivery()
			recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 0)
			sent := runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, total), []byte("12345"), 5)
			_, recvErr := receiveAll(recv, nil)
			wantCode(t, (<-sent).err, codes.InvalidArgument)
			wantCode(t, recvErr, codes.InvalidArgument)
		})
	}
}

func TestReceiverCantAcknowledgeBytesItWasNotSent(t *testing.T) {
	r := startRelay(t, Limits{}, nil)
	a, b := r.agent(t), r.agent(t)
	d := newDelivery()
	recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 0)
	send := openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, 6)
	if _, err := send.Recv(); err != nil {
		t.Fatal(err)
	}
	// Only half the file goes out, but the receiver claims all of it.
	if err := send.Send(&relayv1.SendRequest{Message: &relayv1.SendRequest_Data{Data: []byte("abc")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := recv.Recv(); err != nil {
		t.Fatal(err)
	}
	_ = recv.Send(&relayv1.ReceiveRequest{Message: &relayv1.ReceiveRequest_WrittenBytes{WrittenBytes: 6}})
	_, err := receiveAll(recv, nil)
	wantCode(t, err, codes.InvalidArgument)
	if _, _, err := sendAll(send, nil, 1); err == nil {
		t.Fatal("the sender was told the receiver had the file")
	}
}

func TestResumeOffsetPastTheEndIsRefused(t *testing.T) {
	r := startRelay(t, Limits{}, nil)
	a, b := r.agent(t), r.agent(t)
	d := newDelivery()
	recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 10)
	sent := runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, 5), []byte("12345"), 5)
	_, err := receiveAll(recv, nil)
	wantCode(t, err, codes.InvalidArgument)
	wantCode(t, (<-sent).err, codes.InvalidArgument)
}

func TestANewConnectionReplacesAStaleOne(t *testing.T) {
	r := startRelay(t, Limits{PairWait: 2 * time.Second}, nil)
	a, b := r.agent(t), r.agent(t)
	d := newDelivery()
	ticket := r.ticket(t, d, relayticket.Receive, b, a)
	stale := openReceive(t, r.client(t, b), ticket, d, 0)
	time.Sleep(50 * time.Millisecond)
	fresh := openReceive(t, r.client(t, b), ticket, d, 0)
	_, err := receiveAll(stale, nil)
	wantCode(t, err, codes.Aborted)
	sent := runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, 2), []byte("ok"), 1)
	if got, err := receiveAll(fresh, nil); err != nil || string(got) != "ok" {
		t.Fatalf("got %q, %v", got, err)
	}
	if res := <-sent; res.err != nil {
		t.Fatal(res.err)
	}
}

func TestLimits(t *testing.T) {
	t.Run("streams per agent", func(t *testing.T) {
		r := startRelay(t, Limits{MaxPerAgent: 1, PairWait: 2 * time.Second}, nil)
		a, b := r.agent(t), r.agent(t)
		d1, d2 := newDelivery(), newDelivery()
		_ = openReceive(t, r.client(t, b), r.ticket(t, d1, relayticket.Receive, b, a), d1, 0)
		time.Sleep(50 * time.Millisecond)
		_, err := receiveAll(openReceive(t, r.client(t, b), r.ticket(t, d2, relayticket.Receive, b, a), d2, 0), nil)
		wantCode(t, err, codes.ResourceExhausted)
	})
	t.Run("sides waiting", func(t *testing.T) {
		r := startRelay(t, Limits{MaxWaiting: 1, PairWait: 2 * time.Second}, nil)
		a, b, c := r.agent(t), r.agent(t), r.agent(t)
		d1, d2 := newDelivery(), newDelivery()
		_ = openReceive(t, r.client(t, b), r.ticket(t, d1, relayticket.Receive, b, a), d1, 0)
		time.Sleep(50 * time.Millisecond)
		_, err := receiveAll(openReceive(t, r.client(t, c), r.ticket(t, d2, relayticket.Receive, c, a), d2, 0), nil)
		wantCode(t, err, codes.ResourceExhausted)
	})
	t.Run("pairs forwarding", func(t *testing.T) {
		r := startRelay(t, Limits{MaxPairs: 1, PairWait: 2 * time.Second}, nil)
		a, b := r.agent(t), r.agent(t)
		d1, d2 := newDelivery(), newDelivery()
		recv1 := openReceive(t, r.client(t, b), r.ticket(t, d1, relayticket.Receive, b, a), d1, 0)
		send1 := openSend(t, r.client(t, a), r.ticket(t, d1, relayticket.Send, a, b), d1, 1)
		if _, err := send1.Recv(); err != nil {
			t.Fatal(err)
		}
		_ = openReceive(t, r.client(t, b), r.ticket(t, d2, relayticket.Receive, b, a), d2, 0)
		time.Sleep(50 * time.Millisecond)
		_, _, err := sendAll(openSend(t, r.client(t, a), r.ticket(t, d2, relayticket.Send, a, b), d2, 1), []byte("x"), 1)
		wantCode(t, err, codes.ResourceExhausted)
		_ = recv1
	})
	t.Run("a stalled pair", func(t *testing.T) {
		r := startRelay(t, Limits{Idle: 100 * time.Millisecond}, nil)
		a, b := r.agent(t), r.agent(t)
		d := newDelivery()
		recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 0)
		send := openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, 10)
		if _, err := send.Recv(); err != nil {
			t.Fatal(err)
		}
		_, err := receiveAll(recv, nil)
		wantCode(t, err, codes.DeadlineExceeded)
		if !strings.Contains(r.log.String(), `"event":"forwarding failed"`) {
			t.Fatalf("no failed event in log:\n%s", r.log.String())
		}
	})
	t.Run("a silent stream", func(t *testing.T) {
		r := startRelay(t, Limits{OpenWait: 100 * time.Millisecond}, nil)
		stream, err := r.client(t, r.agent(t)).Receive(testContext(t))
		if err != nil {
			t.Fatal(err)
		}
		_, err = stream.Recv()
		wantCode(t, err, codes.DeadlineExceeded)
	})
	t.Run("message size", func(t *testing.T) {
		r := startRelay(t, Limits{MaxChunk: 1024}, nil)
		a, b := r.agent(t), r.agent(t)
		d := newDelivery()
		recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 0)
		big := make([]byte, 1024+openOverhead+1)
		sent := runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, uint64(len(big))), big, len(big))
		wantCode(t, (<-sent).err, codes.ResourceExhausted)
		_, _ = receiveAll(recv, nil)
	})
}

func TestTheLogNamesNoFiles(t *testing.T) {
	r := startRelay(t, Limits{}, nil)
	a, b := r.agent(t), r.agent(t)
	d := newDelivery()
	recv := openReceive(t, r.client(t, b), r.ticket(t, d, relayticket.Receive, b, a), d, 0)
	sent := runSend(openSend(t, r.client(t, a), r.ticket(t, d, relayticket.Send, a, b), d, 4), []byte("data"), 4)
	if _, err := receiveAll(recv, nil); err != nil {
		t.Fatal(err)
	}
	<-sent
	for _, line := range strings.Split(strings.TrimSpace(r.log.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		for k := range m {
			if k != "time" && k != "event" && k != "delivery_id" && k != "code" && k != "error" {
				t.Errorf("unexpected log field %q", k)
			}
		}
		if m["delivery_id"] != d {
			t.Errorf("delivery_id = %v", m["delivery_id"])
		}
	}
}

func TestIdentityIsNotReplaced(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	if _, err := CreateIdentity(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateIdentity(dir, time.Now()); err == nil {
		t.Fatal("an existing identity was replaced")
	}
}
