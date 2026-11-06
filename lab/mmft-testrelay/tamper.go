package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	relayv1 "mmft.dev/mmft/gen/relay/v1"
	"mmft.dev/mmft/internal/relay"
)

// Tamper modes, read from the mode file before each delivery, for failure
// tests T1 to T3 in lab/README.md.
const (
	modePass     = "pass"     // forward the sealed file unchanged
	modeFlip     = "flip"     // T1: flip one byte in the middle
	modeTruncate = "truncate" // T2: send the first half, then end the stream
	modeSwap     = "swap"     // T3: send the previous delivery's sealed file instead
)

const (
	maxSealed = 16 << 20 // the lab's spools are 16 MB
	chunkSize = 256 << 10
	meetWait  = 2 * time.Minute
)

// tamperer plays a hostile relay. It speaks the relay protocol, but trusts no
// ticket, takes the sender's whole sealed file, tells the sender the receiver
// has it, and sends the receiver whatever the mode says. The agents' checks
// must catch every change.
type tamperer struct {
	relayv1.UnimplementedRelayServiceServer
	modeFile string

	mu    sync.Mutex
	meets map[string]*meet
	// last is the sealed file of the previous delivery, which swap replays.
	last []byte
}

// meet passes the receiver's offset to the sender, and the sender's file to
// the receiver.
type meet struct {
	offset chan uint64
	file   chan []byte
}

func (t *tamperer) meet(delivery string) *meet {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.meets[delivery]
	if m == nil {
		m = &meet{offset: make(chan uint64, 1), file: make(chan []byte, 1)}
		t.meets[delivery] = m
	}
	return m
}

func (t *tamperer) done(delivery string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.meets, delivery)
}

func (t *tamperer) mode() string {
	data, err := os.ReadFile(filepath.Clean(t.modeFile))
	if err != nil {
		return modePass
	}
	return strings.TrimSpace(string(data))
}

func wait[T any](ctx context.Context, c <-chan T) (T, error) {
	var zero T
	select {
	case v := <-c:
		return v, nil
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-time.After(meetWait):
		return zero, status.Error(codes.DeadlineExceeded, "the other side did not connect")
	}
}

func (t *tamperer) Send(stream relayv1.RelayService_SendServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	open := req.GetOpen()
	if open == nil || open.GetTotalBytes() > maxSealed {
		return status.Error(codes.InvalidArgument, "bad open")
	}
	m := t.meet(open.GetDeliveryId())
	offset, err := wait(stream.Context(), m.offset)
	if err != nil {
		return err
	}
	if err := stream.Send(&relayv1.SendResponse{Message: &relayv1.SendResponse_StartOffset{StartOffset: offset}}); err != nil {
		return err
	}
	var file []byte
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if file = append(file, req.GetData()...); len(file) > maxSealed {
			return status.Error(codes.InvalidArgument, "too much data")
		}
	}
	m.file <- file
	// Tell the sender the receiver has everything, whatever happens next.
	return stream.Send(&relayv1.SendResponse{Message: &relayv1.SendResponse_AcknowledgedBytes{AcknowledgedBytes: open.GetTotalBytes()}})
}

func (t *tamperer) Receive(stream relayv1.RelayService_ReceiveServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	open := req.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "bad open")
	}
	delivery := open.GetDeliveryId()
	defer t.done(delivery)
	m := t.meet(delivery)
	m.offset <- open.GetResumeOffset()
	file, err := wait(stream.Context(), m.file)
	if err != nil {
		return err
	}
	mode := t.mode()
	out := file
	t.mu.Lock()
	switch mode {
	case modeFlip:
		out = append([]byte(nil), file...)
		if len(out) > 0 {
			out[len(out)/2] ^= 0x01
		}
	case modeTruncate:
		out = file[:len(file)/2]
	case modeSwap:
		if t.last != nil {
			out = t.last
		}
	}
	t.last = file
	t.mu.Unlock()
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "tampered", "delivery_id": delivery, "mode": mode, "bytes": len(out)})

	for off := 0; off < len(out); off += chunkSize {
		end := min(off+chunkSize, len(out))
		if err := stream.Send(&relayv1.ReceiveResponse{Data: out[off:end]}); err != nil {
			return err
		}
	}
	if mode == modeTruncate {
		// End cleanly, as if the file were complete.
		return nil
	}
	// Wait for the receiver to acknowledge what it was sent.
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if req.GetWrittenBytes() >= uint64(len(out)) {
			return nil
		}
	}
}

// serveTamperer runs the hostile relay with the real relay's identity, so the
// agents' pin on the relay passes and only their file checks stand between
// them and the tampered bytes.
func serveTamperer(ctx context.Context) error {
	cfg, addr, err := relay.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cfg.ConnectionCA)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cfg.Identity},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})), grpc.MaxRecvMsgSize(2<<20))
	relayv1.RegisterRelayServiceServer(srv, &tamperer{
		modeFile: filepath.Join(os.Getenv("MMFT_RELAY_DIR"), "tamper-mode"),
		meets:    map[string]*meet{},
	})
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"event": "started", "address": lis.Addr().String(), "mode": "tamper"})
	go func() {
		<-ctx.Done()
		srv.Stop()
	}()
	return srv.Serve(lis)
}
