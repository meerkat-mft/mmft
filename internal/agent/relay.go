package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "mmft.dev/mmft/gen/agent/v1"
	relayv1 "mmft.dev/mmft/gen/relay/v1"
	"mmft.dev/mmft/internal/relay"
)

// chunkSize is the size of each data message to the relay, well under the
// relay's 1 MiB limit.
const chunkSize = 256 << 10

// Errors from sending and receiving through the relay.
var (
	ErrBadRelay = errors.New("agent: the relay broke the relay protocol")
	// ErrSpoolTooLong means the partial file in the spool is longer than the
	// sealed file, so it can't be resumed.
	ErrSpoolTooLong = errors.New("agent: the spool file is longer than the sealed file")
)

// RelayConfig sets how sending or receiving through the relay retries. Zero values
// get the same defaults as RunConfig.
type RelayConfig struct {
	MinBackoff, MaxBackoff time.Duration
	Now                    func() time.Time
}

func (c *RelayConfig) defaults() {
	if c.MinBackoff == 0 {
		c.MinBackoff = defaultMinBackoff
	}
	if c.MaxBackoff == 0 {
		c.MaxBackoff = defaultMaxBackoff
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// relaySide is one side of a delivery through the relay.
type relaySide struct {
	dir    string
	ticket *agentv1.RelayTicket
	cfg    RelayConfig
	s      State
	keys   *Keys
	// wrongRelay records that a relay failed the pin. gRPC reports a failed
	// handshake only as unavailable, so the reason is kept here.
	wrongRelay atomic.Bool
}

func newRelaySide(dir string, t *agentv1.RelayTicket, cfg RelayConfig) (*relaySide, error) {
	cfg.defaults()
	s, err := ReadState(dir)
	if err != nil {
		return nil, err
	}
	keys, err := LoadKeys(dir)
	if err != nil {
		return nil, err
	}
	return &relaySide{dir: dir, ticket: t, cfg: cfg, s: s, keys: keys}, nil
}

// client connects to the relay with the current connection certificate, which
// `mmft-agent run` may have renewed since the last attempt.
func (t *relaySide) client() (relayv1.RelayServiceClient, func(), error) {
	cert, err := loadCertificate(t.dir, t.s, t.keys, t.cfg.Now())
	if err != nil {
		return nil, nil, err
	}
	tlsConfig := relay.PinnedClient(t.ticket.GetRelayCertificateSha256(), tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  t.keys.Connection,
	})
	verify := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		err := verify(cs)
		if errors.Is(err, relay.ErrWrongRelay) {
			t.wrongRelay.Store(true)
		}
		return err
	}
	conn, err := grpc.NewClient(t.ticket.GetRelayAddress(), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, nil, err
	}
	return relayv1.NewRelayServiceClient(conn), func() { _ = conn.Close() }, nil
}

// retry runs attempt until it succeeds, fails for good, or ctx ends. An
// attempt reports whether it made progress, which resets the backoff.
func (t *relaySide) retry(ctx context.Context, attempt func(context.Context, relayv1.RelayServiceClient) (bool, error)) error {
	backoff := t.cfg.MinBackoff
	for {
		client, closeConn, err := t.client()
		if err != nil {
			return err
		}
		progressed, err := attempt(ctx, client)
		closeConn()
		if err == nil {
			return nil
		}
		// Another relay won't become the right one by trying again.
		if t.wrongRelay.Load() {
			return relay.ErrWrongRelay
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w (last error: %w)", ctx.Err(), err)
		}
		if final(err) {
			return err
		}
		if progressed {
			backoff = t.cfg.MinBackoff
		}
		wait := backoff/2 + mrand.N(backoff/2+1) //nolint:gosec // jitter, not a secret
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last error: %w)", ctx.Err(), err)
		case <-time.After(wait):
		}
		backoff = min(2*backoff, t.cfg.MaxBackoff)
	}
}

// final reports whether retrying with the same ticket can't help.
func final(err error) bool {
	if errors.Is(err, ErrBadRelay) || errors.Is(err, ErrSpoolTooLong) {
		return true
	}
	switch status.Code(err) {
	case codes.PermissionDenied, codes.InvalidArgument, codes.Unauthenticated:
		return true
	}
	return false
}

// SendFile sends a sealed file through the relay named in the ticket. It
// reconnects after an interruption and resumes where the receiver's spool
// ends, until the receiver confirms the whole file or ctx ends.
func SendFile(ctx context.Context, dir string, ticket *agentv1.RelayTicket, path string, cfg RelayConfig) error {
	t, err := newRelaySide(dir, ticket, cfg)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	total := uint64(info.Size()) //nolint:gosec // a file size is never negative
	return t.retry(ctx, func(ctx context.Context, client relayv1.RelayServiceClient) (bool, error) {
		return t.send(ctx, client, f, total)
	})
}

func (t *relaySide) send(ctx context.Context, client relayv1.RelayServiceClient, f *os.File, total uint64) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.Send(ctx)
	if err != nil {
		return false, err
	}
	open := &relayv1.SendOpen{Ticket: t.ticket.GetTicket(), DeliveryId: t.ticket.GetDeliveryId(), TotalBytes: total}
	if err := stream.Send(&relayv1.SendRequest{Message: &relayv1.SendRequest_Open{Open: open}}); err != nil {
		return false, streamEnd(stream.Recv, err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return false, err
	}
	start, ok := resp.GetMessage().(*relayv1.SendResponse_StartOffset)
	if !ok || start.StartOffset > total {
		return false, fmt.Errorf("%w: no valid start offset", ErrBadRelay)
	}

	// The relay's acknowledgements arrive while the data goes out. The stream
	// ends cleanly only once the receiver has the whole file.
	acked := make(chan error, 1)
	var last uint64
	go func() {
		for {
			resp, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				if last != total {
					err = fmt.Errorf("%w: the stream ended before the receiver had the whole file", ErrBadRelay)
				} else {
					err = nil
				}
				acked <- err
				return
			}
			if err != nil {
				acked <- err
				return
			}
			n, ok := resp.GetMessage().(*relayv1.SendResponse_AcknowledgedBytes)
			if !ok || n.AcknowledgedBytes < last || n.AcknowledgedBytes > total {
				acked <- fmt.Errorf("%w: invalid acknowledgement", ErrBadRelay)
				return
			}
			last = n.AcknowledgedBytes
		}
	}()

	sent := start.StartOffset
	buf := make([]byte, chunkSize)
	for sent < total {
		n, err := f.ReadAt(buf[:min(uint64(len(buf)), total-sent)], int64(sent)) //nolint:gosec // sent is below the file size
		if n == 0 {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return false, err
		}
		if err := stream.Send(&relayv1.SendRequest{Message: &relayv1.SendRequest_Data{Data: buf[:n]}}); err != nil {
			// A failed send reports only io.EOF. The reader gets the reason.
			if errors.Is(err, io.EOF) {
				return sent > start.StartOffset, <-acked
			}
			return sent > start.StartOffset, err
		}
		sent += uint64(n) //nolint:gosec // n is at most chunkSize
	}
	if err := stream.CloseSend(); err != nil {
		return true, err
	}
	return sent > start.StartOffset, <-acked
}

// streamEnd returns the real reason a first send failed. A failed send
// reports only io.EOF, and the status comes from the next receive.
func streamEnd[T any](recv func() (T, error), err error) error {
	if errors.Is(err, io.EOF) {
		if _, rerr := recv(); rerr != nil {
			return rerr
		}
	}
	return err
}

// ReceiveFile receives a sealed file of size bytes through the relay named in
// the ticket into path, which must be in the agent's private spool. The size
// comes from the signed manifest, so the relay can't make the agent take more.
// A partial file already at path is kept, and the delivery resumes where it
// ends. Each acknowledgement covers only bytes synced to disk. It returns once
// size bytes are in path, or ctx ends. Checking the file against its signed
// manifest is the caller's job.
func ReceiveFile(ctx context.Context, dir string, ticket *agentv1.RelayTicket, path string, size uint64, cfg RelayConfig) error {
	t, err := newRelaySide(dir, ticket, cfg)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return t.retry(ctx, func(ctx context.Context, client relayv1.RelayServiceClient) (bool, error) {
		return t.receive(ctx, client, f, size)
	})
}

func (t *relaySide) receive(ctx context.Context, client relayv1.RelayServiceClient, f *os.File, size uint64) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	offset := uint64(info.Size()) //nolint:gosec // a file size is never negative
	if offset > size {
		return false, ErrSpoolTooLong
	}
	start := offset
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.Receive(ctx)
	if err != nil {
		return false, err
	}
	open := &relayv1.ReceiveOpen{Ticket: t.ticket.GetTicket(), DeliveryId: t.ticket.GetDeliveryId(), ResumeOffset: offset}
	if err := stream.Send(&relayv1.ReceiveRequest{Message: &relayv1.ReceiveRequest_Open{Open: open}}); err != nil {
		return false, streamEnd(stream.Recv, err)
	}
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			// The relay ends the stream cleanly only after the whole file is
			// acknowledged.
			if offset != size {
				return offset > start, fmt.Errorf("%w: the stream ended before the whole file arrived", ErrBadRelay)
			}
			return offset > start, nil
		}
		if err != nil {
			return offset > start, err
		}
		chunk := resp.GetData()
		if len(chunk) == 0 {
			return offset > start, fmt.Errorf("%w: empty data", ErrBadRelay)
		}
		if uint64(len(chunk)) > size-offset {
			return offset > start, fmt.Errorf("%w: more data than the file holds", ErrBadRelay)
		}
		if _, err := f.WriteAt(chunk, int64(offset)); err != nil { //nolint:gosec // offset is the file size
			return offset > start, err
		}
		if err := f.Sync(); err != nil {
			return offset > start, err
		}
		offset += uint64(len(chunk))
		ack := &relayv1.ReceiveRequest{Message: &relayv1.ReceiveRequest_WrittenBytes{WrittenBytes: offset}}
		if err := stream.Send(ack); err != nil && !errors.Is(err, io.EOF) {
			return true, err
		}
	}
}
