package relay

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	relayv1 "mmft.dev/mmft/gen/relay/v1"
	"mmft.dev/mmft/internal/relayticket"
)

// half is one side of a delivery.
type half struct {
	agent, peer string
	role        relayticket.Role
}

// pairing joins the two sides of one delivery. Data moves from the sender's
// stream to the receiver's one message at a time, so the relay never holds
// more than one message of a file.
type pairing struct {
	s        *Server
	delivery string

	// Set under Server.mu, and read only after paired is closed.
	sender, receiver *half
	total, offset    uint64
	paired           chan struct{}

	data      chan []byte
	ackSignal chan struct{}

	mu        sync.Mutex
	done      chan struct{}
	finished  bool
	err       error
	idle      *time.Timer
	forwarded uint64
	acked     uint64
}

func newPairing(s *Server, delivery string) *pairing {
	return &pairing{
		s:         s,
		delivery:  delivery,
		paired:    make(chan struct{}),
		data:      make(chan []byte),
		ackSignal: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
}

func (p *pairing) has(role relayticket.Role) bool {
	if role == relayticket.Send {
		return p.sender != nil
	}
	return p.receiver != nil
}

func (p *pairing) only() *half {
	if p.sender != nil {
		return p.sender
	}
	return p.receiver
}

func (p *pairing) isPaired() bool { return p.sender != nil && p.receiver != nil }

// end finishes the pairing: successfully with a nil error, or with err. Only
// the first call counts.
func (p *pairing) end(err error) {
	p.mu.Lock()
	if p.finished || p.err != nil {
		p.mu.Unlock()
		return
	}
	if err == nil {
		p.finished = true
	} else {
		p.err = err
	}
	// Log before either side is released, so the log is complete by the time
	// an agent sees its stream end.
	if p.idle != nil {
		p.idle.Stop()
		if err == nil {
			p.s.log("delivery forwarded", p.delivery, nil)
		} else {
			p.s.log("forwarding failed", p.delivery, err)
		}
	}
	close(p.done)
	p.mu.Unlock()
}

// result returns nil for a pair that forwarded the whole file, or why it ended.
func (p *pairing) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return nil
	}
	return p.err
}

// start begins forwarding once both sides are present. Server.mu is held.
func (p *pairing) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.acked = p.offset
	p.idle = time.AfterFunc(p.s.cfg.Limits.Idle, func() {
		p.end(status.Error(codes.DeadlineExceeded, "no data moved for too long"))
	})
	close(p.paired)
}

func (p *pairing) touch() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.idle != nil && !p.finished && p.err == nil {
		p.idle.Reset(p.s.cfg.Limits.Idle)
	}
}

// join adds one side of a delivery, pairing it with the other side if that is
// already waiting.
func (s *Server) join(t relayticket.Ticket, total, offset uint64) (*pairing, *half, error) {
	h := &half{agent: t.Holder, peer: t.Peer, role: t.Role}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perAgent[h.agent] >= s.cfg.Limits.MaxPerAgent {
		return nil, nil, status.Error(codes.ResourceExhausted, "the agent has too many relay streams open")
	}
	p := s.pairings[t.DeliveryID]
	if p != nil && p.has(t.Role) {
		// The agent named in the ticket is reconnecting, so the old stream is
		// stale. The other side reconnects too, and the delivery resumes.
		p.end(status.Error(codes.Aborted, "a newer connection replaced this one"))
		delete(s.pairings, t.DeliveryID)
		p = nil
	}
	waiting, pairs := 0, 0
	for _, q := range s.pairings {
		if q.isPaired() {
			pairs++
		} else {
			waiting++
		}
	}
	if p == nil {
		if waiting >= s.cfg.Limits.MaxWaiting {
			return nil, nil, status.Error(codes.ResourceExhausted, "the relay has too many streams waiting")
		}
		p = newPairing(s, t.DeliveryID)
		s.pairings[t.DeliveryID] = p
	} else {
		other := p.only()
		if other.agent != h.peer || other.peer != h.agent {
			return nil, nil, status.Error(codes.PermissionDenied, "the tickets name different agents")
		}
		if pairs >= s.cfg.Limits.MaxPairs {
			return nil, nil, status.Error(codes.ResourceExhausted, "the relay has too many pairs forwarding")
		}
	}
	if t.Role == relayticket.Send {
		p.sender, p.total = h, total
	} else {
		p.receiver, p.offset = h, offset
	}
	if p.isPaired() {
		p.start()
	}
	s.perAgent[h.agent]++
	return p, h, nil
}

// leave removes one side. A pair still forwarding ends, and the other side
// resumes once this one reconnects.
func (s *Server) leave(p *pairing, h *half) {
	p.end(status.Error(codes.Aborted, "the other side disconnected"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perAgent[h.agent]--; s.perAgent[h.agent] <= 0 {
		delete(s.perAgent, h.agent)
	}
	if s.pairings[p.delivery] == p {
		delete(s.pairings, p.delivery)
	}
}

// awaitPair waits for the other side.
func (s *Server) awaitPair(ctx context.Context, p *pairing) error {
	timer := time.NewTimer(s.cfg.Limits.PairWait)
	defer timer.Stop()
	select {
	case <-p.paired:
		return nil
	case <-p.done:
		return p.result()
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	case <-timer.C:
		p.end(status.Error(codes.DeadlineExceeded, "the other side did not connect"))
		return p.result()
	}
}

func (p *pairing) checkOffset() error {
	if p.offset > p.total {
		err := status.Error(codes.InvalidArgument, "the receiver has more bytes than the sender will send")
		p.end(err)
		return p.result()
	}
	return nil
}

// runSender tells the sender where to start, takes its data, and passes on
// the receiver's acknowledgements until the receiver has the whole file.
func (p *pairing) runSender(stream relayv1.RelayService_SendServer) error {
	if err := p.checkOffset(); err != nil {
		return err
	}
	if err := stream.Send(&relayv1.SendResponse{Message: &relayv1.SendResponse_StartOffset{StartOffset: p.offset}}); err != nil {
		p.end(err)
		return err
	}
	pumped := make(chan error, 1)
	go func() { pumped <- p.pump(stream) }()
	for {
		select {
		case err := <-pumped:
			if err != nil {
				p.end(err)
				return p.result()
			}
			pumped = nil
		case <-p.ackSignal:
			p.mu.Lock()
			acked := p.acked
			p.mu.Unlock()
			if err := stream.Send(ack(acked)); err != nil {
				p.end(err)
				return err
			}
		case <-p.done:
			if err := p.result(); err != nil {
				return err
			}
			return stream.Send(ack(p.total))
		}
	}
}

func ack(n uint64) *relayv1.SendResponse {
	return &relayv1.SendResponse{Message: &relayv1.SendResponse_AcknowledgedBytes{AcknowledgedBytes: n}}
}

// pump moves the sender's data to the receiver. The sender must send exactly
// the bytes from its start offset to the end, then close its side.
func (p *pairing) pump(stream relayv1.RelayService_SendServer) error {
	remaining := p.total - p.offset
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			if remaining != 0 {
				return status.Error(codes.InvalidArgument, "the sender stopped before the end of the file")
			}
			close(p.data)
			return nil
		}
		if err != nil {
			return status.Convert(err).Err()
		}
		chunk := req.GetData()
		if len(chunk) == 0 {
			return status.Error(codes.InvalidArgument, "expected data")
		}
		if uint64(len(chunk)) > remaining {
			return status.Error(codes.InvalidArgument, "the sender sent more than its total")
		}
		remaining -= uint64(len(chunk))
		select {
		case p.data <- chunk:
			p.touch()
		case <-p.done:
			return nil
		}
	}
}

// runReceiver sends the data on to the receiver and reads its
// acknowledgements, until it has acknowledged the whole file.
func (p *pairing) runReceiver(stream relayv1.RelayService_ReceiveServer) error {
	if err := p.checkOffset(); err != nil {
		return err
	}
	if p.offset == p.total {
		p.end(nil)
		return nil
	}
	acks := make(chan error, 1)
	go func() { acks <- p.readAcks(stream) }()
	data := p.data
	for {
		select {
		case chunk, ok := <-data:
			if !ok {
				data = nil
				continue
			}
			// Count the bytes before sending, so an acknowledgement can never
			// arrive for bytes not yet counted.
			p.mu.Lock()
			p.forwarded += uint64(len(chunk))
			p.mu.Unlock()
			if err := stream.Send(&relayv1.ReceiveResponse{Data: chunk}); err != nil {
				p.end(err)
				return err
			}
		case err := <-acks:
			if err != nil {
				p.end(err)
				return p.result()
			}
			acks = nil
		case <-p.done:
			return p.result()
		}
	}
}

// readAcks reads the receiver's acknowledgements. Each must cover no more than
// the receiver has been sent, and none may go backwards.
func (p *pairing) readAcks(stream relayv1.RelayService_ReceiveServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "the receiver stopped before acknowledging the whole file")
		}
		if err != nil {
			return status.Convert(err).Err()
		}
		written, ok := req.GetMessage().(*relayv1.ReceiveRequest_WrittenBytes)
		if !ok {
			return status.Error(codes.InvalidArgument, "expected an acknowledgement")
		}
		n := written.WrittenBytes
		p.mu.Lock()
		valid := n >= p.acked && n <= p.offset+p.forwarded
		if valid {
			p.acked = n
		}
		p.mu.Unlock()
		if !valid {
			return status.Error(codes.InvalidArgument, "the acknowledgement does not match the bytes sent")
		}
		p.touch()
		if n == p.total {
			p.end(nil)
			return nil
		}
		select {
		case p.ackSignal <- struct{}{}:
		default:
		}
	}
}
