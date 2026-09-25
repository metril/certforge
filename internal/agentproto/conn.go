// Package agentproto is the wire protocol between the CertForge server and
// certforge-agent: WebSocket message types, the REST bodies of /agent/v1/*,
// the enrolment token format, and a transport-independent framing
// interface. Authentication is mutual TLS on the agent listener (ADR 0009);
// this package adds no cryptography of its own.
package agentproto

import (
	"context"
	"errors"
	"sync"
)

// Conn carries whole messages: one ReadMsg or WriteMsg is one WebSocket
// text message. Implementations: WS (coder/websocket) and PipeConn (tests).
type Conn interface {
	ReadMsg(ctx context.Context) ([]byte, error)
	WriteMsg(ctx context.Context, b []byte) error
}

// ErrClosed is returned by a closed PipeConn.
var ErrClosed = errors.New("agentproto: connection closed")

// PipeConn is one end of an in-memory Conn pair.
type PipeConn struct {
	in     <-chan []byte
	out    chan<- []byte
	closed chan struct{}
	once   *sync.Once
}

// Pipe returns two connected ends; closing either closes both.
func Pipe() (*PipeConn, *PipeConn) {
	ab, ba := make(chan []byte, 64), make(chan []byte, 64)
	closed, once := make(chan struct{}), &sync.Once{}
	return &PipeConn{in: ba, out: ab, closed: closed, once: once},
		&PipeConn{in: ab, out: ba, closed: closed, once: once}
}

// ReadMsg returns the next message, ErrClosed, or ctx's error. Messages
// queued before Close are still delivered.
func (p *PipeConn) ReadMsg(ctx context.Context) ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	default:
	}
	select {
	case b := <-p.in:
		return b, nil
	case <-p.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WriteMsg queues a copy of b for the other end.
func (p *PipeConn) WriteMsg(ctx context.Context, b []byte) error {
	select {
	case <-p.closed:
		return ErrClosed
	default:
	}
	c := append([]byte(nil), b...)
	select {
	case p.out <- c:
		return nil
	case <-p.closed:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close closes both ends.
func (p *PipeConn) Close() { p.once.Do(func() { close(p.closed) }) }
