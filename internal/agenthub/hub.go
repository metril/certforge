// Package agenthub keeps this server's open agent WebSockets (single
// replica, ADR 0010): one per client, the newest connection wins, each is
// pinged every 25 s and closed after 75 s without a message or pong.
// Messages are hints; agents always reconcile to the latest revision.
package agenthub

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

// Session is one agent socket.
type Session interface {
	agentproto.Conn
	Ping(ctx context.Context) error
	Close(code int, reason string) error
}

// Handler processes agent messages and returns replies.
type Handler interface {
	OnMessage(ctx context.Context, clientID uuid.UUID, m agentproto.Message) ([]agentproto.Message, error)
}

// unauthorizer is implemented by an error a Handler returns to mean the
// client is no longer authorized to hold this socket (revoked, re-enrolled,
// or otherwise no longer active): Serve closes with CloseRevoked instead of
// just logging and continuing. agents.Error implements it without this
// package importing internal/agents.
type unauthorizer interface{ Unauthorized() bool }

func isUnauthorized(err error) bool {
	var u unauthorizer
	return errors.As(err, &u) && u.Unauthorized()
}

// Defaults.
const (
	DefaultPingInterval = 25 * time.Second
	DefaultIdleTimeout  = 75 * time.Second
	writeTimeout        = 10 * time.Second
	shutdownTimeout     = 2 * time.Second
	closeNormal         = 1000
	closeGoingAway      = 1001
)

// Hub is safe for concurrent use.
type Hub struct {
	PingInterval time.Duration
	IdleTimeout  time.Duration
	Log          *slog.Logger

	mu    sync.Mutex
	conns map[uuid.UUID]*conn
}

type conn struct {
	s          Session
	out        chan []byte
	done       chan struct{}
	writerDone chan struct{} // closed once the writer has flushed and called s.Close
	once       sync.Once
	code       int
	reason     string
}

// close asks the writer to flush queued messages and close the session.
func (c *conn) close(code int, reason string) {
	c.once.Do(func() {
		c.code, c.reason = code, reason
		close(c.done)
	})
}

// New returns an empty hub.
func New(log *slog.Logger) *Hub {
	if log == nil {
		log = slog.Default()
	}
	return &Hub{PingInterval: DefaultPingInterval, IdleTimeout: DefaultIdleTimeout, Log: log, conns: map[uuid.UUID]*conn{}}
}

// Serve registers s for clientID, evicting an older connection, and runs
// until the session ends. Replies from handler are queued to the agent.
//
// verify, when non-nil, is called once right after registration, before
// any message is processed: a revoke or re-enrolment that committed
// between the caller's own authentication check (for example requireAgent
// verifying the TLS client certificate) and this call registering the
// socket must not leave a connection open under a client id it no longer
// authorizes. A verify error closes the socket with CloseRevoked and Serve
// returns without reading anything.
func (h *Hub) Serve(ctx context.Context, clientID uuid.UUID, s Session, handler Handler, verify func(context.Context) error) error {
	c := &conn{s: s, out: make(chan []byte, 16), done: make(chan struct{}), writerDone: make(chan struct{})}
	h.mu.Lock()
	old := h.conns[clientID]
	h.conns[clientID] = c
	h.mu.Unlock()
	if old != nil {
		old.close(agentproto.CloseReplaced, "replaced by a newer connection")
	}
	ctx, cancel := context.WithCancel(ctx)
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	go func() {
		defer close(c.writerDone)
		h.writer(ctx, c)
	}()
	go h.keepalive(ctx, c, &last)
	defer func() {
		h.mu.Lock()
		if h.conns[clientID] == c {
			delete(h.conns, clientID)
		}
		h.mu.Unlock()
		c.close(closeNormal, "")
		<-c.writerDone
		cancel()
	}()
	if verify != nil {
		if err := verify(ctx); err != nil {
			h.Log.Warn("agent connection rejected on re-check after registering", "client", clientID, "err", err)
			c.close(agentproto.CloseRevoked, "revoked")
			return err
		}
	}
	for {
		b, err := s.ReadMsg(ctx)
		if err != nil {
			select {
			case <-c.done:
				return nil
			default:
			}
			return err
		}
		last.Store(time.Now().UnixNano())
		m, err := agentproto.Unmarshal(b)
		if err != nil {
			h.Log.Warn("agent sent an unreadable message", "client", clientID, "err", err)
			continue
		}
		hctx, hcancel := h.handlerContext(ctx)
		replies, err := handler.OnMessage(hctx, clientID, m)
		hcancel()
		if err != nil {
			if isUnauthorized(err) {
				h.Log.Warn("agent no longer authorized; closing", "client", clientID, "type", m.MsgType(), "err", err)
				c.close(agentproto.CloseRevoked, "revoked")
				return err
			}
			h.Log.Warn("agent message failed", "client", clientID, "type", m.MsgType(), "err", err)
			continue
		}
		for _, r := range replies {
			h.enqueue(c, r)
		}
	}
}

// handlerContext bounds one OnMessage call to half the idle timeout: the read
// loop cannot read pongs while a handler runs, so a handler that outlived the
// idle timeout would get a healthy connection closed as idle.
func (h *Hub) handlerContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if h.IdleTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, h.IdleTimeout/2)
}

func (h *Hub) write(ctx context.Context, c *conn, b []byte) error {
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return c.s.WriteMsg(wctx, b)
}

// writer flushes queued application messages to the session and is the
// only goroutine that closes it. keepalive writes ping frames to the same
// session concurrently from its own goroutine; coder/websocket serialises
// writes (including pings) on the wire itself, so this is safe.
func (h *Hub) writer(ctx context.Context, c *conn) {
	for {
		select {
		case b := <-c.out:
			if err := h.write(ctx, c, b); err != nil {
				c.close(closeNormal, "")
			}
		case <-c.done:
		drain:
			for {
				select {
				case b := <-c.out:
					if h.write(ctx, c, b) != nil {
						break drain
					}
				default:
					break drain
				}
			}
			_ = c.s.Close(c.code, c.reason)
			return
		}
	}
}

func (h *Hub) keepalive(ctx context.Context, c *conn, last *atomic.Int64) {
	t := time.NewTicker(h.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, h.PingInterval)
			if err := c.s.Ping(pctx); err == nil {
				last.Store(time.Now().UnixNano())
			}
			cancel()
			if time.Since(time.Unix(0, last.Load())) > h.IdleTimeout {
				c.close(agentproto.CloseIdle, "no message or pong within the idle timeout")
				return
			}
		}
	}
}

func (h *Hub) enqueue(c *conn, m agentproto.Message) bool {
	b, err := agentproto.Marshal(m)
	if err != nil {
		h.Log.Error("agent message not encodable", "type", m.MsgType(), "err", err)
		return false
	}
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.out <- b:
		return true
	default:
		h.Log.Warn("agent send queue full; message dropped", "type", m.MsgType())
		return false
	}
}

func (h *Hub) get(id uuid.UUID) *conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[id]
}

// Send queues m for the client's socket; false when it is not connected.
func (h *Hub) Send(clientID uuid.UUID, m agentproto.Message) bool {
	c := h.get(clientID)
	return c != nil && h.enqueue(c, m)
}

// Close flushes queued messages and closes the client's socket with code.
func (h *Hub) Close(clientID uuid.UUID, code int, reason string) {
	if c := h.get(clientID); c != nil {
		c.close(code, reason)
	}
}

// Connected reports whether the client has an open socket.
func (h *Hub) Connected(clientID uuid.UUID) bool { return h.get(clientID) != nil }

func (h *Hub) all() []*conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*conn, 0, len(h.conns))
	for _, c := range h.conns {
		out = append(out, c)
	}
	return out
}

// Broadcast queues m for every socket and returns how many took it.
func (h *Hub) Broadcast(m agentproto.Message) int {
	n := 0
	for _, c := range h.all() {
		if h.enqueue(c, m) {
			n++
		}
	}
	return n
}

// Shutdown closes every socket with 1001 (going away); agents reconnect.
// It waits, bounded by shutdownTimeout in total, for each writer to flush
// and actually send its close frame before returning.
func (h *Hub) Shutdown() {
	conns := h.all()
	for _, c := range conns {
		c.close(closeGoingAway, "server shutting down")
	}
	deadline := time.NewTimer(shutdownTimeout)
	defer deadline.Stop()
	for _, c := range conns {
		select {
		case <-c.writerDone:
		case <-deadline.C:
			return
		}
	}
}
