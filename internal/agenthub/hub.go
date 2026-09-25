// Package agenthub keeps this server's open agent WebSockets (single
// replica, ADR 0010): one per client, the newest connection wins, each is
// pinged every 25 s and closed after 75 s without a message or pong.
// Messages are hints; agents always reconcile to the latest revision.
package agenthub

import (
	"context"
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

// Defaults.
const (
	DefaultPingInterval = 25 * time.Second
	DefaultIdleTimeout  = 75 * time.Second
	writeTimeout        = 10 * time.Second
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
	s      Session
	out    chan []byte
	done   chan struct{}
	once   sync.Once
	code   int
	reason string
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
func (h *Hub) Serve(ctx context.Context, clientID uuid.UUID, s Session, handler Handler) error {
	c := &conn{s: s, out: make(chan []byte, 16), done: make(chan struct{})}
	h.mu.Lock()
	old := h.conns[clientID]
	h.conns[clientID] = c
	h.mu.Unlock()
	if old != nil {
		old.close(agentproto.CloseReplaced, "replaced by a newer connection")
	}
	ctx, cancel := context.WithCancel(ctx)
	writerDone := make(chan struct{})
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	go func() {
		defer close(writerDone)
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
		<-writerDone
		cancel()
	}()
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
		replies, err := handler.OnMessage(ctx, clientID, m)
		if err != nil {
			h.Log.Warn("agent message failed", "client", clientID, "type", m.MsgType(), "err", err)
		}
		for _, r := range replies {
			h.enqueue(c, r)
		}
	}
}

func (h *Hub) write(ctx context.Context, c *conn, b []byte) error {
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return c.s.WriteMsg(wctx, b)
}

// writer is the only goroutine that writes to or closes the session.
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
func (h *Hub) Shutdown() {
	for _, c := range h.all() {
		c.close(closeGoingAway, "server shutting down")
	}
}
