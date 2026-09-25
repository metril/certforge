package agenthub

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

type fakeSession struct {
	*agentproto.PipeConn
	peer     *agentproto.PipeConn
	failPing atomic.Bool
	mu       sync.Mutex
	code     int
	closed   chan struct{}
	once     sync.Once
}

func newFakeSession() *fakeSession {
	a, b := agentproto.Pipe()
	return &fakeSession{PipeConn: a, peer: b, closed: make(chan struct{})}
}

func (f *fakeSession) Ping(ctx context.Context) error {
	if f.failPing.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (f *fakeSession) Close(code int, _ string) error {
	f.once.Do(func() {
		f.mu.Lock()
		f.code = code
		f.mu.Unlock()
		close(f.closed)
		f.PipeConn.Close()
	})
	return nil
}

func (f *fakeSession) closeCode(t *testing.T) int {
	t.Helper()
	select {
	case <-f.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("session not closed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.code
}

func (f *fakeSession) recv(t *testing.T) agentproto.Message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := f.peer.ReadMsg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, err := agentproto.Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *fakeSession) send(t *testing.T, m agentproto.Message) {
	t.Helper()
	b, _ := agentproto.Marshal(m)
	if err := f.peer.WriteMsg(context.Background(), b); err != nil {
		t.Fatal(err)
	}
}

type helloHandler struct{ got chan agentproto.Message }

func (h helloHandler) OnMessage(_ context.Context, _ uuid.UUID, m agentproto.Message) ([]agentproto.Message, error) {
	h.got <- m
	if _, ok := m.(agentproto.Hello); ok {
		return []agentproto.Message{agentproto.HelloAck{HeartbeatSeconds: 60, Revision: 3}}, nil
	}
	return nil, nil
}

func serve(t *testing.T, h *Hub, id uuid.UUID, s *fakeSession) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- h.Serve(context.Background(), id, s, helloHandler{got: make(chan agentproto.Message, 8)})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		c := h.conns[id]
		h.mu.Unlock()
		if c != nil && c.s == Session(s) {
			return done
		}
		if time.Now().After(deadline) {
			t.Fatal("not registered")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestServeRepliesToHello(t *testing.T) {
	h, id, s := New(nil), uuid.New(), newFakeSession()
	serve(t, h, id, s)
	s.send(t, agentproto.Hello{AgentVersion: "1"})
	if m := s.recv(t); m != agentproto.Message(agentproto.HelloAck{HeartbeatSeconds: 60, Revision: 3}) {
		t.Fatalf("reply %#v", m)
	}
}

func TestSendAndDisconnect(t *testing.T) {
	h, id, s := New(nil), uuid.New(), newFakeSession()
	done := serve(t, h, id, s)
	if !h.Connected(id) || !h.Send(id, agentproto.Sync{Revision: 5}) || h.Send(uuid.New(), agentproto.Sync{}) {
		t.Fatal("send")
	}
	if m := s.recv(t); m != agentproto.Message(agentproto.Sync{Revision: 5}) {
		t.Fatalf("got %#v", m)
	}
	s.peer.Close()
	<-done
	if h.Connected(id) {
		t.Fatal("still connected after disconnect")
	}
}

func TestNewConnectionEvictsOld(t *testing.T) {
	h, id := New(nil), uuid.New()
	s1, s2 := newFakeSession(), newFakeSession()
	serve(t, h, id, s1)
	serve(t, h, id, s2)
	if code := s1.closeCode(t); code != agentproto.CloseReplaced {
		t.Fatalf("old closed with %d", code)
	}
	h.Send(id, agentproto.Sync{Revision: 1})
	if m := s2.recv(t); m != agentproto.Message(agentproto.Sync{Revision: 1}) {
		t.Fatalf("new got %#v", m)
	}
	if !h.Connected(id) {
		t.Fatal("new connection dropped with the old one")
	}
}

func TestCloseDeliversQueuedMessageFirst(t *testing.T) {
	h, id, s := New(nil), uuid.New(), newFakeSession()
	done := serve(t, h, id, s)
	h.Send(id, agentproto.Revoked{})
	h.Close(id, agentproto.CloseRevoked, "revoked")
	if m := s.recv(t); m != agentproto.Message(agentproto.Revoked{}) {
		t.Fatalf("got %#v", m)
	}
	if code := s.closeCode(t); code != agentproto.CloseRevoked {
		t.Fatalf("code %d", code)
	}
	<-done
}

func TestIdleTimeoutClosesHalfOpen(t *testing.T) {
	h, id, s := New(nil), uuid.New(), newFakeSession()
	h.PingInterval, h.IdleTimeout = 10*time.Millisecond, 50*time.Millisecond
	s.failPing.Store(true)
	serve(t, h, id, s)
	if code := s.closeCode(t); code != agentproto.CloseIdle {
		t.Fatalf("code %d", code)
	}
}

func TestBroadcastAndShutdown(t *testing.T) {
	h := New(nil)
	s1, s2 := newFakeSession(), newFakeSession()
	serve(t, h, uuid.New(), s1)
	serve(t, h, uuid.New(), s2)
	if n := h.Broadcast(agentproto.TrustBundleUpdate{Bundle: "pem"}); n != 2 {
		t.Fatalf("broadcast %d", n)
	}
	for _, s := range []*fakeSession{s1, s2} {
		if m := s.recv(t); m != agentproto.Message(agentproto.TrustBundleUpdate{Bundle: "pem"}) {
			t.Fatalf("got %#v", m)
		}
	}
	h.Shutdown()
	if s1.closeCode(t) != 1001 || s2.closeCode(t) != 1001 {
		t.Fatal("shutdown close codes")
	}
}
