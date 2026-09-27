package agents

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/challenge"
)

// testHub is a minimal Hub for challenge.go's unit tests: Send optionally
// simulates the agent's own reply (onSend), so Present's wait can be
// satisfied without a real socket. connected is read and written under a
// lock since some tests flip it from a goroutine while Present's own
// fail-fast tick reads it concurrently.
type testHub struct {
	mu        sync.Mutex
	connected bool
	sent      []agentproto.Message
	onSend    func(agentproto.Message)
}

func (h *testHub) setConnected(v bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.connected = v
}

func (h *testHub) Send(_ uuid.UUID, m agentproto.Message) bool {
	h.mu.Lock()
	h.sent = append(h.sent, m)
	cb := h.onSend
	h.mu.Unlock()
	if cb != nil {
		cb(m)
	}
	return true
}

func (h *testHub) Close(uuid.UUID, int, string) {}

func (h *testHub) Connected(uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.connected
}

func (h *testHub) Broadcast(agentproto.Message) int { return 0 }

// messages returns a snapshot of what was sent so far.
func (h *testHub) messages() []agentproto.Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]agentproto.Message(nil), h.sent...)
}

// hasCleanup reports whether msgs contains a ChallengeCleanup for token.
func hasCleanup(msgs []agentproto.Message, token string) bool {
	for _, m := range msgs {
		if c, ok := m.(agentproto.ChallengeCleanup); ok && c.Token == token {
			return true
		}
	}
	return false
}

// TestRelayPresentReady: a fake hub answers ready, then answers with an
// error, for two separate Present calls sharing one Service (so the
// waiters registry is exercised across both). The error-reply case must
// also send challenge_cleanup: lego's http01.Challenge.Solve only calls
// CleanUp after a successful Present, so once challenge_present has
// actually reached the agent, every later failure path must ask it to
// stop on its own (fix round 1, Important finding).
func TestRelayPresentReady(t *testing.T) {
	clientID := uuid.New()
	hub := &testHub{connected: true}
	svc := &Service{Hub: hub}
	p := &agentChallengeProvider{svc: svc, clientID: clientID, name: "web-1", active: true, method: challenge.MethodHTTP01}

	hub.onSend = func(m agentproto.Message) {
		cp, ok := m.(agentproto.ChallengePresent)
		if !ok {
			return
		}
		go func() {
			_ = svc.ChallengeReady(context.Background(), clientID, agentproto.ChallengeReady{Token: cp.Token})
		}()
	}
	if err := p.Present(context.Background(), "example.test", "tok-1", "key-1"); err != nil {
		t.Fatalf("present (ready): %v", err)
	}
	if hasCleanup(hub.messages(), "tok-1") {
		t.Fatal("cleanup sent after a successful present (unnecessary; CleanUp handles it)")
	}

	hub.onSend = func(m agentproto.Message) {
		cp, ok := m.(agentproto.ChallengePresent)
		if !ok {
			return
		}
		go func() {
			_ = svc.ChallengeReady(context.Background(), clientID, agentproto.ChallengeReady{Token: cp.Token, Error: "listener refused"})
		}()
	}
	err := p.Present(context.Background(), "example.test", "tok-2", "key-2")
	if err == nil || !strings.Contains(err.Error(), "web-1: listener refused") {
		t.Fatalf("present (error reply) = %v", err)
	}
	if !hasCleanup(hub.messages(), "tok-2") {
		t.Fatal("no challenge_cleanup sent after an error reply")
	}
}

// TestRelayOfflineAndTimeout: a disconnected client is reported offline
// without waiting and without ever sending challenge_present; a connected
// one that never answers times out after Service.ChallengeReadyTimeout and
// still sends challenge_cleanup for the token it already sent
// challenge_present for.
func TestRelayOfflineAndTimeout(t *testing.T) {
	clientID := uuid.New()
	hub := &testHub{connected: false}
	svc := &Service{Hub: hub}
	p := &agentChallengeProvider{svc: svc, clientID: clientID, name: "web-2", active: true, method: challenge.MethodTLSALPN01}

	start := time.Now()
	err := p.Present(context.Background(), "example.test", "tok", "key")
	if err == nil || !strings.Contains(err.Error(), "web-2 is offline or cannot serve challenges") {
		t.Fatalf("offline present = %v", err)
	}
	if time.Since(start) > 20*time.Millisecond {
		t.Fatalf("offline present did not fail immediately: took %s", time.Since(start))
	}
	if len(hub.messages()) != 0 {
		t.Fatalf("offline present still sent %d message(s)", len(hub.messages()))
	}

	hub.setConnected(true)
	svc.ChallengeReadyTimeout = 50 * time.Millisecond
	start = time.Now()
	err = p.Present(context.Background(), "example.test", "tok", "key")
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "web-2 did not confirm the challenge within 50ms") {
		t.Fatalf("timeout present = %v", err)
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("timeout present returned early: took %s", elapsed)
	}
	if !hasCleanup(hub.messages(), "tok") {
		t.Fatal("no challenge_cleanup sent after a timeout")
	}
}

// TestRelayCleansUpOnContextCancel: a context canceled mid-wait (the
// issuance attempt was aborted) also gets a best-effort challenge_cleanup,
// the same as a timeout or an error reply.
func TestRelayCleansUpOnContextCancel(t *testing.T) {
	clientID := uuid.New()
	hub := &testHub{connected: true}
	svc := &Service{ChallengeReadyTimeout: 5 * time.Second, Hub: hub}
	p := &agentChallengeProvider{svc: svc, clientID: clientID, name: "web-3", active: true, method: challenge.MethodHTTP01}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := p.Present(ctx, "example.test", "tok", "key")
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("present (context canceled) = %v", err)
	}
	if !hasCleanup(hub.messages(), "tok") {
		t.Fatal("no challenge_cleanup sent after the context was canceled")
	}
}

// TestRelayFailsFastOnDisconnect (fix round 1, Minor finding): a socket
// that drops mid-wait is noticed well before the full
// ChallengeReadyTimeout, not only once that timeout elapses.
func TestRelayFailsFastOnDisconnect(t *testing.T) {
	clientID := uuid.New()
	hub := &testHub{connected: true}
	svc := &Service{ChallengeReadyTimeout: 5 * time.Second, Hub: hub}
	p := &agentChallengeProvider{svc: svc, clientID: clientID, name: "web-4", active: true, method: challenge.MethodHTTP01}

	go func() {
		time.Sleep(50 * time.Millisecond)
		hub.setConnected(false)
	}()
	start := time.Now()
	err := p.Present(context.Background(), "example.test", "tok", "key")
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "web-4 is offline or cannot serve challenges") {
		t.Fatalf("present (disconnect mid-wait) = %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("did not fail fast on disconnect: took %s (timeout was 5s)", elapsed)
	}
	if !hasCleanup(hub.messages(), "tok") {
		t.Fatal("no challenge_cleanup sent after failing fast on disconnect")
	}
}
