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
// satisfied without a real socket.
type testHub struct {
	mu        sync.Mutex
	connected bool
	sent      []agentproto.Message
	onSend    func(agentproto.Message)
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

func (h *testHub) Close(uuid.UUID, int, string)     {}
func (h *testHub) Connected(uuid.UUID) bool         { return h.connected }
func (h *testHub) Broadcast(agentproto.Message) int { return 0 }

// TestRelayPresentReady: a fake hub answers ready, then answers with an
// error, for two separate Present calls sharing one Service (so the
// waiters registry is exercised across both).
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
}

// TestRelayOfflineAndTimeout: a disconnected client is reported offline
// without waiting; a connected one that never answers times out after
// Service.ChallengeReadyTimeout.
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
	if len(hub.sent) != 0 {
		t.Fatalf("offline present still sent %d message(s)", len(hub.sent))
	}

	hub.connected = true
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
}
