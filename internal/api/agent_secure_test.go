package api

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/config"

	"github.com/google/uuid"
)

func TestMemNoncesRejectReplayUntilExpiry(t *testing.T) {
	n := newMemNonces()
	now := time.Now()
	add := func(k string, at time.Time) bool {
		ok, err := n.Add(k, at)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !add("a", now) || add("a", now.Add(time.Second)) {
		t.Fatal("a nonce must be accepted once")
	}
	if !add("b", now) {
		t.Fatal("distinct nonce refused")
	}
	if !add("a", now.Add(nonceTTL+time.Second)) {
		t.Fatal("an expired nonce is forgotten")
	}
}

func TestMemNoncesCap(t *testing.T) {
	n := newMemNonces()
	n.max = 2
	now := time.Now()
	for _, k := range []string{"a", "b"} {
		if ok, err := n.Add(k, now); !ok || err != nil {
			t.Fatalf("%s: %v %v", k, ok, err)
		}
	}
	if _, err := n.Add("c", now); !errors.Is(err, errNonceFull) {
		t.Fatalf("full cache: %v", err)
	}
	if ok, err := n.Add("c", now.Add(nonceTTL+time.Second)); !ok || err != nil {
		t.Fatalf("expired entries must free space: %v %v", ok, err)
	}
}

func TestAgentSessionsExpireAndCapPerClient(t *testing.T) {
	var s agentSessions
	now := time.Now()
	c := uuid.New()
	s.put(&agentSession{id: "old", clientID: c, created: now}, now)
	if s.get("old", now.Add(sessionTTL-time.Second)) == nil {
		t.Fatal("live session lost")
	}
	if s.get("old", now.Add(sessionTTL)) != nil {
		t.Fatal("expired session served")
	}
	for i := range maxSessionsClient + 3 {
		s.put(&agentSession{id: string(rune('a' + i)), clientID: c, created: now.Add(time.Duration(i) * time.Second)}, now.Add(time.Duration(i)*time.Second))
	}
	if len(s.m) != maxSessionsClient {
		t.Fatalf("%d sessions kept for one client", len(s.m))
	}
	if s.get("a", now.Add(time.Minute)) != nil {
		t.Fatal("the oldest session should have been evicted first")
	}
}

// The authorities an agent may sign for survive an Agent URL change while the
// old host stays a listener name; an unlisted host is refused.
func TestAuthoritiesKeepListenerNames(t *testing.T) {
	st := agents.StaticSettings(agents.Settings{AgentURL: "https://new.example.com:8443", ListenerNames: []string{"Old.Example.com", "10.0.0.5"}}, "https://cf.example.com")
	a := &agentAPI{d: Deps{AgentSettings: st, Config: config.Config{BaseURL: "https://cf.example.com"}}, httpPort: true}
	got := a.authorities(context.Background())
	for _, want := range []string{"new.example.com:8443", "old.example.com", "old.example.com:8443", "10.0.0.5:8443", "cf.example.com"} {
		if !slices.Contains(got, want) {
			t.Errorf("authorities %v lack %q", got, want)
		}
	}
	if slices.Contains(got, "evil.example.com") {
		t.Errorf("unlisted host accepted: %v", got)
	}
	a.httpPort = false
	if slices.Contains(a.authorities(context.Background()), "cf.example.com") {
		t.Error("the base URL host is only valid on the HTTP port")
	}
}
