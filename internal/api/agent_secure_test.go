package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMemNoncesRejectReplayUntilExpiry(t *testing.T) {
	n := newMemNonces()
	now := time.Now()
	if !n.Add("a", now) || n.Add("a", now.Add(time.Second)) {
		t.Fatal("a nonce must be accepted once")
	}
	if !n.Add("b", now) {
		t.Fatal("distinct nonce refused")
	}
	if !n.Add("a", now.Add(nonceTTL+time.Second)) {
		t.Fatal("an expired nonce is forgotten")
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
