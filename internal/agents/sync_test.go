package agents

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMarkSeen(t *testing.T) {
	s := &Service{}
	a, b := uuid.New(), uuid.New()
	t0 := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if !s.markSeen(a, t0) || s.markSeen(a, t0.Add(touchEvery-time.Second)) || !s.markSeen(a, t0.Add(touchEvery)) {
		t.Fatal("first sighting, then one within touchEvery, then one at touchEvery")
	}
	s.markSeen(b, t0.Add(2*touchEvery))
	// One seenTTL after a's last sighting a prune runs: a is idle, b is not.
	s.markSeen(b, t0.Add(touchEvery+seenTTL))
	if _, ok := s.seen[a]; ok {
		t.Fatal("idle client not pruned")
	}
	if _, ok := s.seen[b]; !ok {
		t.Fatal("active client pruned")
	}
}
