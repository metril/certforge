package challenge

import (
	"context"
	"testing"
	"time"
)

// TestHTTPTokensTTL: Get works before the TTL elapses and fails after it;
// Delete removes a token outright.
func TestHTTPTokensTTL(t *testing.T) {
	clock := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	tok := NewHTTPTokens(10 * time.Minute)
	tok.Now = func() time.Time { return clock }

	tok.Put("abc", "keyauth-1")
	if got, ok := tok.Get("abc"); !ok || got != "keyauth-1" {
		t.Fatalf("Get before TTL = %q, %v", got, ok)
	}

	clock = clock.Add(9*time.Minute + 59*time.Second)
	if _, ok := tok.Get("abc"); !ok {
		t.Fatal("Get just before TTL should still succeed")
	}

	clock = clock.Add(2 * time.Second)
	if _, ok := tok.Get("abc"); ok {
		t.Fatal("Get after TTL should fail")
	}

	tok.Put("xyz", "keyauth-2")
	tok.Delete("xyz")
	if _, ok := tok.Get("xyz"); ok {
		t.Fatal("Get after Delete should fail")
	}

	if _, ok := tok.Get("never-put"); ok {
		t.Fatal("Get of an unknown token should fail")
	}
}

// TestHTTPTokensPutPurgesExpired (fix round 1, Minor finding): an expired
// token is not just unreadable via Get (already covered by TestHTTPTokensTTL)
// but actually evicted from the store on a later Put, so a long-running
// server does not accumulate one map entry per token forever.
func TestHTTPTokensPutPurgesExpired(t *testing.T) {
	clock := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	tok := NewHTTPTokens(time.Minute)
	tok.Now = func() time.Time { return clock }

	tok.Put("a", "ka-a")
	tok.Put("b", "ka-b")
	if got := len(tok.tokens); got != 2 {
		t.Fatalf("len(tokens) = %d, want 2", got)
	}

	clock = clock.Add(2 * time.Minute) // both a and b are now expired
	tok.Put("c", "ka-c")
	if got := len(tok.tokens); got != 1 {
		t.Fatalf("len(tokens) after Put past the TTL = %d, want 1 (only c; a and b purged)", got)
	}
	if _, ok := tok.tokens["c"]; !ok {
		t.Fatal("c itself must still be there")
	}
}

// TestServerHTTP01PresentCleanUp: Present stores the token/keyAuth pair so
// it is servable, and Type reports http-01; CleanUp removes it.
func TestServerHTTP01PresentCleanUp(t *testing.T) {
	tok := NewHTTPTokens(time.Minute)
	p := NewServerHTTP01(tok)
	if p.Type() != HTTP01 {
		t.Fatalf("Type() = %v", p.Type())
	}
	if err := p.Present(context.Background(), "example.com", "tok1", "keyauth-1"); err != nil {
		t.Fatal(err)
	}
	if got, ok := tok.Get("tok1"); !ok || got != "keyauth-1" {
		t.Fatalf("Get after Present = %q, %v", got, ok)
	}
	if err := p.CleanUp(context.Background(), "example.com", "tok1", "keyauth-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := tok.Get("tok1"); ok {
		t.Fatal("token should be gone after CleanUp")
	}
}
