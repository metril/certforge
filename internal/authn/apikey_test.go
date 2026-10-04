package authn

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAPIKeyToken(t *testing.T) {
	tok, prefix, hash, err := NewAPIKeyToken()
	if err != nil {
		t.Fatal(err)
	}
	p, secret, ok := ParseAPIKeyToken(tok)
	if !ok || p != prefix || !bytes.Equal(HashAPIKeySecret(secret), hash) || !strings.HasPrefix(tok, "cf_"+prefix+"_") {
		t.Fatalf("round trip: %q %q %v", tok, p, ok)
	}
	for _, bad := range []string{"", "cf_", "cf_abc_def", "xx_0123456789ab_" + secret, "cf_0123456789aB_" + secret, "cf_0123456789ab_short"} {
		if _, _, ok := ParseAPIKeyToken(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestTouchGuardThrottlesPerKey(t *testing.T) {
	g := &touchGuard{seen: map[uuid.UUID]time.Time{}}
	now := time.Unix(3_000_000, 0)
	a, b := uuid.New(), uuid.New()
	if !g.due(a, now) || g.due(a, now.Add(59*time.Second)) {
		t.Fatal("second touch within a minute must be skipped")
	}
	if !g.due(b, now.Add(time.Second)) {
		t.Fatal("another key is independent")
	}
	if !g.due(a, now.Add(61*time.Second)) {
		t.Fatal("touch after a minute must write again")
	}
}
