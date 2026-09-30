package targets_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/targets"
)

// TestFactoryForcesLoopbackFlag covers the final review fix: it must
// exercise the client f.New actually returns, not just compare httpx's own
// policy helpers side by side (which would pass even if HTTPFactory ignored
// AllowLoopback entirely, since neither helper is ever called through it).
// A real 127.0.0.1 httptest server stands in for a target's own endpoint:
// the dial is blocked when allow=false and succeeds when allow=true.
func TestFactoryForcesLoopbackFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	for _, allow := range []bool{true, false} {
		f := targets.HTTPFactory{AllowLoopback: allow}
		// The caller's own opts.AllowLoopback (the opposite of f's) must be
		// overridden by f's own value, not merely defaulted.
		c, err := f.New(httpx.Options{AllowLoopback: !allow})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if c == nil {
			t.Fatal("New returned a nil client")
		}
		_, doErr := c.Do(context.Background(), http.MethodGet, srv.URL, nil, nil)
		if allow && doErr != nil {
			t.Fatalf("allow=true: Do against a 127.0.0.1 server failed: %v", doErr)
		}
		if !allow && doErr == nil {
			t.Fatal("allow=false: Do reached a loopback server, want it blocked")
		}
	}
}
