package targets_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"

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

func TestFactoryWebSocket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		typ, b, err := c.Read(r.Context())
		if err != nil {
			return
		}
		_ = c.Write(r.Context(), typ, b)
	}))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	if o, err := (targets.HTTPFactory{}).WebSocket(httpx.Options{}); err != nil {
		t.Fatal(err)
	} else if c, resp, err := websocket.Dial(context.Background(), url, o); err == nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		_ = c.CloseNow()
		t.Fatal("loopback dial should be refused")
	}

	o, err := (targets.HTTPFactory{AllowLoopback: true}).WebSocket(httpx.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, resp, err := websocket.Dial(context.Background(), url, o)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	defer func() { _ = c.CloseNow() }()
	if err := c.Write(context.Background(), websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	_, b, err := c.Read(context.Background())
	if err != nil || string(b) != "hi" {
		t.Fatalf("got %q %v", b, err)
	}
}
