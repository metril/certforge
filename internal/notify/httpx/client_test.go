package httpx_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metril/certforge/internal/notify/httpx"
)

func newClient(t *testing.T) *httpx.Client {
	t.Helper()
	c, err := httpx.New(httpx.Options{AllowLoopback: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNoRedirectFollow(t *testing.T) {
	var hits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	c := newClient(t)
	status, err := c.Do(context.Background(), http.MethodGet, srv.URL, nil, nil)
	if err == nil {
		t.Fatalf("Do returned nil error for a 3xx response (status %d)", status)
	}
	if status != http.StatusFound {
		t.Errorf("status = %d, want %d", status, http.StatusFound)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("redirect target was hit %d times, want 0 (no redirect following)", hits)
	}
}

// TestNoConnectionReuse: clients are built per send, so an idle keep-alive
// connection would only linger; every request must use its own connection.
func TestNoConnectionReuse(t *testing.T) {
	var conns int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&conns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := newClient(t)
	for i := 0; i < 2; i++ {
		if _, err := c.Do(context.Background(), http.MethodGet, srv.URL, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := atomic.LoadInt32(&conns); n != 2 {
		t.Errorf("connections = %d, want 2 (no keep-alive reuse)", n)
	}
}

func TestRetryOn5xxNot4xx(t *testing.T) {
	t.Run("5xx retries up to Attempts", func(t *testing.T) {
		var n int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&n, 1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		c := newClient(t)
		if _, err := c.Do(context.Background(), http.MethodPost, srv.URL, nil, nil); err == nil {
			t.Fatal("Do returned nil error for a persistent 500")
		}
		if got := atomic.LoadInt32(&n); got != httpx.Attempts {
			t.Errorf("server hit %d times, want %d", got, httpx.Attempts)
		}
	})

	t.Run("4xx does not retry", func(t *testing.T) {
		var n int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&n, 1)
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer srv.Close()

		c := newClient(t)
		if _, err := c.Do(context.Background(), http.MethodPost, srv.URL, nil, nil); err == nil {
			t.Fatal("Do returned nil error for a 400")
		}
		if got := atomic.LoadInt32(&n); got != 1 {
			t.Errorf("server hit %d times, want 1 (no retry on 4xx)", got)
		}
	})

	t.Run("success needs no retry", func(t *testing.T) {
		var n int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&n, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		c := newClient(t)
		status, err := c.Do(context.Background(), http.MethodGet, srv.URL, nil, nil)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
		if got := atomic.LoadInt32(&n); got != 1 {
			t.Errorf("server hit %d times, want 1", got)
		}
	})
}

func TestBodyCapped(t *testing.T) {
	huge := strings.Repeat("x", httpx.MaxBody*2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(huge))
	}))
	defer srv.Close()

	c := newClient(t)
	_, err := c.Do(context.Background(), http.MethodGet, srv.URL, nil, nil)
	if err == nil {
		t.Fatal("Do returned nil error for a 400")
	}
	// The error text embeds only the scrubbed first 200 bytes of the body,
	// however large the body itself was, and Do never buffers more than
	// MaxBody bytes of it.
	if len(err.Error()) > 300 {
		t.Errorf("error text is %d bytes, want it bounded to the scrub limit: %q", len(err.Error()), err.Error())
	}
}

// TestDialControlRejectsResolvedLoopback is a narrow unit test of
// DialControl itself, called directly with an already-resolved address
// (as net.Dialer would call it after DNS lookup). The end-to-end version —
// a hostname that actually resolves to a blocked address through a stub
// DNS server — is TestDialRejectsLoopbackAfterResolve, in
// client_internal_test.go (batch-1 review finding 6).
func TestDialControlRejectsResolvedLoopback(t *testing.T) {
	control := httpx.DialControl(false)
	if err := control("tcp4", "127.0.0.1:80", nil); err == nil {
		t.Fatal("DialControl(false) admitted a resolved loopback address")
	}
	if err := control("tcp4", "93.184.216.34:80", nil); err != nil {
		t.Errorf("DialControl(false) rejected a public resolved address: %v", err)
	}
}

func TestConnectionErrorReturnsError(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), http.MethodGet, "http://127.0.0.1:1/", nil, nil)
	if err == nil {
		t.Fatal("Do to an unreachable port returned nil error")
	}
}

// TestConnectionErrorOmitsPathAndQuery is batch-1 review finding 1's httpx
// half: a webhook/ntfy/Home Assistant URL's path or query string can carry
// a secret (a signed path, a token query param), so a transport-level
// failure's error text must name only the host, never the path or query —
// even though the underlying *url.Error Go's own http.Client returns
// embeds the full URL.
func TestConnectionErrorOmitsPathAndQuery(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), http.MethodGet, "http://127.0.0.1:1/webhook/secret-path?token=super-secret-token", nil, nil)
	if err == nil {
		t.Fatal("Do to an unreachable port returned nil error")
	}
	msg := err.Error()
	if strings.Contains(msg, "secret-path") {
		t.Errorf("error leaked the URL path: %q", msg)
	}
	if strings.Contains(msg, "super-secret-token") {
		t.Errorf("error leaked the query string: %q", msg)
	}
	if !strings.Contains(msg, "127.0.0.1:1") {
		t.Errorf("error dropped the host entirely: %q", msg)
	}
}

func TestCheckURLRejectedBeforeAnyRequest(t *testing.T) {
	c, err := httpx.New(httpx.Options{AllowLoopback: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Do(context.Background(), http.MethodGet, "http://127.0.0.1/", nil, nil); err == nil {
		t.Fatal("Do reached a blocked host")
	}
}
