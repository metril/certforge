//go:build integration

package api_test

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/authn"
)

// deadlineRecorder wraps the ResponseWriter so a test can see whether (and
// how far out) a handler pushed the request's read deadline.
type deadlineRecorder struct {
	http.ResponseWriter
	mu    *sync.Mutex
	calls *[]time.Duration
}

func (d deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	*d.calls = append(*d.calls, time.Until(t))
	d.mu.Unlock()
	return nil
}

func (d deadlineRecorder) Unwrap() http.ResponseWriter { return d.ResponseWriter }

// TestImportExtendsReadDeadline: only an authenticated, permitted,
// multipart import gets the long read deadline; an unauthenticated or a
// non-multipart request keeps the server's ReadTimeout, so neither can hold
// a connection open for minutes.
func TestImportExtendsReadDeadline(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()

	var mu sync.Mutex
	var calls []time.Duration
	rec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.NewRouter(e.deps).ServeHTTP(deadlineRecorder{ResponseWriter: w, mu: &mu, calls: &calls}, r)
	}))
	defer rec.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("caId", "00000000-0000-0000-0000-000000000000"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	path := rec.URL + "/api/v1/orgs/" + org.String() + "/certificates/import"
	extended := func() bool {
		mu.Lock()
		defer mu.Unlock()
		defer func() { calls = nil }()
		for _, d := range calls {
			if d > time.Minute {
				return true
			}
		}
		return false
	}
	post := func(c *http.Client, ct, body string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", ct)
		req.Header.Set(authn.CSRFHeader, csrf)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	post(e.client, mw.FormDataContentType(), buf.String())
	if !extended() {
		t.Error("authenticated multipart import: read deadline not extended")
	}
	post(&http.Client{}, mw.FormDataContentType(), buf.String())
	if extended() {
		t.Error("unauthenticated import: read deadline was extended")
	}
	post(e.client, "application/json", "{}")
	if extended() {
		t.Error("authenticated non-multipart import: read deadline was extended")
	}
}
