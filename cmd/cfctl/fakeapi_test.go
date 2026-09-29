package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// route is one fake-server handler, matched by exact method and path.
type route struct {
	method string
	path   string
	handle http.HandlerFunc
}

// newFakeAPI starts an httptest.Server that dispatches by exact "METHOD
// path" and fails the test if any request lacks the expected bearer
// token — every cfctl command test runs through this, so a command that
// ever dropped the Authorization header would fail its own test rather
// than silently talking to the server unauthenticated.
func newFakeAPI(t *testing.T, token string, routes ...route) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization header = %q, want %q (request %s %s)", got, "Bearer "+token, r.Method, r.URL.Path)
		}
		for _, rt := range routes {
			if rt.method == r.Method && rt.path == r.URL.Path {
				rt.handle(w, r)
				return
			}
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testEnv builds an *env wired to srv with the given token and org, for
// tests that call a command function directly rather than going through run.
func testEnv(t *testing.T, srv *httptest.Server, token, org string, jsonOut bool, stdout, stderr *bytes.Buffer) *env {
	t.Helper()
	cwr, raw, err := newClients(Config{URL: srv.URL, Token: token}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &env{cwr: cwr, raw: raw, json: jsonOut, org: org, stdout: stdout, stderr: stderr}
}

// writeJSON writes v as the JSON response body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(v)
}
