package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
)

// fakeVault is a minimal httptest-backed stand-in for Vault's HTTP API. It
// routes by method+path, counts calls and records the last request's
// headers and decoded body, so tests can assert on both the client's retry
// behavior and the exact shape of what it sent. Every test in this package
// runs against one of these, never a real Vault (Contract: "all tests run
// against httptest fakes").
type fakeVault struct {
	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	calls    map[string]int
	headers  map[string]http.Header
	bodies   map[string][]byte
	srv      *httptest.Server
}

func newFakeVault() *fakeVault {
	f := &fakeVault{
		handlers: map[string]http.HandlerFunc{},
		calls:    map[string]int{},
		headers:  map[string]http.Header{},
		bodies:   map[string][]byte{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	return f
}

func (f *fakeVault) Close() { f.srv.Close() }

func (f *fakeVault) URL() string { return f.srv.URL }

func routeKey(method, path string) string { return method + " " + path }

// handle registers a fixed handler for method+path.
func (f *fakeVault) handle(method, path string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[routeKey(method, path)] = h
}

// fakeResponse is one scripted reply for handleSeq.
type fakeResponse struct {
	status int
	body   any
}

// handleSeq scripts a sequence of responses for method+path: call N of the
// route gets responses[N-1]; once the sequence is exhausted, the last entry
// repeats. Used to make the Nth attempt of a retry succeed or fail.
func (f *fakeVault) handleSeq(method, path string, responses ...fakeResponse) {
	f.handle(method, path, func(w http.ResponseWriter, r *http.Request) {
		n := f.CallCount(method, path) // serveHTTP already counted this call
		idx := n - 1
		if idx >= len(responses) {
			idx = len(responses) - 1
		}
		writeJSON(w, responses[idx].status, responses[idx].body)
	})
}

func (f *fakeVault) serveHTTP(w http.ResponseWriter, r *http.Request) {
	k := routeKey(r.Method, r.URL.Path)
	body, _ := readAndRestore(r)
	f.mu.Lock()
	f.calls[k]++
	f.headers[k] = r.Header.Clone()
	f.bodies[k] = body
	h, ok := f.handlers[k]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

func readAndRestore(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, nil //nolint:nilerr // an empty/non-JSON body is fine, tests just see nil
	}
	return raw, nil
}

// CallCount returns how many times method+path has been requested so far.
func (f *fakeVault) CallCount(method, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[routeKey(method, path)]
}

// LastHeader returns the named header from the most recent request to
// method+path.
func (f *fakeVault) LastHeader(method, path, header string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.headers[routeKey(method, path)].Get(header)
}

// LastBody decodes the most recent JSON request body sent to method+path.
func (f *fakeVault) LastBody(method, path string, out any) error {
	f.mu.Lock()
	raw := f.bodies[routeKey(method, path)]
	f.mu.Unlock()
	if raw == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}
