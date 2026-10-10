package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func enrolledClient(t *testing.T) (*fakeServer, *Client) {
	t.Helper()
	f := newFakeServer(t)
	id, err := Enroll(context.Background(), t.TempDir(), f.token(t), facts)
	if err != nil {
		t.Fatal(err)
	}
	return f, NewClient(id)
}

func TestSessionIsReusedAndRecovers(t *testing.T) {
	f, cl := enrolledClient(t)
	for range 3 {
		if _, err := cl.Assignments(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.proto.handshakes != 1 {
		t.Fatalf("%d handshakes for three calls", f.proto.handshakes)
	}
	// The server forgets its sessions (a restart): one transparent handshake.
	f.proto.mu.Lock()
	f.proto.sessions = map[string]*fakeSession{}
	f.proto.mu.Unlock()
	if _, err := cl.Assignments(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.proto.handshakes != 2 {
		t.Fatalf("%d handshakes after a lost session", f.proto.handshakes)
	}
	// A renewal changes the certificate serial, so the next call re-handshakes.
	if err := cl.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Assignments(context.Background()); err != nil || f.proto.handshakes != 3 {
		t.Fatalf("after renew: %v, %d handshakes", err, f.proto.handshakes)
	}
}

// Anything the server's responder did not sign for this very request is refused.
func TestUnsignedResponsesAreRefused(t *testing.T) {
	_, cl := enrolledClient(t)
	if _, err := cl.Assignments(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*http.Response){
		"plain body": func(r *http.Response) {
			r.Header = http.Header{}
			r.Body = io.NopCloser(strings.NewReader(`{"revision":9}`))
		},
		"no sealing": func(r *http.Response) { r.Header.Del("Cf-Seq") },
		"other nonce": func(r *http.Response) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), "req-nonce=\"", "req-nonce=\"x", 1))
		},
	} {
		cl.st.base = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp, err := cl.tr.RoundTrip(req)
			if err == nil {
				mutate(resp)
			}
			return resp, err
		})
		if _, err := cl.Assignments(context.Background()); !errors.Is(err, ErrUnsigned) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
