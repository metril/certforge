package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metril/certforge/internal/signer"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"120", 2 * time.Minute, true},
		{now.Add(time.Hour).Format(http.TimeFormat), time.Hour, true},
		{now.Add(-time.Hour).Format(http.TimeFormat), 0, true},
		{"", 0, false},
		{"soon", 0, false},
		{"-5", 0, false},
		{"999999999999", maxRetryAfter, true},
		{"9223372036854775807", maxRetryAfter, true},
		{"Wed, 21 Oct 2099 07:28:00 GMT", maxRetryAfter, true},
	}
	for _, c := range cases {
		got, ok := parseRetryAfter(c.in, now)
		if got != c.want || ok != c.ok {
			t.Errorf("parseRetryAfter(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestLegoKeyType(t *testing.T) {
	for _, k := range []signer.KeyType{signer.RSA2048, signer.RSA3072, signer.RSA4096, signer.EC256, signer.EC384} {
		if _, err := legoKeyType(k); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	if _, err := legoKeyType("dsa1024"); err == nil {
		t.Error("want error for unsupported key type")
	}
}

type nopSolver struct{}

func (nopSolver) Present(string, string, string) error    { return nil }
func (nopSolver) CleanUp(string, string, string) error    { return nil }
func (nopSolver) Timeout() (time.Duration, time.Duration) { return time.Second, time.Second }
func (nopSolver) PreCheck(string, string, string, func(string, string) (bool, error)) (bool, error) {
	return true, nil
}
func (nopSolver) ChallengeTypes() []string          { return []string{"dns-01"} }
func (nopSolver) TypeFor(string) (string, error)    { return "dns-01", nil }
func (nopSolver) For(string) signer.ChallengeSolver { return nopSolver{} }

// fakeRateLimitedCA serves just enough ACME for lego to reach newOrder, which
// answers 429 rateLimited with Retry-After.
func fakeRateLimitedCA(t *testing.T, retryAfter string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"revokeCert":%q,"keyChange":%q}`,
			base+"/nonce", base+"/acct", base+"/order", base+"/revoke", base+"/key")
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-1")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-2")
		w.Header().Set("Retry-After", retryAfter)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many new orders","status":429}`)
	})
	srv := httptest.NewTLSServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

// fakeBlockingCA serves just enough ACME for lego to reach newOrder, then
// blocks that request until its client-side context is done. It signals
// reached once the order request arrives, so the test can cancel precisely
// while a CA call is in flight.
func fakeBlockingCA(t *testing.T) (srv *httptest.Server, reached chan struct{}) {
	t.Helper()
	reached = make(chan struct{})
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"revokeCert":%q,"keyChange":%q}`,
			base+"/nonce", base+"/acct", base+"/order", base+"/revoke", base+"/key")
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-1")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		// Drain the request body before blocking: net/http's server only
		// watches for the client closing the connection (and cancels
		// r.Context() accordingly) once the request body has been read to
		// EOF. A real CA always reads the signed JWS body before acting on
		// it, so this matches real behaviour rather than working around it.
		_, _ = io.Copy(io.Discard, r.Body)
		close(reached)
		<-r.Context().Done()
	})
	srv = httptest.NewTLSServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv, reached
}

// fakeRenewalInfoCA serves a directory publishing renewalInfo and a
// renewalInfo endpoint that always answers the same suggested window;
// dirHits counts how many times the directory endpoint was actually hit,
// for TestRenewalInfoCachesDirectory (fix round 1).
func fakeRenewalInfoCA(t *testing.T) (srv *httptest.Server, dirHits *int32) {
	t.Helper()
	var hits int32
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"revokeCert":%q,"keyChange":%q,"renewalInfo":%q}`,
			base+"/nonce", base+"/acct", base+"/order", base+"/revoke", base+"/key", base+"/renewal-info")
	})
	mux.HandleFunc("/renewal-info/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"suggestedWindow":{"start":"2026-09-25T00:00:00Z","end":"2026-09-26T00:00:00Z"}}`)
	})
	srv = httptest.NewTLSServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestRenewalInfoCachesDirectory is fix round 1's review finding
// ("fetch each CA's directory once per run"): ARIPollWorker reuses one
// Signer per CA across many certificates in a poll run, so the directory
// must be fetched once per Signer instance, not once per RenewalInfo call.
func TestRenewalInfoCachesDirectory(t *testing.T) {
	srv, dirHits := fakeRenewalInfoCA(t)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	s := New(Config{DirectoryURL: srv.URL + "/dir", TrustBundlePEM: string(bundle)})

	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), AuthorityKeyId: []byte{1, 2, 3, 4}}
	for i := 0; i < 3; i++ {
		win, err := s.RenewalInfo(context.Background(), leaf)
		if err != nil {
			t.Fatal(err)
		}
		if win == nil {
			t.Fatal("nil window")
		}
	}
	if got := atomic.LoadInt32(dirHits); got != 1 {
		t.Fatalf("directory fetched %d times, want 1 (cached per Signer instance)", got)
	}
}

// TestRenewalInfoErrorExpires (fix round 2): a failed directory fetch is
// remembered only for riErrTTL (no re-fetch inside it), then retried; a
// success is cached for good.
func TestRenewalInfoErrorExpires(t *testing.T) {
	srv, dirHits := fakeRenewalInfoCA(t)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	s := New(Config{DirectoryURL: srv.URL + "/dir", TrustBundlePEM: string(bundle)})
	clock := time.Now()
	s.now = func() time.Time { return clock }
	s.riErr, s.riErrAt = errors.New("directory down"), clock

	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), AuthorityKeyId: []byte{1, 2, 3, 4}}
	if _, err := s.RenewalInfo(context.Background(), leaf); err == nil {
		t.Fatal("want the cached error inside the TTL")
	}
	if got := atomic.LoadInt32(dirHits); got != 0 {
		t.Fatalf("directory fetched %d times inside the error TTL, want 0", got)
	}
	clock = clock.Add(riErrTTL + time.Second)
	if _, err := s.RenewalInfo(context.Background(), leaf); err != nil {
		t.Fatalf("after the TTL the fetch must be retried: %v", err)
	}
	if _, err := s.RenewalInfo(context.Background(), leaf); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(dirHits); got != 1 {
		t.Fatalf("directory fetched %d times, want 1 (success cached)", got)
	}
}

func testAccount(t *testing.T) signer.AccountMaterial {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return signer.AccountMaterial{Email: "ops@example.test", KeyPKCS8: der, RegistrationURI: "https://ca.test/acct/1"}
}

func TestIssueRateLimitedKeepsRetryAfter(t *testing.T) {
	srv := fakeRateLimitedCA(t, "7200")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	s := New(Config{DirectoryURL: srv.URL + "/dir", TrustBundlePEM: string(bundle)})

	_, err := s.Issue(context.Background(), signer.IssueRequest{
		Names: []string{"a.example.test"}, KeyType: signer.EC256,
		Account: testAccount(t), Challenge: nopSolver{},
	})
	var se *signer.Error
	if !errors.As(err, &se) {
		t.Fatalf("want *signer.Error, got %T %v", err, err)
	}
	if se.ShortType() != "rateLimited" || se.Status != 429 {
		t.Fatalf("type=%q status=%d", se.Type, se.Status)
	}
	if se.RetryAfter != 2*time.Hour {
		t.Fatalf("RetryAfter = %v, want 2h", se.RetryAfter)
	}
}

func TestIssueRejectsBadTrustBundle(t *testing.T) {
	s := New(Config{DirectoryURL: "https://ca.test/dir", TrustBundlePEM: "not pem"})
	_, err := s.Issue(context.Background(), signer.IssueRequest{
		Names: []string{"a.example.test"}, KeyType: signer.EC256, Account: testAccount(t), Challenge: nopSolver{},
	})
	if err == nil {
		t.Fatal("want error")
	}
}

// TestIssueCancelledContextReturnsPromptly is the controller's cancellation
// ruling: once the issuance ctx is cancelled mid-request, the in-flight CA
// call must fail immediately with a ctx error, not hang until the CA
// responds or times out.
func TestIssueCancelledContextReturnsPromptly(t *testing.T) {
	srv, reached := fakeBlockingCA(t)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	s := New(Config{DirectoryURL: srv.URL + "/dir", TrustBundlePEM: string(bundle)})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := s.Issue(ctx, signer.IssueRequest{
			Names: []string{"a.example.test"}, KeyType: signer.EC256,
			Account: testAccount(t), Challenge: nopSolver{},
		})
		errCh <- err
	}()

	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("fake CA never received the order request")
	}
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("want error, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Issue did not return promptly after cancellation")
	}
}

func TestPresetByCode(t *testing.T) {
	p, ok := PresetByCode("zerossl")
	if !ok || !p.RequiresEAB || p.DirectoryURL == "" {
		t.Fatalf("zerossl preset = %+v", p)
	}
	if _, ok := PresetByCode("nope"); ok {
		t.Fatal("unknown preset found")
	}
}
