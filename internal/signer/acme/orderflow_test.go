package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certificate"

	"github.com/metril/certforge/internal/signer"
)

// fakeTypeSolver is a minimal signer.ChallengeSolver for TestPickChallenge:
// TypeFor answers from a fixed domain->type map, as Router.For(t).TypeFor
// would for the rule covering that domain.
type fakeTypeSolver struct {
	types map[string]string
}

func (fakeTypeSolver) Present(string, string, string) error    { return nil }
func (fakeTypeSolver) CleanUp(string, string, string) error    { return nil }
func (fakeTypeSolver) Timeout() (time.Duration, time.Duration) { return time.Second, time.Second }
func (fakeTypeSolver) PreCheck(string, string, string, func(string, string) (bool, error)) (bool, error) {
	return true, nil
}
func (f fakeTypeSolver) ChallengeTypes() []string { return nil }
func (f fakeTypeSolver) TypeFor(domain string) (string, error) {
	t, ok := f.types[domain]
	if !ok {
		return "", fmt.Errorf("no rule for %s", domain)
	}
	return t, nil
}
func (f fakeTypeSolver) For(string) signer.ChallengeSolver { return f }

func challengeSet(domain string) []legoacme.Challenge {
	return []legoacme.Challenge{
		{Type: "dns-01", URL: "https://ca.test/chlg/dns/" + domain, Token: "tok-dns"},
		{Type: "http-01", URL: "https://ca.test/chlg/http/" + domain, Token: "tok-http"},
		{Type: "tls-alpn-01", URL: "https://ca.test/chlg/tlsalpn/" + domain, Token: "tok-tlsalpn"},
	}
}

func TestPickChallenge(t *testing.T) {
	t.Run("picks the type TypeFor names among the CA's offered challenges", func(t *testing.T) {
		solver := fakeTypeSolver{types: map[string]string{"a.example.com": "http-01"}}
		authz := legoacme.Authorization{
			Identifier: legoacme.Identifier{Value: "a.example.com"},
			Challenges: challengeSet("a.example.com"),
		}
		typ, chlg, skip, err := pickChallenge(solver, authz)
		if err != nil || skip {
			t.Fatalf("pickChallenge() = %q, %v, skip=%v, err=%v", typ, chlg, skip, err)
		}
		if typ != "http-01" || chlg.Type != "http-01" {
			t.Fatalf("typ=%q chlg.Type=%q, want http-01", typ, chlg.Type)
		}
	})

	t.Run("a wildcard authorization picks the *.zone rule's type", func(t *testing.T) {
		solver := fakeTypeSolver{types: map[string]string{"*.example.com": "dns-01"}}
		authz := legoacme.Authorization{
			Identifier: legoacme.Identifier{Value: "example.com"},
			Wildcard:   true,
			Challenges: challengeSet("example.com"),
		}
		typ, _, skip, err := pickChallenge(solver, authz)
		if err != nil || skip {
			t.Fatalf("pickChallenge() skip=%v err=%v", skip, err)
		}
		if typ != "dns-01" {
			t.Fatalf("typ = %q, want dns-01", typ)
		}
	})

	t.Run("a type the CA never offered is a named error", func(t *testing.T) {
		solver := fakeTypeSolver{types: map[string]string{"a.example.com": "http-01"}}
		authz := legoacme.Authorization{
			Identifier: legoacme.Identifier{Value: "a.example.com"},
			Challenges: []legoacme.Challenge{{Type: "dns-01", URL: "https://ca.test/chlg/dns"}},
		}
		_, _, skip, err := pickChallenge(solver, authz)
		if skip || err == nil {
			t.Fatalf("pickChallenge() skip=%v err=%v, want an error", skip, err)
		}
		if got := err.Error(); got != "CA offered no http-01 challenge for a.example.com" {
			t.Fatalf("err = %q", got)
		}
	})

	t.Run("an already-valid authorization is skipped", func(t *testing.T) {
		solver := fakeTypeSolver{types: map[string]string{}} // TypeFor would error; must not be reached
		authz := legoacme.Authorization{Status: legoacme.StatusValid, Identifier: legoacme.Identifier{Value: "a.example.com"}}
		_, _, skip, err := pickChallenge(solver, authz)
		if !skip || err != nil {
			t.Fatalf("pickChallenge() skip=%v err=%v, want skip=true err=nil", skip, err)
		}
	})
}

// fakeChallengeCA serves just enough ACME for api.New and mixedResolver's
// hand-rolled validate to run against: a directory, a nonce endpoint, one
// challenge URL that starts pending and whose authorization later resolves
// valid, and one challenge URL that reports invalid immediately with an ACME
// problem. No JWS is ever verified.
func fakeChallengeCA(t *testing.T) *httptest.Server {
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
	mux.HandleFunc("/chlg-pending", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-2")
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Link", `<`+base+`/authz-pending>; rel="up"`)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"type":"dns-01","url":"`+base+`/chlg-pending","status":"pending","token":"tok1"}`)
	})
	mux.HandleFunc("/authz-pending", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-3")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"valid","identifier":{"type":"dns","value":"a.example.test"},`+
			`"challenges":[{"type":"dns-01","url":"`+base+`/chlg-pending","status":"valid","token":"tok1"}]}`)
	})
	mux.HandleFunc("/chlg-invalid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-4")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"type":"dns-01","url":"`+base+`/chlg-invalid","status":"invalid","token":"tok2",`+
			`"error":{"type":"urn:ietf:params:acme:error:unauthorized","detail":"nope","status":403}}`)
	})
	srv := httptest.NewTLSServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func fakeCore(t *testing.T, srv *httptest.Server) *api.Core {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core, err := api.New(srv.Client(), "certforge-test", srv.URL+"/dir", "https://ca.test/acct/1", key)
	if err != nil {
		t.Fatal(err)
	}
	return core
}

func TestValidatePolls(t *testing.T) {
	srv := fakeChallengeCA(t)
	core := fakeCore(t, srv)

	t.Run("pending then valid returns nil", func(t *testing.T) {
		m := &mixedResolver{core: core, ctx: context.Background()}
		err := m.validate(core, "a.example.test", legoacme.Challenge{URL: srv.URL + "/chlg-pending"})
		if err != nil {
			t.Fatalf("validate() = %v, want nil", err)
		}
	})

	t.Run("invalid preserves the ACME problem type through classify", func(t *testing.T) {
		m := &mixedResolver{core: core, ctx: context.Background()}
		err := m.validate(core, "a.example.test", legoacme.Challenge{URL: srv.URL + "/chlg-invalid"})
		if err == nil {
			t.Fatal("validate() = nil, want an error")
		}
		var se *signer.Error
		if !errors.As(classify(err, nil), &se) {
			t.Fatalf("classify(%v) is not a *signer.Error", err)
		}
		if se.ShortType() != "unauthorized" || se.Status != 403 {
			t.Fatalf("Type=%q Status=%d, want unauthorized/403", se.Type, se.Status)
		}
	})
}

func TestIssueSingleTypeKeepsSolverManager(t *testing.T) {
	orig := newCertifier
	t.Cleanup(func() { newCertifier = orig })
	called := false
	newCertifier = func(core *api.Core, res resolver, opts certificate.CertifierOptions) *certificate.Certifier {
		called = true
		return orig(core, res, opts)
	}

	srv := fakeRateLimitedCA(t, "60")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	s := New(Config{DirectoryURL: srv.URL + "/dir", TrustBundlePEM: string(bundle)})

	_, err := s.Issue(context.Background(), signer.IssueRequest{
		Names: []string{"a.example.test"}, KeyType: signer.EC256,
		Account: testAccount(t), Challenge: nopSolver{}, // nopSolver.ChallengeTypes() = ["dns-01"], a single type
	})
	if err == nil {
		t.Fatal("want an error from the rate-limited fake CA")
	}
	if called {
		t.Fatal("newCertifier must not be called for a single challenge type")
	}
}

// multiTypeSolver is nopSolver with more than one challenge type, so Issue
// takes the mixed order-flow path without needing a working per-type view
// (Obtain fails at order creation against fakeRateLimitedCA before Solve is
// ever reached).
type multiTypeSolver struct{ nopSolver }

func (multiTypeSolver) ChallengeTypes() []string { return []string{"dns-01", "http-01"} }

// TestIssueMultiTypeReachesNewCertifierWithUnboundedCtx is fix round 1,
// Important: newCertifier is called for a multi-type request (the positive
// counterpart to TestIssueSingleTypeKeepsSolverManager), and the
// mixedResolver it is given carries no deadline of its own when the Issue
// caller's ctx has none. Before the fix, issueMixed wrapped the Issue ctx in
// context.WithTimeout(ctx, certifierTimeout+30*time.Second) once, up front,
// covering PreSolve/propagation and every validate call with one shared
// clock; a slow DNS rule or manual wait could exhaust most of that budget
// before validate ever got to poll, failing with "context deadline
// exceeded" even though the challenge itself would have validated quickly.
// mixedResolver.ctx must be exactly the Issue ctx now; validate derives its
// own fresh per-call bound from it instead (see TestValidateBudgetIsPerCall).
func TestIssueMultiTypeReachesNewCertifierWithUnboundedCtx(t *testing.T) {
	orig := newCertifier
	t.Cleanup(func() { newCertifier = orig })
	var captured *mixedResolver
	newCertifier = func(core *api.Core, res resolver, opts certificate.CertifierOptions) *certificate.Certifier {
		captured, _ = res.(*mixedResolver)
		return orig(core, res, opts)
	}

	srv := fakeRateLimitedCA(t, "60")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	s := New(Config{DirectoryURL: srv.URL + "/dir", TrustBundlePEM: string(bundle)})

	_, err := s.Issue(context.Background(), signer.IssueRequest{
		Names: []string{"a.example.test"}, KeyType: signer.EC256,
		Account: testAccount(t), Challenge: multiTypeSolver{},
	})
	if err == nil {
		t.Fatal("want an error from the rate-limited fake CA")
	}
	if captured == nil {
		t.Fatal("newCertifier was not called for a multi-type request")
	}
	if _, ok := captured.ctx.Deadline(); ok {
		t.Fatal("mixedResolver.ctx must not carry a deadline the Issue caller never set")
	}
}

// callLog is a mutex-protected append-only log shared by recordingProviders,
// so a test can assert the relative order of Present/CleanUp calls across
// more than one challenge type within a single mixedResolver.Solve.
type callLog struct {
	mu  sync.Mutex
	log []string
}

func (c *callLog) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, s)
}

func (c *callLog) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.log)
}

// recordingProvider is a signer.ChallengeSolver whose Present/CleanUp append
// to a shared callLog instead of doing anything real; PreCheck always
// reports ready so no real DNS lookup happens.
type recordingProvider struct {
	name       string
	log        *callLog
	cleanupErr error
}

func (p *recordingProvider) Present(domain, _, _ string) error {
	p.log.add(p.name + " present " + domain)
	return nil
}

func (p *recordingProvider) CleanUp(domain, _, _ string) error {
	p.log.add(p.name + " cleanup " + domain)
	return p.cleanupErr
}

func (p *recordingProvider) Timeout() (time.Duration, time.Duration) {
	return time.Second, time.Millisecond
}
func (p *recordingProvider) PreCheck(string, string, string, func(string, string) (bool, error)) (bool, error) {
	return true, nil
}
func (p *recordingProvider) ChallengeTypes() []string          { return nil }
func (p *recordingProvider) TypeFor(string) (string, error)    { return "", errors.New("not used") }
func (p *recordingProvider) For(string) signer.ChallengeSolver { return p }

// recordingSolver routes TypeFor/For by domain to one of two
// recordingProviders (dns, http), for
// TestMixedResolverSolvePreSolvesDNSBeforeAnyValidateAndCleansUpOnFailure.
type recordingSolver struct {
	types map[string]string
	dns   *recordingProvider
	http  *recordingProvider
}

func (recordingSolver) Present(string, string, string) error    { return nil }
func (recordingSolver) CleanUp(string, string, string) error    { return nil }
func (recordingSolver) Timeout() (time.Duration, time.Duration) { return time.Second, time.Millisecond }
func (recordingSolver) PreCheck(string, string, string, func(string, string) (bool, error)) (bool, error) {
	return true, nil
}
func (s *recordingSolver) ChallengeTypes() []string { return []string{"dns-01", "http-01"} }
func (s *recordingSolver) TypeFor(domain string) (string, error) {
	t, ok := s.types[domain]
	if !ok {
		return "", fmt.Errorf("no rule for %s", domain)
	}
	return t, nil
}
func (s *recordingSolver) For(t string) signer.ChallengeSolver {
	switch t {
	case "dns-01":
		return s.dns
	case "http-01":
		return s.http
	}
	return s
}

// TestMixedResolverSolvePreSolvesDNSBeforeAnyValidateAndCleansUpOnFailure is
// fix round 1, Minor: Solve must present every dns-01 challenge before
// validating any authorization (so every TXT record has the most time to
// propagate), and must still clean up the dns-01 challenge — logging a
// failure to do so, scrubbed by the time it reaches here since a real
// dns-01 rule's provider is always challenge.WrapLego-wrapped — even though
// the http-01 authorization (listed first) is the one that fails.
func TestMixedResolverSolvePreSolvesDNSBeforeAnyValidateAndCleansUpOnFailure(t *testing.T) {
	srv := fakeChallengeCA(t)
	core := fakeCore(t, srv)

	var logBuf bytes.Buffer
	origLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(origLogger) })

	log := &callLog{}
	dns := &recordingProvider{name: "dns", log: log, cleanupErr: errors.New("boom")}
	httpP := &recordingProvider{name: "http", log: log}
	solver := &recordingSolver{
		types: map[string]string{"dns.example.test": "dns-01", "http.example.test": "http-01"},
		dns:   dns, http: httpP,
	}

	m := &mixedResolver{core: core, solver: solver, ctx: context.Background()}
	// http-01 is listed first, and its challenge URL reports invalid right
	// away (see fakeChallengeCA): if Solve simply walked the list in order,
	// it would validate http-01 before ever presenting the dns-01 TXT
	// record. It must not.
	authorizations := []legoacme.Authorization{
		{
			Identifier: legoacme.Identifier{Value: "http.example.test"},
			Challenges: []legoacme.Challenge{{Type: "http-01", URL: srv.URL + "/chlg-invalid", Token: "tok-http"}},
		},
		{
			Identifier: legoacme.Identifier{Value: "dns.example.test"},
			Challenges: []legoacme.Challenge{{Type: "dns-01", URL: srv.URL + "/chlg-pending", Token: "tok-dns"}},
		},
	}

	err := m.Solve(authorizations)
	if err == nil {
		t.Fatal("want an error from the invalid http-01 challenge")
	}

	got := log.snapshot()
	if len(got) == 0 || got[0] != "dns present dns.example.test" {
		t.Fatalf("log = %v, want dns-01 presented first (before any validate)", got)
	}
	if !slices.Contains(got, "http cleanup http.example.test") {
		t.Fatalf("log = %v, want an http-01 CleanUp (lego's own http01.Challenge.Solve defers it after a successful Present)", got)
	}
	if !slices.Contains(got, "dns cleanup dns.example.test") {
		t.Fatalf("log = %v, want a dns-01 CleanUp even though the http-01 authorization is what failed", got)
	}
	if !strings.Contains(logBuf.String(), "boom") {
		t.Fatalf("dns-01 CleanUp's error was not logged: %s", logBuf.String())
	}
}

func TestObtainRequest(t *testing.T) {
	or, err := obtainRequest(signer.IssueRequest{
		Names:          []string{"a.example.test", "b.example.test"},
		MustStaple:     true,
		PreferredChain: "ISRG Root X1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(or.Domains) != 2 || !or.Bundle || !or.MustStaple || or.PreferredChain != "ISRG Root X1" || or.PrivateKey != nil {
		t.Fatalf("obtainRequest() = %+v", or)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	or, err = obtainRequest(signer.IssueRequest{Names: []string{"a.example.test"}, ReuseKeyPKCS8: der})
	if err != nil || or.PrivateKey == nil {
		t.Fatalf("obtainRequest() with ReuseKeyPKCS8 = %+v, err = %v", or, err)
	}

	if _, err := obtainRequest(signer.IssueRequest{Names: []string{"a.example.test"}, ReuseKeyPKCS8: []byte("not a key")}); err == nil {
		t.Fatal("want an error for a malformed reused key")
	}
}
