package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
