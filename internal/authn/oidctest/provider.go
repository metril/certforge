// Package oidctest is an in-process OpenID Connect provider for tests:
// discovery, JWKS, an auto-approving authorize endpoint that enforces PKCE
// S256, a token endpoint that issues RS256 ID tokens, and userinfo.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Client credentials the provider accepts.
const (
	ClientID     = "certforge-test"
	ClientSecret = "test-secret"
)

// User is the identity the next login returns.
type User struct {
	Subject, Email, Name string
	Groups               []string
}

// Provider is a running fake OIDC provider.
type Provider struct {
	srv          *httptest.Server
	key          *rsa.PrivateKey
	mu           sync.Mutex
	user         User
	denied       bool
	nonce        string
	audience     string
	publicClient bool
	closeOnce    sync.Once
	codes        map[string]grant
	tokens       map[string]User
}

type grant struct {
	nonce, challenge, redirect string
	user                       User
}

// New starts a provider that stops when t ends.
func New(t testing.TB) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{key: key, codes: map[string]grant{}, tokens: map[string]User{},
		user: User{Subject: "sub-1", Email: "user@example.test", Name: "Test User"}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.Stop)
	return p
}

// URL is the issuer URL.
func (p *Provider) URL() string { return p.srv.URL }

// SetUser sets the identity returned by later logins.
func (p *Provider) SetUser(u User) { p.mu.Lock(); p.user = u; p.mu.Unlock() }

// SetDenied makes /authorize answer error=access_denied.
func (p *Provider) SetDenied(d bool) { p.mu.Lock(); p.denied = d; p.mu.Unlock() }

// SetNonce forces the nonce claim of later ID tokens (replay tests).
func (p *Provider) SetNonce(n string) { p.mu.Lock(); p.nonce = n; p.mu.Unlock() }

// SetAudience forces the aud claim of later ID tokens to a value other than
// ClientID, for testing that the relying party refuses a token minted for a
// different client. Empty restores the default (ClientID).
func (p *Provider) SetAudience(aud string) { p.mu.Lock(); p.audience = aud; p.mu.Unlock() }

// SetPublicClient makes the token endpoint accept ClientID with an empty
// client secret (a public client using PKCE alone), in addition to the
// normal confidential-client credentials.
func (p *Provider) SetPublicClient(v bool) { p.mu.Lock(); p.publicClient = v; p.mu.Unlock() }

// Stop shuts the provider down before the test ends, for tests that need to
// simulate the identity provider becoming unreachable mid-flow. Safe to call
// more than once (including via the automatic t.Cleanup).
func (p *Provider) Stop() { p.closeOnce.Do(p.srv.Close) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	u := p.srv.URL
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token",
		"jwks_uri": u + "/jwks", "userinfo_endpoint": u + "/userinfo", "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported": []string{"S256"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: string(jose.RS256), Use: "sig"},
	}})
}

func randHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("client_id") != ClientID || q.Get("response_type") != "code" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE S256 required", http.StatusBadRequest)
		return
	}
	v := back.Query()
	v.Set("state", q.Get("state"))
	p.mu.Lock()
	if p.denied {
		v.Set("error", "access_denied")
	} else {
		code := randHex()
		p.codes[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), user: p.user}
		v.Set("code", code)
	}
	p.mu.Unlock()
	back.RawQuery = v.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	p.mu.Lock()
	publicOK := p.publicClient && secret == ""
	p.mu.Unlock()
	if id != ClientID || (secret != ClientSecret && !publicOK) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	g, found := p.codes[code]
	delete(p.codes, code)
	forced := p.nonce
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || g.redirect != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if forced != "" {
		g.nonce = forced
	}
	idt, err := p.sign(g)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	p.mu.Lock()
	p.tokens["at-"+code] = g.user
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"access_token": "at-" + code, "token_type": "Bearer", "expires_in": 300, "id_token": idt})
}

// userinfo answers for access tokens this provider issued. CertForge reads
// claims from the ID token; this exists so clients that call userinfo work.
func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	u, ok := p.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	p.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": u.Subject, "email": u.Email, "name": u.Name, "groups": u.Groups})
}

func (p *Provider) sign(g grant) (string, error) {
	now := time.Now()
	p.mu.Lock()
	aud := p.audience
	p.mu.Unlock()
	if aud == "" {
		aud = ClientID
	}
	claims := map[string]any{"iss": p.srv.URL, "sub": g.user.Subject, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": g.nonce,
		"email": g.user.Email, "name": g.user.Name}
	if g.user.Groups != nil {
		claims["groups"] = g.user.Groups
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}
