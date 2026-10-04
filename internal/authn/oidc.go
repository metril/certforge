package authn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

// StateCookieName holds the signed OIDC flow state between start and callback.
const StateCookieName = "cf_oidc"

const (
	stateTTL    = 10 * time.Minute
	providerTTL = 10 * time.Minute
	// failureTTL is how long a failed discovery is remembered: long enough
	// that an unreachable IdP is not dialled once per anonymous start, short
	// enough that a recovered IdP is picked up within seconds.
	failureTTL    = 5 * time.Second
	maxGroups     = 256
	maxGroupBytes = 256
)

// OIDC flow errors. The callback maps them to /login?error=<code>.
var (
	ErrOIDCDisabled = errors.New("oidc: single sign-on is not configured")
	ErrOIDCState    = errors.New("oidc: login state missing, expired, or mismatched")
	ErrOIDCDenied   = errors.New("oidc: the identity provider refused the login")
)

// Identity is the verified result of an OIDC login.
type Identity struct {
	Issuer, Subject, Email, Name string
	Groups                       []string
}

// DiscoveryResult is what POST /settings/authentication/test reports.
type DiscoveryResult struct {
	Issuer, AuthorizationEndpoint, TokenEndpoint string
	Keys                                         int
}

type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Expires  int64  `json:"e"`
}

type cachedProvider struct {
	p  *oidc.Provider
	at time.Time
}

// OIDC runs the auth-code + PKCE flow. Discovery documents are cached per
// issuer for 10 minutes; Forget drops the cache after a settings change.
type OIDC struct {
	key       []byte
	hc        *http.Client
	now       func() time.Time
	mu        sync.Mutex
	providers map[string]cachedProvider
	failures  map[string]cachedFailure
	gen       int // bumped by Forget so an in-flight discovery cannot repopulate the cache
	flight    singleflight.Group
}

type cachedFailure struct {
	err error
	at  time.Time
}

// NewOIDC returns a client that signs flow state with stateKey
// (crypto.DeriveKey(kek, "certforge-oidc-state")). hc nil means a 10 s client.
func NewOIDC(stateKey []byte, hc *http.Client) *OIDC {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &OIDC{key: stateKey, hc: hc, now: time.Now, providers: map[string]cachedProvider{}, failures: map[string]cachedFailure{}}
}

// Forget drops cached discovery documents.
func (o *OIDC) Forget() {
	o.mu.Lock()
	o.providers = map[string]cachedProvider{}
	o.failures = map[string]cachedFailure{}
	o.gen++
	o.mu.Unlock()
}

// provider returns the cached discovery for issuer. Concurrent misses share
// one fetch (singleflight) and a failure is remembered for failureTTL, so an
// unreachable IdP costs one dial per few seconds, not one per request.
func (o *OIDC) provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	o.mu.Lock()
	c, ok := o.providers[issuer]
	f, failed := o.failures[issuer]
	gen := o.gen
	o.mu.Unlock()
	if ok && o.now().Sub(c.at) < providerTTL {
		return c.p, nil
	}
	if failed && o.now().Sub(f.at) < failureTTL {
		return nil, f.err
	}
	v, err, _ := o.flight.Do(issuer, func() (any, error) {
		// Detached from the first caller's context so its cancellation does
		// not fail every waiter; o.hc's timeout still bounds the fetch.
		p, err := oidc.NewProvider(oidc.ClientContext(context.WithoutCancel(ctx), o.hc), issuer)
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.gen != gen {
			return p, err
		}
		if err != nil {
			err = fmt.Errorf("oidc discovery: %w", err)
			o.failures[issuer] = cachedFailure{err: err, at: o.now()}
			return nil, err
		}
		delete(o.failures, issuer)
		o.providers[issuer] = cachedProvider{p: p, at: o.now()}
		return p, nil
	})
	if err != nil {
		if !strings.HasPrefix(err.Error(), "oidc discovery:") {
			err = fmt.Errorf("oidc discovery: %w", err)
		}
		return nil, err
	}
	return v.(*oidc.Provider), nil
}

func oauthConfig(p *oidc.Provider, cfg AuthSettings, redirectURL string) *oauth2.Config {
	return &oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: redirectURL, Scopes: cfg.Scopes}
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Begin returns the provider's authorize URL and the state cookie to set.
func (o *OIDC) Begin(ctx context.Context, cfg AuthSettings, redirectURL, next string, secure bool) (string, *http.Cookie, error) {
	if !cfg.OIDCReady() {
		return "", nil, ErrOIDCDisabled
	}
	p, err := o.provider(ctx, cfg.Issuer)
	if err != nil {
		return "", nil, err
	}
	st := flowState{State: randomString(), Nonce: randomString(), Verifier: oauth2.GenerateVerifier(),
		Next: next, Expires: o.now().Add(stateTTL).Unix()}
	u := oauthConfig(p, cfg, redirectURL).AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	b, err := json.Marshal(st)
	if err != nil {
		return "", nil, err
	}
	payload := base64.RawURLEncoding.EncodeToString(b)
	return u, &http.Cookie{Name: StateCookieName, Value: payload + "." + o.mac(payload), Path: "/api/v1/auth/oidc",
		MaxAge: int(stateTTL.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}, nil
}

// ClearStateCookie deletes the state cookie.
func (o *OIDC) ClearStateCookie(secure bool) *http.Cookie {
	return &http.Cookie{Name: StateCookieName, Value: "", Path: "/api/v1/auth/oidc", MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
}

func (o *OIDC) mac(payload string) string {
	m := hmac.New(sha256.New, o.key)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (o *OIDC) readState(r *http.Request) (flowState, error) {
	c, err := r.Cookie(StateCookieName)
	if err != nil {
		return flowState{}, ErrOIDCState
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(o.mac(payload))) {
		return flowState{}, ErrOIDCState
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return flowState{}, ErrOIDCState
	}
	var st flowState
	if err := json.Unmarshal(b, &st); err != nil || o.now().Unix() > st.Expires {
		return flowState{}, ErrOIDCState
	}
	return st, nil
}

// Finish validates the callback request and returns the verified identity
// and the next path saved by Begin.
func (o *OIDC) Finish(ctx context.Context, cfg AuthSettings, redirectURL string, r *http.Request) (Identity, string, error) {
	st, err := o.readState(r)
	if err != nil {
		return Identity{}, "", err
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		return Identity{}, st.Next, ErrOIDCState
	}
	if e := q.Get("error"); e != "" {
		return Identity{}, st.Next, fmt.Errorf("%w: %s", ErrOIDCDenied, e)
	}
	if !cfg.OIDCReady() {
		return Identity{}, st.Next, ErrOIDCDisabled
	}
	p, err := o.provider(ctx, cfg.Issuer)
	if err != nil {
		return Identity{}, st.Next, err
	}
	tok, err := oauthConfig(p, cfg, redirectURL).Exchange(oidc.ClientContext(ctx, o.hc), q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return Identity{}, st.Next, fmt.Errorf("oidc exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return Identity{}, st.Next, errors.New("oidc: token response has no id_token")
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return Identity{}, st.Next, fmt.Errorf("oidc verify: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		return Identity{}, st.Next, ErrOIDCState
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, st.Next, fmt.Errorf("oidc claims: %w", err)
	}
	id := Identity{Issuer: idt.Issuer, Subject: idt.Subject, Email: claimString(claims, "email"),
		Name: claimString(claims, "name"), Groups: claimGroups(claimAt(claims, cfg.GroupsClaim))}
	for _, alt := range []string{claimString(claims, "preferred_username"), id.Email, id.Subject} {
		if id.Name == "" {
			id.Name = alt
		}
	}
	return id, st.Next, nil
}

func claimString(c map[string]any, k string) string {
	s, _ := c[k].(string)
	return s
}

// claimAt reads a claim by name. A key that exists at the top level wins
// (including one containing a dot); otherwise name is walked as a dotted
// path through nested objects, e.g. "realm_access.roles".
func claimAt(c map[string]any, name string) any {
	if v, ok := c[name]; ok || !strings.Contains(name, ".") {
		return v
	}
	var cur any = c
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

// claimGroups accepts a string or an array of strings, capped.
func claimGroups(v any) []string {
	out := []string{}
	add := func(s string) {
		if s != "" && len(s) <= maxGroupBytes && len(out) < maxGroups {
			out = append(out, s)
		}
	}
	switch g := v.(type) {
	case string:
		add(g)
	case []any:
		for _, e := range g {
			if s, ok := e.(string); ok {
				add(s)
			}
		}
	}
	return out
}

// Test fetches the discovery document and the JWKS without logging in.
func (o *OIDC) Test(ctx context.Context, issuer string) (DiscoveryResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.hc), issuer)
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("discovery: %w", err)
	}
	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := p.Claims(&meta); err != nil || meta.JWKSURI == "" {
		return DiscoveryResult{}, errors.New("discovery document has no jwks_uri")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.JWKSURI, nil)
	if err != nil {
		return DiscoveryResult{}, err
	}
	resp, err := o.hc.Do(req)
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DiscoveryResult{}, fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return DiscoveryResult{}, fmt.Errorf("jwks: %w", err)
	}
	if len(set.Keys) == 0 {
		return DiscoveryResult{}, errors.New("jwks has no keys")
	}
	ep := p.Endpoint()
	return DiscoveryResult{Issuer: issuer, AuthorizationEndpoint: ep.AuthURL, TokenEndpoint: ep.TokenURL, Keys: len(set.Keys)}, nil
}
