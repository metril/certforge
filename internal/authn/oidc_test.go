package authn

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metril/certforge/internal/authn/oidctest"
)

const testRedirect = "http://certforge.test/api/v1/auth/oidc/callback"

func oidcSetup(t *testing.T) (*OIDC, *oidctest.Provider, AuthSettings) {
	t.Helper()
	p := oidctest.New(t)
	cfg := AuthSettings{Enabled: true, Issuer: p.URL(), ClientID: oidctest.ClientID, ClientSecret: oidctest.ClientSecret}
	cfg.normalize()
	return NewOIDC(bytes.Repeat([]byte{3}, 32), nil), p, cfg
}

// runFlow drives Begin, the provider's authorize redirect, and returns the
// callback request carrying the state cookie.
func runFlow(t *testing.T, o *OIDC, cfg AuthSettings, next string) *http.Request {
	t.Helper()
	authURL, cookie, err := o.Begin(context.Background(), cfg, testRedirect, next, false)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), testRedirect) {
		t.Fatalf("authorize redirect %q", resp.Header.Get("Location"))
	}
	r := httptest.NewRequest(http.MethodGet, loc.String(), nil)
	r.AddCookie(cookie)
	return r
}

func TestOIDCFlow(t *testing.T) {
	o, p, cfg := oidcSetup(t)
	p.SetUser(oidctest.User{Subject: "abc", Email: "ann@example.test", Name: "Ann", Groups: []string{"ops", "dev"}})
	id, next, err := o.Finish(context.Background(), cfg, testRedirect, runFlow(t, o, cfg, "/o/home"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Issuer != p.URL() || id.Subject != "abc" || id.Email != "ann@example.test" || id.Name != "Ann" ||
		len(id.Groups) != 2 || next != "/o/home" {
		t.Fatalf("identity %+v next %q", id, next)
	}
}

func TestOIDCRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("tampered cookie", func(t *testing.T) {
		o, _, cfg := oidcSetup(t)
		r := runFlow(t, o, cfg, "/")
		c, _ := r.Cookie(StateCookieName)
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: StateCookieName, Value: "x" + c.Value})
		if _, _, err := o.Finish(ctx, cfg, testRedirect, r); !errors.Is(err, ErrOIDCState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing cookie", func(t *testing.T) {
		o, _, cfg := oidcSetup(t)
		r := runFlow(t, o, cfg, "/")
		r.Header.Del("Cookie")
		if _, _, err := o.Finish(ctx, cfg, testRedirect, r); !errors.Is(err, ErrOIDCState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("expired state", func(t *testing.T) {
		o, _, cfg := oidcSetup(t)
		r := runFlow(t, o, cfg, "/")
		o.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
		if _, _, err := o.Finish(ctx, cfg, testRedirect, r); !errors.Is(err, ErrOIDCState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("state mismatch", func(t *testing.T) {
		o, _, cfg := oidcSetup(t)
		r := runFlow(t, o, cfg, "/")
		q := r.URL.Query()
		q.Set("state", "other")
		r.URL.RawQuery = q.Encode()
		if _, _, err := o.Finish(ctx, cfg, testRedirect, r); !errors.Is(err, ErrOIDCState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("denied", func(t *testing.T) {
		o, p, cfg := oidcSetup(t)
		p.SetDenied(true)
		if _, _, err := o.Finish(ctx, cfg, testRedirect, runFlow(t, o, cfg, "/")); !errors.Is(err, ErrOIDCDenied) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("nonce replay", func(t *testing.T) {
		o, p, cfg := oidcSetup(t)
		p.SetNonce("someone-elses-nonce")
		if _, _, err := o.Finish(ctx, cfg, testRedirect, runFlow(t, o, cfg, "/")); !errors.Is(err, ErrOIDCState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong client secret", func(t *testing.T) {
		o, _, cfg := oidcSetup(t)
		r := runFlow(t, o, cfg, "/")
		cfg.ClientSecret = "wrong"
		if _, _, err := o.Finish(ctx, cfg, testRedirect, r); err == nil {
			t.Fatal("exchange with a wrong secret succeeded")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		o, _, cfg := oidcSetup(t)
		cfg.Enabled = false
		if _, _, err := o.Begin(ctx, cfg, testRedirect, "/", false); !errors.Is(err, ErrOIDCDisabled) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestOIDCWrongAudienceRefused(t *testing.T) {
	o, p, cfg := oidcSetup(t)
	p.SetAudience("someone-elses-client")
	if _, _, err := o.Finish(context.Background(), cfg, testRedirect, runFlow(t, o, cfg, "/")); err == nil {
		t.Fatal("id token minted for a different audience was accepted")
	}
}

func TestOIDCPublicClient(t *testing.T) {
	p := oidctest.New(t)
	p.SetPublicClient(true)
	cfg := AuthSettings{Enabled: true, Issuer: p.URL(), ClientID: oidctest.ClientID, ClientSecret: ""}
	cfg.normalize()
	o := NewOIDC(bytes.Repeat([]byte{3}, 32), nil)
	p.SetUser(oidctest.User{Subject: "pub", Email: "pub@example.test", Name: "Pub"})
	id, _, err := o.Finish(context.Background(), cfg, testRedirect, runFlow(t, o, cfg, "/"))
	if err != nil || id.Subject != "pub" {
		t.Fatalf("id %+v err %v", id, err)
	}
}

func TestOIDCTest(t *testing.T) {
	o, p, _ := oidcSetup(t)
	res, err := o.Test(context.Background(), p.URL())
	if err != nil || res.Keys != 1 || res.TokenEndpoint != p.URL()+"/token" {
		t.Fatalf("res %+v err %v", res, err)
	}
	if _, err := o.Test(context.Background(), "http://127.0.0.1:1"); err == nil {
		t.Fatal("unreachable issuer passed")
	}
}

func TestClaimAt(t *testing.T) {
	c := map[string]any{
		"groups":       []any{"a"},
		"a.b":          []any{"literal"},
		"realm_access": map[string]any{"roles": []any{"admin", "ops"}},
		"a":            map[string]any{"b": []any{"nested"}},
	}
	for name, want := range map[string][]string{
		"groups":             {"a"},
		"realm_access.roles": {"admin", "ops"},
		"a.b":                {"literal"}, // a top-level key containing a dot wins
		"realm_access.nope":  {},
		"nope.deeper":        {},
		"groups.x":           {},
	} {
		if got := claimGroups(claimAt(c, name)); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
}

func TestOIDCDiscoveryFailureCachedBriefly(t *testing.T) {
	var hits atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(idp.Close)
	now := time.Unix(3_000_000, 0)
	o := NewOIDC(bytes.Repeat([]byte{3}, 32), nil)
	o.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := o.provider(ctx, idp.URL); err == nil {
			t.Fatal("discovery against a failing IdP succeeded")
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1 (failure cached)", hits.Load())
	}
	o.Forget() // a settings change drops the cached failure
	_, _ = o.provider(ctx, idp.URL)
	if hits.Load() != 2 {
		t.Fatalf("hits after Forget = %d, want 2", hits.Load())
	}
	now = now.Add(failureTTL)
	_, _ = o.provider(ctx, idp.URL)
	if hits.Load() != 3 {
		t.Fatalf("hits after TTL = %d, want 3", hits.Load())
	}
}
