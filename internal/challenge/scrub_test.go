package challenge

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	legochallenge "github.com/go-acme/lego/v4/challenge"
)

// Review Focus: a live DNS provider error (or a construction failure) must
// never echo a config secret back out raw or query-escaped, since it ends
// up in the worker's attempt log/last_error, the audit log, and (for the
// test endpoint) the API response.
func TestScrubRedactsRawAndQueryEscaped(t *testing.T) {
	secret := "s3cr3t value/with?special=chars"
	cfg := map[string]string{"TOKEN": secret, "EMPTY": ""}
	err := fmt.Errorf("POST https://api.example.test/v1?token=%s failed: invalid token %q", url.QueryEscape(secret), secret)

	scrubbed := Scrub(err, cfg)
	msg := scrubbed.Error()
	if strings.Contains(msg, secret) {
		t.Fatalf("raw secret survived: %s", msg)
	}
	if strings.Contains(msg, url.QueryEscape(secret)) {
		t.Fatalf("query-escaped secret survived: %s", msg)
	}
	if !strings.Contains(msg, redacted) {
		t.Fatalf("expected %q in scrubbed message: %s", redacted, msg)
	}
	if !errors.Is(scrubbed, err) {
		t.Fatal("Scrub must preserve the original error for errors.Is/As via Unwrap")
	}

	if Scrub(nil, cfg) != nil {
		t.Fatal("Scrub(nil, ...) must return nil")
	}
	plain := errors.New("no secrets here")
	if got := Scrub(plain, cfg); got.Error() != plain.Error() || !errors.Is(got, plain) {
		t.Fatal("Scrub must return the error unchanged when nothing needed scrubbing")
	}
}

type leakyLegoProvider struct{ secret string }

func (p leakyLegoProvider) Present(string, string, string) error {
	return fmt.Errorf("present failed: token=%s (escaped %s)", p.secret, url.QueryEscape(p.secret))
}

func (p leakyLegoProvider) CleanUp(string, string, string) error {
	return fmt.Errorf("cleanup failed: token=%s", p.secret)
}

func TestWrapLegoScrubsProviderErrors(t *testing.T) {
	secret := "s3cr3t/token value"
	cfg := map[string]string{"TOKEN": secret}
	cp := WrapLego("stub", leakyLegoProvider{secret: secret}, cfg)

	if err := cp.Present(context.Background(), "d", "t", "k"); err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), url.QueryEscape(secret)) {
		t.Fatalf("Present error leaked the secret: %v", err)
	}
	if err := cp.CleanUp(context.Background(), "d", "t", "k"); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("CleanUp error leaked the secret: %v", err)
	}
}

// TestBuildScrubsConstructionError covers the other error site Scrub must
// cover: NewDNSProvider (here stubbed via newByName) failing with the
// credential value in its own error text.
func TestBuildScrubsConstructionError(t *testing.T) {
	orig := newByName
	t.Cleanup(func() { newByName = orig })
	secret := "s3cr3t?const=value"
	newByName = func(string) (legochallenge.Provider, error) {
		return nil, fmt.Errorf("construct failed: token=%s (escaped %s)", secret, url.QueryEscape(secret))
	}
	_, err := Build("cloudflare", map[string]string{"CF_DNS_API_TOKEN": secret})
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), url.QueryEscape(secret)) {
		t.Fatalf("construction error leaked the secret: %s", err.Error())
	}
}
