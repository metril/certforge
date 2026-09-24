package challenge

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"

	legochallenge "github.com/go-acme/lego/v4/challenge"
)

// Review Focus: a live DNS provider error (or a construction failure) must
// never echo a config secret back out raw, query-escaped, path-escaped, or
// JSON-escaped, since it ends up in the worker's attempt log/last_error,
// the audit log, and (for the test endpoint) the API response.
func TestScrubRedactsRawAndQueryEscaped(t *testing.T) {
	secret := "s3cr3t value/with?special=chars"
	cfg := map[string]string{"TOKEN": secret, "EMPTY": ""}
	err := fmt.Errorf("POST https://api.example.test/v1?token=%s failed: invalid token %q", url.QueryEscape(secret), secret)

	scrubbed := Scrub(err, "cloudflare", cfg)
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

	if Scrub(nil, "cloudflare", cfg) != nil {
		t.Fatal("Scrub(nil, ...) must return nil")
	}
	plain := errors.New("no secrets here")
	if got := Scrub(plain, "cloudflare", cfg); got.Error() != plain.Error() || !errors.Is(got, plain) {
		t.Fatal("Scrub must return the error unchanged when nothing needed scrubbing")
	}
}

// Review Focus (fix round 2, item 1, Critical): scrubbing in cfg's random
// map order can let a short value land inside a longer value that contains
// it as a substring, redacting a fragment and leaving the rest of the
// secret behind. 200 iterations exercise Go's randomized map iteration
// order to catch a fix that only works some of the time.
func TestScrubDefeatsMapOrderFragmentation(t *testing.T) {
	secret := "XY9ef2AB9ef2CD" // CF_DNS_API_TOKEN: forced-secret regardless of length
	overlap := "9ef2"          // CLOUDFLARE_TTL: non-secret, length 4 (qualifies), substring of secret twice over
	cfg := map[string]string{"CF_DNS_API_TOKEN": secret, "CLOUDFLARE_TTL": overlap}
	msg := "provider rejected token " + secret

	for i := 0; i < 200; i++ {
		got := Scrub(errors.New(msg), "cloudflare", cfg).Error()
		if strings.Contains(got, secret) || strings.Contains(got, "XY") || strings.Contains(got, "AB") || strings.Contains(got, "CD") {
			t.Fatalf("iteration %d: secret fragment survived: %s", i, got)
		}
		if n := strings.Count(got, redacted); n != 1 {
			t.Fatalf("iteration %d: want exactly 1 %q (secret redacted whole, not fragmented), got %d: %s", i, redacted, n, got)
		}
	}
}

// Review Focus (fix round 2, item 1): a short non-secret value (a
// propagation-seconds "2", a poll interval) must never be redacted — it is
// far too likely to be an ordinary substring of unrelated message text.
func TestScrubLeavesShortNonSecretValueIntact(t *testing.T) {
	cfg := map[string]string{"CLOUDFLARE_POLLING_INTERVAL": "2"}
	msg := "waited 2 seconds for propagation"
	err := errors.New(msg)
	if got := Scrub(err, "cloudflare", cfg); got.Error() != msg {
		t.Fatalf("short non-secret value must not be scrubbed: %s", got.Error())
	}
}

func TestScrubRedactsJSONQuotedSecret(t *testing.T) {
	secret := `sec"ret\value`
	cfg := map[string]string{"CF_DNS_API_TOKEN": secret}
	quoted := strconv.Quote(secret)
	inner := quoted[1 : len(quoted)-1]
	msg := `response body: {"token":"` + inner + `"}`

	got := Scrub(errors.New(msg), "cloudflare", cfg).Error()
	if strings.Contains(got, inner) || strings.Contains(got, secret) {
		t.Fatalf("JSON-escaped secret survived: %s", got)
	}
	if !strings.Contains(got, redacted) {
		t.Fatalf("expected %q in scrubbed message: %s", redacted, got)
	}
}

func TestScrubRedactsPathEscapedSecret(t *testing.T) {
	secret := "sec ret/val#ue"
	cfg := map[string]string{"CF_DNS_API_TOKEN": secret}
	esc := url.PathEscape(secret)
	msg := "GET /api/v1/" + esc + " failed"

	got := Scrub(errors.New(msg), "cloudflare", cfg).Error()
	if strings.Contains(got, esc) || strings.Contains(got, secret) {
		t.Fatalf("path-escaped secret survived: %s", got)
	}
	if !strings.Contains(got, redacted) {
		t.Fatalf("expected %q in scrubbed message: %s", redacted, got)
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

// Review Focus (fix round 2, item 3): Build must also refuse a serverPath
// value, not just SplitConfig, since a credential created before that
// check existed could still have one persisted.
func TestBuildRejectsServerPathValue(t *testing.T) {
	_, err := Build("gcloud", map[string]string{"GCE_SERVICE_ACCOUNT_FILE": "/etc/secrets/gcloud.json"})
	if !errors.Is(err, ErrServerPath) {
		t.Fatalf("want ErrServerPath, got %v", err)
	}
}
