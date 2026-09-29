package httpx_test

import (
	"strings"
	"testing"

	"github.com/metril/certforge/internal/notify/httpx"
)

func TestRedactEscapedForms(t *testing.T) {
	secret := "a secret/value"
	msg := "plain: " + secret +
		"; query: " + "https://example.com/x?token=a+secret%2Fvalue" +
		"; path: " + "https://example.com/a%20secret%2Fvalue/y"

	out := httpx.Redact(msg, secret)

	if strings.Contains(out, secret) {
		t.Errorf("Redact left the raw secret in %q", out)
	}
	if strings.Contains(out, "a+secret%2Fvalue") {
		t.Errorf("Redact left the query-escaped form in %q", out)
	}
	if strings.Contains(out, "a%20secret%2Fvalue") {
		t.Errorf("Redact left the path-escaped form in %q", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("Redact produced no [redacted] marker in %q", out)
	}
}

func TestRedactEmptySecretIgnored(t *testing.T) {
	if got := httpx.Redact("hello world", ""); got != "hello world" {
		t.Errorf("Redact with an empty secret changed the string: %q", got)
	}
}
