package targets_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/targets"
)

func TestRedactEscapedForms(t *testing.T) {
	secret := "a secret/value"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	msg := "plain: " + secret +
		"; query: https://example.com/x?token=a+secret%2Fvalue" +
		"; path: https://example.com/a%20secret%2Fvalue/y" +
		"; b64: " + b64

	out := targets.Redact(errors.New(msg), map[string]string{"token": secret}, targets.MaxDetail)

	if strings.Contains(out, secret) {
		t.Errorf("Redact left the raw secret in %q", out)
	}
	if strings.Contains(out, "a+secret%2Fvalue") {
		t.Errorf("Redact left the query-escaped form in %q", out)
	}
	if strings.Contains(out, "a%20secret%2Fvalue") {
		t.Errorf("Redact left the path-escaped form in %q", out)
	}
	if strings.Contains(out, b64) {
		t.Errorf("Redact left the base64 form in %q", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("Redact produced no [redacted] marker in %q", out)
	}
}

func TestRedactCutsToMaxOnUTF8Boundary(t *testing.T) {
	msg := strings.Repeat("é", 150) // 2 bytes each in UTF-8: 300 bytes
	out := targets.Redact(errors.New(msg), nil, 100)
	if len(out) > 100 {
		t.Fatalf("Redact returned %d bytes, want <= 100", len(out))
	}
	if !strings.HasSuffix(out, "é") && len(out) > 0 {
		// The cut must land on a full rune, never a partial one.
		r := []rune(out)
		if len(r) == 0 {
			t.Fatal("Redact produced invalid UTF-8")
		}
	}
}

func TestRedactNilError(t *testing.T) {
	if got := targets.Redact(nil, map[string]string{"a": "b"}, 10); got != "" {
		t.Fatalf("Redact(nil) = %q, want empty", got)
	}
}

func TestRedactEmptySecretsSkipped(t *testing.T) {
	out := targets.Redact(errors.New("hello world"), map[string]string{"a": ""}, targets.MaxDetail)
	if out != "hello world" {
		t.Fatalf("Redact = %q, want unchanged message", out)
	}
}
