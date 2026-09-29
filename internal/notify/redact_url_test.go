package notify

import (
	"strings"
	"testing"
)

func TestRedactURLsStripsVaultStyleError(t *testing.T) {
	in := `vault: request PUT "https://vault.internal.example.net:8200/v1/secret/data/certs/foo": dial tcp 10.0.5.7:8200: connect: connection refused`
	out := redactURLs(in)
	for _, leak := range []string{"vault.internal.example.net", "10.0.5.7", "https://"} {
		if strings.Contains(out, leak) {
			t.Errorf("redactURLs(%q) = %q, still contains %q", in, out, leak)
		}
	}
	if !strings.Contains(out, "<redacted-url>") {
		t.Errorf("redactURLs(%q) = %q, want a <redacted-url> placeholder", in, out)
	}
}

func TestRedactURLsLeavesPlainTextAlone(t *testing.T) {
	in := "deploy failed: disk full"
	if got := redactURLs(in); got != in {
		t.Errorf("redactURLs(%q) = %q, want unchanged", in, got)
	}
}
