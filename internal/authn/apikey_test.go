package authn

import (
	"bytes"
	"strings"
	"testing"
)

func TestAPIKeyToken(t *testing.T) {
	tok, prefix, hash, err := NewAPIKeyToken()
	if err != nil {
		t.Fatal(err)
	}
	p, secret, ok := ParseAPIKeyToken(tok)
	if !ok || p != prefix || !bytes.Equal(HashAPIKeySecret(secret), hash) || !strings.HasPrefix(tok, "cf_"+prefix+"_") {
		t.Fatalf("round trip: %q %q %v", tok, p, ok)
	}
	for _, bad := range []string{"", "cf_", "cf_abc_def", "xx_0123456789ab_" + secret, "cf_0123456789aB_" + secret, "cf_0123456789ab_short"} {
		if _, _, ok := ParseAPIKeyToken(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}
