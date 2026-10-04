package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/signer"
)

// TestMapErrSignerHidesTransportError covers S14: the 502 for a CA failure
// carries the signer error's detail and problem type, never the wrapped
// transport error (which can name the Vault address).
func TestMapErrSignerHidesTransportError(t *testing.T) {
	se := &signer.Error{Type: "urn:ietf:params:acme:error:rateLimited", Detail: "too many requests",
		Err: errors.New(`Post "https://vault.internal.example:8200/v1/pki/sign/x": dial tcp 10.0.0.5:8200: connection refused`)}
	var he *HTTPError
	if err := mapErr(se); !errors.As(err, &he) || he.Status != http.StatusBadGateway {
		t.Fatalf("err = %#v", err)
	}
	if strings.Contains(he.Detail, "vault.internal") || strings.Contains(he.Detail, "10.0.0.5") {
		t.Fatalf("detail leaks the transport error: %q", he.Detail)
	}
	if he.Detail != "too many requests (rateLimited)" {
		t.Fatalf("detail = %q", he.Detail)
	}
	if err := mapErr(&signer.Error{Err: errors.New("dial tcp 10.0.0.5:8200")}); !errors.As(err, &he) || strings.Contains(he.Detail, "10.0.0.5") {
		t.Fatalf("detail leaks the transport error: %v", err)
	}
}
