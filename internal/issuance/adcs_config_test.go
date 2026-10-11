package issuance

import (
	"errors"
	"testing"

	"github.com/metril/certforge/internal/signer/adcs"
)

func TestADCSConfigValidation(t *testing.T) {
	ok := map[string]any{"cepUrl": "https://ca.test/cep", "template": "Web", "username": "svc"}
	cfg, err := parseADCSInput(ok)
	if err != nil || cfg.TimeoutSeconds != 30 || cfg.validate() != nil {
		t.Fatalf("defaults: %+v, %v / %v", cfg, err, cfg.validate())
	}
	bad := []map[string]any{
		{"cepUrl": "http://ca.test/cep", "template": "Web", "username": "svc"},
		{"cepUrl": "https://ca.test/cep", "cesUrl": "ftp://x", "template": "Web", "username": "svc"},
		{"cepUrl": "https://ca.test/cep", "username": "svc"},
		{"cepUrl": "https://ca.test/cep", "template": "Web"},
		{"cepUrl": "https://ca.test/cep", "template": "Web", "username": "svc", "timeoutSeconds": 4},
		{"cepUrl": "https://ca.test/cep", "template": "Web", "username": "svc", "timeoutSeconds": 301},
	}
	for i, raw := range bad {
		c, err := parseADCSInput(raw)
		if err == nil {
			err = c.validate()
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("case %d: err = %v, want ValidationError", i, err)
		}
	}
}

func TestNonRetryable(t *testing.T) {
	err := nonRetryable(adcs.ErrPending{RequestID: "77"})
	var nr *nonRetryableError
	if !errors.As(err, &nr) || err.Error() != "approve request 77 in AD CS, then renew" {
		t.Fatalf("pending = %v", err)
	}
	err = nonRetryable(adcs.ErrDenied{Disposition: "Denied by Policy Module"})
	if !errors.As(err, &nr) || err.Error() != "AD CS denied the request: Denied by Policy Module" {
		t.Fatalf("denied = %v", err)
	}
	plain := errors.New("boom")
	if nonRetryable(plain) != plain {
		t.Fatal("plain error must pass through")
	}
}
