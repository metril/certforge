package issuance

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/signer/adcs"
)

func TestADCSAuthMessage(t *testing.T) {
	const lead = "authentication to the enrollment policy service failed"
	with := fmt.Errorf("wrapped: %w", &adcs.AuthError{Detail: "FailedAuthentication: nope", Hint: adcs.UsernameHint("svc")})
	if got, want := adcsAuthMessage(with), lead+` (FailedAuthentication: nope; use DOMAIN\user or user@domain)`; got != want {
		t.Errorf("with hint: %q", got)
	}
	without := &adcs.AuthError{Detail: "http 401", Hint: adcs.UsernameHint(`CORP\svc`)}
	if got, want := adcsAuthMessage(without), lead+" (http 401)"; got != want || strings.Contains(got, "DOMAIN") {
		t.Errorf("without hint: %q", got)
	}
	if got := adcsAuthMessage(adcs.ErrAuth); got != lead {
		t.Errorf("bare: %q", got)
	}
}

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
