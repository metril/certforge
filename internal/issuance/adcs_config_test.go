package issuance

import (
	"errors"
	"testing"
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
