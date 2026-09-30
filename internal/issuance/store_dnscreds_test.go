package issuance

import (
	"errors"
	"testing"

	"github.com/metril/certforge/internal/challenge"
)

func TestSplitErrNoAuthMethodIs422(t *testing.T) {
	_, _, err := challenge.SplitConfig("cloudflare", map[string]string{"CF_API_EMAIL": "e"})
	var ve *ValidationError
	if !errors.As(splitErr(err), &ve) || ve.Field != "config" {
		t.Fatalf("got %v", splitErr(err))
	}
}
