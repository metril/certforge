package metrics

import (
	"testing"

	"github.com/metril/certforge/internal/settings"
)

// TestPrometheusRequiresTokenWhenEnabled covers Phase 6A Task 1's
// "prometheus" settings section (Shared contract, Settings row): bearerToken
// is required whenever enabled is true, either freshly sent or already
// stored (checkTokenRequired via AddUpdateCheck), and is the section's only
// secret key.
func TestPrometheusRequiresTokenWhenEnabled(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, ok := r.Section(SectionName)
	if !ok {
		t.Fatal("prometheus section not registered")
	}
	if err := sec.Validate(sec.Default); err != nil {
		t.Fatalf("default rejected: %v", err)
	}
	if got := sec.SecretKeys(); len(got) != 1 || got[0] != "bearerToken" {
		t.Fatalf("secret keys = %v, want [bearerToken]", got)
	}

	if err := sec.ValidateUpdate(nil, []byte(`{"enabled":true}`)); err == nil {
		t.Fatal("first save, enabled without token: accepted")
	}
	if err := sec.ValidateUpdate(nil, []byte(`{"enabled":true,"bearerToken":"0123456789abcdef"}`)); err != nil {
		t.Fatalf("first save, enabled with token: %v", err)
	}
	if err := sec.ValidateUpdate(nil, []byte(`{"enabled":false}`)); err != nil {
		t.Fatalf("first save, disabled: %v", err)
	}

	enabledStored := []byte(`{"enabled":true}`)
	if err := sec.ValidateUpdate(enabledStored, []byte(`{"enabled":true,"bearerToken":"__unchanged__"}`)); err != nil {
		t.Fatalf("stored token counts, __unchanged__: %v", err)
	}
	if err := sec.ValidateUpdate(enabledStored, []byte(`{"enabled":true}`)); err != nil {
		t.Fatalf("stored token counts, omitted: %v", err)
	}

	disabledStored := []byte(`{"enabled":false}`)
	if err := sec.ValidateUpdate(disabledStored, []byte(`{"enabled":true}`)); err == nil {
		t.Fatal("was disabled, enabling without a fresh token: accepted")
	}

	// batch-1 review finding 2: the schema's own minLength used to reject
	// {"enabled":true,"bearerToken":"__unchanged__"} at the plain schema
	// level (Validate), before ValidateUpdate — which is the only thing
	// that actually knows "__unchanged__" means "keep what's already
	// there" — ever got a look. Validate alone must now accept it...
	if err := sec.Validate([]byte(`{"enabled":true,"bearerToken":"__unchanged__"}`)); err != nil {
		t.Fatalf("Validate rejected __unchanged__ (schema minLength should be gone): %v", err)
	}
	// ...and the full pipeline (Validate then ValidateUpdate, same order
	// PutSectionTx runs them in) must also accept it once a token is
	// already stored.
	if err := sec.Validate([]byte(`{"enabled":true,"bearerToken":"__unchanged__"}`)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := sec.ValidateUpdate(enabledStored, []byte(`{"enabled":true,"bearerToken":"__unchanged__"}`)); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}

	// The 16-character minimum still applies, just to a fresh value, via
	// ValidateUpdate now instead of the schema.
	if err := sec.ValidateUpdate(nil, []byte(`{"enabled":true,"bearerToken":"short"}`)); err == nil {
		t.Fatal("fresh token under 16 characters: accepted")
	}
	if err := sec.Validate([]byte(`{"enabled":true,"bearerToken":"short"}`)); err != nil {
		t.Fatalf("Validate rejected a short token (minLength moved out of the schema): %v", err)
	}
}
