//go:build integration

package issuance

import (
	"bytes"
	"context"
	"testing"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/settings"
)

func testEnvelope(b byte) *crypto.Envelope {
	k := bytes.Repeat([]byte{b}, 32)
	return crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(k), k))
}

// TestLoadIssuanceSettingsPartialDocument covers review fix round 1
// (internal/issuance/settings.go:76): the "issuance" section's schema has
// no "required", and a PUT replaces the whole stored document, so a caller
// that saves a partial value (here, only rateLimits.certsPerRegisteredDomainPerWeek)
// must still get every other field's built-in default back — not that
// field's Go zero value, which would silently turn caaCheck off and every
// other rate limit to 0 (unlimited).
func TestLoadIssuanceSettingsPartialDocument(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	store := settings.NewStore(q, testEnvelope(7))

	partial := map[string]any{"rateLimits": map[string]any{"certsPerRegisteredDomainPerWeek": 10}}
	if err := store.Set(ctx, settings.SectionKey(SettingsSectionIssuance), partial); err != nil {
		t.Fatal(err)
	}

	got, err := LoadIssuanceSettings(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	want := defaultIssuanceSettings()
	want.RateLimits.CertsPerRegisteredDomainPerWeek = 10
	if got != want {
		t.Fatalf("LoadIssuanceSettings = %+v, want %+v", got, want)
	}

	// A bare {} (every field omitted) must round-trip to every default,
	// including caaCheck staying true rather than silently turning off.
	if err := store.Set(ctx, settings.SectionKey(SettingsSectionIssuance), map[string]any{}); err != nil {
		t.Fatal(err)
	}
	got, err = LoadIssuanceSettings(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if got != defaultIssuanceSettings() {
		t.Fatalf("LoadIssuanceSettings on {} = %+v, want defaults %+v", got, defaultIssuanceSettings())
	}
}
