package issuance

import (
	"encoding/json"
	"testing"

	"github.com/metril/certforge/internal/settings"
)

func TestRegisterSettings(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, ok := r.Section(SettingsKey)
	if !ok {
		t.Fatal("section missing")
	}
	if err := sec.Validate([]byte(`{"keyType":"rsa4096","renewPolicy":{"mode":"days","value":30,"useAri":true},"propagationSeconds":300}`)); err != nil {
		t.Fatalf("valid value rejected: %v", err)
	}
	for _, bad := range []string{`{"keyType":"dsa"}`, `{"renewPolicy":{"mode":"weeks","value":1,"useAri":false}}`, `{"unknown":1}`} {
		if err := sec.Validate([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// Review Focus: percent mode must cap at 99 (100% of lifetime never renews);
// the same value is fine in days mode, where the schema's plain maximum is
// 365 regardless of mode.
func TestRegisterSettingsPercentCap(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.Section(SettingsKey)
	if err := sec.Validate([]byte(`{"renewPolicy":{"mode":"percent","value":100,"useAri":false}}`)); err == nil {
		t.Error("percent value 100 accepted")
	}
	if err := sec.Validate([]byte(`{"renewPolicy":{"mode":"percent","value":99,"useAri":false}}`)); err != nil {
		t.Errorf("percent value 99 rejected: %v", err)
	}
	if err := sec.Validate([]byte(`{"renewPolicy":{"mode":"days","value":100,"useAri":false}}`)); err != nil {
		t.Errorf("days value 100 rejected: %v", err)
	}
}

// TestIssuanceSettingsDefaults covers the "issuance" global settings
// section (Phase 4A Task 1): caaCheck defaults true, the four rate limits
// default to Let's Encrypt's own published limits, and the schema rejects a
// negative limit and an unknown top-level key.
func TestIssuanceSettingsDefaults(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterIssuanceSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, ok := r.Section(SettingsSectionIssuance)
	if !ok {
		t.Fatal("section missing")
	}
	var def IssuanceSettings
	if err := json.Unmarshal(sec.Default, &def); err != nil {
		t.Fatal(err)
	}
	want := IssuanceSettings{CAACheck: true, RateLimits: RateLimits{
		CertsPerRegisteredDomainPerWeek: 50, DuplicateCertsPerWeek: 5, FailedValidationsPerHour: 5, NewOrdersPer3Hours: 300,
	}}
	if def != want {
		t.Fatalf("default = %+v, want %+v", def, want)
	}
	if err := sec.Validate([]byte(`{"caaCheck":true,"rateLimits":{"certsPerRegisteredDomainPerWeek":50,"duplicateCertsPerWeek":5,"failedValidationsPerHour":5,"newOrdersPer3Hours":300}}`)); err != nil {
		t.Errorf("valid value rejected: %v", err)
	}
	for _, bad := range []string{
		`{"rateLimits":{"certsPerRegisteredDomainPerWeek":-1}}`,
		`{"unknown":1}`,
		`{"rateLimits":{"unknown":1}}`,
	} {
		if err := sec.Validate([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
