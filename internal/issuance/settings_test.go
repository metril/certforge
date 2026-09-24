package issuance

import (
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
