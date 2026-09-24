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
