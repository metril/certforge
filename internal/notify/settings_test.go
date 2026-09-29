package notify

import (
	"errors"
	"testing"

	"github.com/metril/certforge/internal/settings"
)

// TestSMTPSettingsSchema covers Phase 6A Task 1's "smtp" settings section
// (Shared contract, Settings row): the defaults validate, a username paired
// with security "none" is rejected, a host/port change without a fresh
// password is rejected, and password is the section's only secret key.
func TestSMTPSettingsSchema(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, ok := r.Section(SMTPSectionName)
	if !ok {
		t.Fatal("smtp section not registered")
	}

	if err := sec.Validate(sec.Default); err != nil {
		t.Fatalf("default rejected: %v", err)
	}
	if got := sec.SecretKeys(); len(got) != 1 || got[0] != "password" {
		t.Fatalf("secret keys = %v, want [password]", got)
	}

	if err := sec.Validate([]byte(`{"host":"smtp.example.test","port":587,"username":"ops","security":"none","from":"a@example.test"}`)); err == nil {
		t.Fatal("username with security none: accepted")
	}
	if err := sec.Validate([]byte(`{"host":"smtp.example.test","from":"a@example.test"}`)); err != nil {
		t.Fatalf("host with from: rejected: %v", err)
	}
	if err := sec.Validate([]byte(`{"host":"smtp.example.test"}`)); err == nil {
		t.Fatal("host without from: accepted")
	}

	stored := []byte(`{"host":"smtp.example.test","port":587,"security":"starttls","timeoutSeconds":10}`)
	if err := sec.ValidateUpdate(nil, []byte(`{"host":"smtp.example.test","from":"a@example.test"}`)); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"host":"smtp.example.test","port":587,"security":"starttls","timeoutSeconds":10}`)); err != nil {
		t.Fatalf("unchanged host/port, no password: %v", err)
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"host":"smtp.example.test","port":587,"security":"starttls","timeoutSeconds":10,"password":"__unchanged__"}`)); err != nil {
		t.Fatalf("unchanged host/port, __unchanged__ password: %v", err)
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"host":"other.example.test","port":587,"security":"starttls","timeoutSeconds":10}`)); err == nil {
		t.Fatal("changed host, omitted password: accepted")
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"host":"other.example.test","port":587,"security":"starttls","timeoutSeconds":10,"password":"__unchanged__"}`)); err == nil {
		t.Fatal("changed host, __unchanged__ password: accepted")
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"host":"other.example.test","port":587,"security":"starttls","timeoutSeconds":10,"password":"p2"}`)); err != nil {
		t.Fatalf("changed host, fresh password: %v", err)
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"host":"smtp.example.test","port":2525,"security":"starttls","timeoutSeconds":10}`)); err == nil {
		t.Fatal("changed port, omitted password: accepted")
	}
}

// TestNotificationsSettingsBounds covers the "notifications" settings
// section: the defaults validate and expiryWarningDays/failureThreshold are
// bounded.
func TestNotificationsSettingsBounds(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, ok := r.Section(SectionName)
	if !ok {
		t.Fatal("notifications section not registered")
	}
	if err := sec.Validate(sec.Default); err != nil {
		t.Fatalf("default rejected: %v", err)
	}
	for name, bad := range map[string]string{
		"expiryWarningDays 0":  `{"expiryWarningDays":0}`,
		"expiryWarningDays 61": `{"expiryWarningDays":61}`,
		"failureThreshold 0":   `{"failureThreshold":0}`,
		"failureThreshold 11":  `{"failureThreshold":11}`,
	} {
		if err := sec.Validate([]byte(bad)); !errors.Is(err, settings.ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := sec.Validate([]byte(`{"allowLoopbackUrls":true,"expiryWarningDays":60,"failureThreshold":10}`)); err != nil {
		t.Fatalf("bounds ok: %v", err)
	}
}
