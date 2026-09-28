package vault

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/metril/certforge/internal/settings"
)

// TestVaultSettingsSchema covers Phase 5A Task 1's "vault" settings section:
// the defaults validate, an authMethod/secret mismatch is rejected, the
// timeout bounds are enforced, and token/secretId are the section's secret
// properties (Shared contract, Settings row).
func TestVaultSettingsSchema(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, ok := r.Section(SectionName)
	if !ok {
		t.Fatal("vault section not registered")
	}

	if err := sec.Validate(sec.Default); err != nil {
		t.Fatalf("default rejected: %v", err)
	}

	if got := sec.SecretKeys(); !slices.Equal(got, []string{"secretId", "token"}) {
		t.Fatalf("secret keys = %v, want [secretId token]", got)
	}

	for name, bad := range map[string]string{
		"token without authMethod token":  `{"address":"https://vault.test:8200","authMethod":"approle","token":"t"}`,
		"roleId/secretId without approle": `{"address":"https://vault.test:8200","roleId":"r","secretId":"s"}`,
		"timeoutSeconds 0":                `{"address":"https://vault.test:8200","timeoutSeconds":0}`,
		"timeoutSeconds 61":               `{"address":"https://vault.test:8200","timeoutSeconds":61}`,
		"namespace without address":       `{"namespace":"ns"}`,
	} {
		if err := sec.Validate([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	for name, ok := range map[string]string{
		"address alone":                `{"address":"https://vault.test:8200"}`,
		"token with authMethod":        `{"address":"https://vault.test:8200","authMethod":"token","token":"t"}`,
		"approle with roleId/secretId": `{"address":"https://vault.test:8200","authMethod":"approle","roleId":"r","secretId":"s"}`,
		"timeoutSeconds bounds":        `{"address":"https://vault.test:8200","timeoutSeconds":60}`,
	} {
		if err := sec.Validate([]byte(ok)); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}

// TestVaultSettingsReentry covers checkReentry (pre-flight ruling): first
// save is always allowed; once address/namespace is stored, a PUT that
// keeps them unchanged may omit or send "__unchanged__" for the active
// method's secret, but a PUT that changes either one must re-send it.
func TestVaultSettingsReentry(t *testing.T) {
	sec, ok := func() (*settings.Section, bool) {
		r := settings.NewRegistry()
		if err := RegisterSettings(r); err != nil {
			t.Fatal(err)
		}
		return r.Section(SectionName)
	}()
	if !ok {
		t.Fatal("vault section not registered")
	}

	stored := json.RawMessage(`{"address":"https://vault.test:8200","authMethod":"token"}`)

	if err := sec.ValidateUpdate(nil, []byte(`{"address":"https://vault.test:8200","authMethod":"token"}`)); err != nil {
		t.Fatalf("first save rejected: %v", err)
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"address":"https://vault.test:8200","authMethod":"token"}`)); err != nil {
		t.Fatalf("unchanged address, no token: %v", err)
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"address":"https://vault.test:8200","authMethod":"token","token":"__unchanged__"}`)); err != nil {
		t.Fatalf("unchanged address, __unchanged__ token: %v", err)
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"address":"https://other.test:8200","authMethod":"token"}`)); err == nil {
		t.Fatal("changed address, omitted token: accepted")
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"address":"https://other.test:8200","authMethod":"token","token":"__unchanged__"}`)); err == nil {
		t.Fatal("changed address, __unchanged__ token: accepted")
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"address":"https://other.test:8200","authMethod":"token","token":"t2"}`)); err != nil {
		t.Fatalf("changed address, fresh token: %v", err)
	}
	if err := sec.ValidateUpdate(stored, []byte(`{"address":"https://vault.test:8200","namespace":"ns","authMethod":"token"}`)); err == nil {
		t.Fatal("changed namespace, omitted token: accepted")
	}

	approleStored := json.RawMessage(`{"address":"https://vault.test:8200","authMethod":"approle"}`)
	if err := sec.ValidateUpdate(approleStored, []byte(`{"address":"https://other.test:8200","authMethod":"approle","roleId":"r"}`)); err == nil {
		t.Fatal("approle, changed address, omitted secretId: accepted")
	}
	if err := sec.ValidateUpdate(approleStored, []byte(`{"address":"https://other.test:8200","authMethod":"approle","roleId":"r","secretId":"s2"}`)); err != nil {
		t.Fatalf("approle, changed address, fresh secretId: %v", err)
	}
}
