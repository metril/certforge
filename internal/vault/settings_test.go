package vault

import (
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
