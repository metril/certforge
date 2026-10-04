package issuance

import "testing"

func TestVaultPKIRoleValidation(t *testing.T) {
	for role, ok := range map[string]bool{
		"my-role": true, "Role_1.x": true, "": false, "a/b": false, "a b": false,
		"..": false, "a..b": false, "r?x=1": false, "r%2F": false,
	} {
		err := vaultPKIConfig{Mount: "pki", Role: role}.validate()
		if (err == nil) != ok {
			t.Errorf("role %q: err = %v, want ok=%v", role, err, ok)
		}
	}
}
