package challenge

import (
	"errors"
	"os"
	"testing"

	legochallenge "github.com/go-acme/lego/v4/challenge"
)

func azureKeys(method string) map[string]string {
	c := map[string]string{"AZURE_CLIENT_ID": "i", "AZURE_CLIENT_SECRET": "s", "AZURE_TENANT_ID": "t",
		"AZURE_SUBSCRIPTION_ID": "u", "AZURE_RESOURCE_GROUP": "r"}
	if method != "" {
		c["AZURE_AUTH_METHOD"] = method
	}
	return c
}

func TestCheckNoAmbientAzureAuthMethod(t *testing.T) {
	for m, bad := range map[string]bool{"env": false, "ENV": false, "msi": true, "cli": true, "wli": true} {
		err := CheckNoAmbient("azuredns", azureKeys(m), nil)
		if bad != errors.Is(err, ErrAmbientCredentials) {
			t.Errorf("%s: err=%v want bad=%v", m, err, bad)
		}
	}
}

func TestBuildForcesAzureEnvAuth(t *testing.T) {
	orig := newByName
	t.Cleanup(func() { newByName = orig })
	got := "unset"
	newByName = func(string) (legochallenge.Provider, error) {
		got = os.Getenv("AZURE_AUTH_METHOD")
		return envCapture{}, nil
	}
	if _, err := Build("azuredns", azureKeys("")); err != nil {
		t.Fatal(err)
	}
	if got != "env" {
		t.Fatalf("AZURE_AUTH_METHOD = %q, want env", got)
	}
}
