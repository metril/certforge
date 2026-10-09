//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/metril/certforge/internal/api/gen"
)

// Ambient auth (the server's own cloud identity) and role/profile delegation
// are reserved for a global settings:write holder.
func TestDNSCredentialAmbientNeedsGlobalSettingsWrite(t *testing.T) {
	f := newAPIFixture(t)
	keys := map[string]string{"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b"}
	with := func(extra string) map[string]string {
		m := map[string]string{"AWS_ASSUME_ROLE_ARN": "arn:aws:iam::1:role/x"}
		if extra == "profile" {
			m = map[string]string{"AWS_PROFILE": "p"}
		}
		for k, v := range keys {
			m[k] = v
		}
		return m
	}
	create := func(role, name string, cfg map[string]string) error {
		_, err := f.srv.CreateDNSCredential(f.as(role), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
			Body: &gen.DNSCredentialInput{Name: name, ProviderCode: "route53", Config: cfg}})
		return err
	}
	wantStatus(t, create("org-admin", "amb", map[string]string{}), http.StatusUnprocessableEntity)
	wantStatus(t, create("org-admin", "role", with("role")), http.StatusUnprocessableEntity)
	wantStatus(t, create("org-admin", "prof", with("profile")), http.StatusUnprocessableEntity)
	if err := create("org-admin", "keys", keys); err != nil {
		t.Fatalf("explicit keys: %v", err)
	}
	if err := create("admin", "amb", map[string]string{}); err != nil {
		t.Fatalf("global admin ambient: %v", err)
	}
	if err := create("admin", "role", with("role")); err != nil {
		t.Fatalf("global admin assume role: %v", err)
	}
}
