//go:build integration

package api

import (
	"errors"
	"net/http"
	"testing"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/challenge"
)

type failingDNS struct{}

func (failingDNS) Present(string, string, string) error { return errors.New("403 from provider API") }
func (failingDNS) CleanUp(string, string, string) error { return nil }

func TestDNSCredentialResponseHasNoSecrets(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_API_EMAIL": "a@example.test", "CF_DNS_API_TOKEN": "t0p"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.CreateDNSCredential201JSONResponse)
	if _, leaked := c.Config["CF_DNS_API_TOKEN"]; leaked || c.StoredSecrets == nil || len(*c.StoredSecrets) != 1 || (*c.StoredSecrets)[0] != "CF_DNS_API_TOKEN" {
		t.Fatalf("credential = %+v", c)
	}
	if n := f.auditCount(t, "dns_credential.create"); n != 1 {
		t.Fatalf("dns_credential.create audit count = %d", n)
	}
}

func TestCreateDNSCredentialValidation(t *testing.T) {
	f := newAPIFixture(t)
	_, err := f.srv.CreateDNSCredential(f.as("viewer"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": "t"}}})
	wantStatus(t, err, http.StatusForbidden)
	_, err = f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "not-a-provider", Config: map[string]string{}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	_, err = f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"NOT_A_FIELD": "x"}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	_, err = f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": challenge.Unchanged}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

func TestListAndUpdateDNSCredential(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_API_EMAIL": "a@example.test", "CF_DNS_API_TOKEN": "t0p"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.CreateDNSCredential201JSONResponse)
	list, err := f.srv.ListDNSCredentials(f.as("viewer"), gen.ListDNSCredentialsRequestObject{OrgId: f.org})
	if err != nil || len(list.(gen.ListDNSCredentials200JSONResponse)) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	// __unchanged__ keeps the stored secret; the new email replaces the old.
	up, err := f.srv.UpdateDNSCredential(f.as("operator"), gen.UpdateDNSCredentialRequestObject{OrgId: f.org, Id: c.Id,
		Body: &gen.DNSCredentialUpdate{Name: "cf2", Config: map[string]string{"CF_API_EMAIL": "b@example.test", "CF_DNS_API_TOKEN": challenge.Unchanged}}})
	if err != nil {
		t.Fatal(err)
	}
	u := up.(gen.UpdateDNSCredential200JSONResponse)
	if u.Name != "cf2" || u.Config["CF_API_EMAIL"] != "b@example.test" || u.StoredSecrets == nil || len(*u.StoredSecrets) != 1 {
		t.Fatalf("updated = %+v", u)
	}
	if n := f.auditCount(t, "dns_credential.update"); n != 1 {
		t.Fatalf("dns_credential.update audit count = %d", n)
	}
	got, err := f.srv.GetDNSCredential(f.as("viewer"), gen.GetDNSCredentialRequestObject{OrgId: f.org, Id: c.Id})
	if err != nil || got.(gen.GetDNSCredential200JSONResponse).Name != "cf2" {
		t.Fatalf("get = %+v %v", got, err)
	}
}

func TestDeleteDNSCredentialAuditedAndBlockedWhileReferenced(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": "t"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.CreateDNSCredential201JSONResponse)
	secs := 60
	if _, err := f.srv.PutOrgIssuanceDefaults(f.as("operator"), gen.PutOrgIssuanceDefaultsRequestObject{OrgId: f.org,
		Body: &gen.IssuanceDefaults{PropagationSeconds: &secs, VerificationRules: &[]gen.VerificationRule{
			{Match: "example.test", Method: "dns-01", DnsCredentialId: &c.Id}}}}); err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.DeleteDNSCredential(f.as("operator"), gen.DeleteDNSCredentialRequestObject{OrgId: f.org, Id: c.Id})
	wantStatus(t, err, http.StatusConflict)

	// Clear the reference, then delete succeeds and is audited.
	if _, err := f.srv.PutOrgIssuanceDefaults(f.as("operator"), gen.PutOrgIssuanceDefaultsRequestObject{OrgId: f.org,
		Body: &gen.IssuanceDefaults{PropagationSeconds: &secs}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.DeleteDNSCredential(f.as("operator"), gen.DeleteDNSCredentialRequestObject{OrgId: f.org, Id: c.Id}); err != nil {
		t.Fatal(err)
	}
	if n := f.auditCount(t, "dns_credential.delete"); n != 1 {
		t.Fatalf("dns_credential.delete audit count = %d", n)
	}
	_, err = f.srv.GetDNSCredential(f.as("operator"), gen.GetDNSCredentialRequestObject{OrgId: f.org, Id: c.Id})
	wantStatus(t, err, http.StatusNotFound)
}

func TestTestDNSCredentialReportsProviderError(t *testing.T) {
	f := newAPIFixture(t)
	res, _ := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": "t"}}})
	id := res.(gen.CreateDNSCredential201JSONResponse).Id
	f.srv.d.Issuance.BuildDNS = func(string, map[string]string) (legochallenge.Provider, error) { return failingDNS{}, nil }
	out, err := f.srv.TestDNSCredential(f.as("operator"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	r := out.(gen.TestDNSCredential200JSONResponse)
	if r.Ok || r.Error == nil || r.Fqdn != "_acme-challenge._certforge-test.example.test" {
		t.Fatalf("result = %+v", r)
	}
	_, err = f.srv.TestDNSCredential(f.as("viewer"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	wantStatus(t, err, http.StatusForbidden)
}

func TestGlobalDefaultsRuleValidatesDNSCredential(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": "t"}}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDNSCredential201JSONResponse).Id

	// A missing dnsCredentialId is rejected (exercises ValidateGlobalDefaultsTx's
	// LockDNSCredentialKeyShare existence check).
	missing := uuid.New().String()
	_, err = f.srv.PutSettingsSection(f.as("admin"), gen.PutSettingsSectionRequestObject{Section: "issuance_defaults",
		Body: &gen.SettingsValue{"verificationRules": []map[string]any{{"match": "example.test", "method": "dns-01", "dnsCredentialId": missing}}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	// A real credential validates and stores.
	out, err := f.srv.PutSettingsSection(f.as("admin"), gen.PutSettingsSectionRequestObject{Section: "issuance_defaults",
		Body: &gen.SettingsValue{"verificationRules": []map[string]any{{"match": "example.test", "method": "dns-01", "dnsCredentialId": id.String()}}}})
	if err != nil {
		t.Fatal(err)
	}
	sec := out.(gen.PutSettingsSection200JSONResponse)
	rules, _ := sec.Value["verificationRules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("stored section = %+v", sec)
	}

	// Deleting the now globally-referenced credential is blocked.
	_, err = f.srv.DeleteDNSCredential(f.as("operator"), gen.DeleteDNSCredentialRequestObject{OrgId: f.org, Id: id})
	wantStatus(t, err, http.StatusConflict)
}

func TestTestDNSCredentialNotFoundAndInvalidZone(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": "t"}}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDNSCredential201JSONResponse).Id
	_, err = f.srv.TestDNSCredential(f.as("operator"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: ""}})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	missing := gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: uuid.New(), Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}}
	_, err = f.srv.TestDNSCredential(f.as("operator"), missing)
	wantStatus(t, err, http.StatusNotFound)
}
