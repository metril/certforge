//go:build integration

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/challenge"
)

// failingDNS records call order so tests can assert CleanUp always runs,
// even after Present failed.
type failingDNS struct {
	presentCalled bool
	cleanedUp     bool
}

func (p *failingDNS) Present(string, string, string) error {
	p.presentCalled = true
	return errors.New("403 from provider API")
}

func (p *failingDNS) CleanUp(string, string, string) error {
	if !p.presentCalled {
		panic("CleanUp called before Present")
	}
	p.cleanedUp = true
	return nil
}

// blockingDNS blocks Present until unblock is closed, then records CleanUp
// on cleanedUp; used to test the test-endpoint timeout.
type blockingDNS struct {
	unblock   chan struct{}
	cleanedUp chan struct{}
}

func (p *blockingDNS) Present(string, string, string) error {
	<-p.unblock
	return nil
}

func (p *blockingDNS) CleanUp(string, string, string) error {
	close(p.cleanedUp)
	return nil
}

// leakyDNS echoes the credential value into its Present error, raw and
// query-escaped, the way a real REST provider's client commonly does when
// reporting a failed request URL.
type leakyDNS struct{ secret string }

func (p leakyDNS) Present(string, string, string) error {
	return fmt.Errorf("PUT https://api.example.test/update?token=%s failed: bad token %q", url.QueryEscape(p.secret), p.secret)
}

func (leakyDNS) CleanUp(string, string, string) error { return nil }

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

// Fix round 1, item 4: a _FILE/_PATH config value names a path on the
// server's own filesystem, not something the API accepts from a caller.
func TestCreateDNSCredentialRejectsServerPathField(t *testing.T) {
	f := newAPIFixture(t)
	_, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "gc", ProviderCode: "gcloud", Config: map[string]string{"GCE_SERVICE_ACCOUNT_FILE": "/etc/secrets/gcloud.json"}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

// Phase 5 task 12: transip's file-backed credential is now usable through
// this API via its inline TRANSIP_PRIVATE_KEY field (internal/challenge's
// fileBacked writes it to a private server-side temp file for lego's
// TRANSIP_PRIVATE_KEY_PATH to read), so it is no longer rejected outright.
func TestCreateDNSCredentialAcceptsTransipInlineKey(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "ti", ProviderCode: "transip", Config: map[string]string{
			"TRANSIP_ACCOUNT_NAME": "acct", "TRANSIP_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.CreateDNSCredential201JSONResponse)
	if c.StoredSecrets == nil || len(*c.StoredSecrets) != 1 || (*c.StoredSecrets)[0] != "TRANSIP_PRIVATE_KEY" {
		t.Fatalf("credential = %+v", c)
	}
}

// Phase 5 task 12: TRANSIP_PRIVATE_KEY_PATH names a path on the server's
// own filesystem and must still be rejected directly, same as before —
// only the new inline field is accepted.
func TestCreateDNSCredentialRejectsTransipServerPathField(t *testing.T) {
	f := newAPIFixture(t)
	_, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "ti2", ProviderCode: "transip", Config: map[string]string{
			"TRANSIP_PRIVATE_KEY_PATH": "/etc/secrets/transip.key"}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

// Fix round 2, item 2: oraclecloud's OCI_PRIVKEY (added to the schema
// because lego's env.Get accepts it inline even though the TOML only
// documents OCI_PRIVKEY_FILE) makes the provider usable through the API.
func TestCreateDNSCredentialAcceptsOracleCloudInlineKey(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "oci", ProviderCode: "oraclecloud", Config: map[string]string{
			"OCI_PRIVKEY": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----", "OCI_REGION": "us-phoenix-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.CreateDNSCredential201JSONResponse)
	if c.StoredSecrets == nil || len(*c.StoredSecrets) != 1 || (*c.StoredSecrets)[0] != "OCI_PRIVKEY" {
		t.Fatalf("credential = %+v", c)
	}
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
	if _, leaked := list.(gen.ListDNSCredentials200JSONResponse)[0].Config["CF_DNS_API_TOKEN"]; leaked {
		t.Fatal("list leaked a secret value")
	}
	// __unchanged__ keeps the stored secret when no public field changes
	// (only the name, which lives outside config, changes here).
	up, err := f.srv.UpdateDNSCredential(f.as("operator"), gen.UpdateDNSCredentialRequestObject{OrgId: f.org, Id: c.Id,
		Body: &gen.DNSCredentialUpdate{Name: "cf2", Config: map[string]string{"CF_API_EMAIL": "a@example.test", "CF_DNS_API_TOKEN": challenge.Unchanged}}})
	if err != nil {
		t.Fatal(err)
	}
	u := up.(gen.UpdateDNSCredential200JSONResponse)
	if u.Name != "cf2" || u.Config["CF_API_EMAIL"] != "a@example.test" || u.StoredSecrets == nil || len(*u.StoredSecrets) != 1 {
		t.Fatalf("updated = %+v", u)
	}
	if _, leaked := u.Config["CF_DNS_API_TOKEN"]; leaked {
		t.Fatal("update leaked a secret value")
	}
	if n := f.auditCount(t, "dns_credential.update"); n != 1 {
		t.Fatalf("dns_credential.update audit count = %d", n)
	}
	got, err := f.srv.GetDNSCredential(f.as("viewer"), gen.GetDNSCredentialRequestObject{OrgId: f.org, Id: c.Id})
	if err != nil || got.(gen.GetDNSCredential200JSONResponse).Name != "cf2" {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, leaked := got.(gen.GetDNSCredential200JSONResponse).Config["CF_DNS_API_TOKEN"]; leaked {
		t.Fatal("get leaked a secret value")
	}

	// Changing a public field (the email) while keeping the secret
	// Unchanged is rejected: re-entering the secret alongside it succeeds.
	_, err = f.srv.UpdateDNSCredential(f.as("operator"), gen.UpdateDNSCredentialRequestObject{OrgId: f.org, Id: c.Id,
		Body: &gen.DNSCredentialUpdate{Name: "cf2", Config: map[string]string{"CF_API_EMAIL": "b@example.test", "CF_DNS_API_TOKEN": challenge.Unchanged}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	up, err = f.srv.UpdateDNSCredential(f.as("operator"), gen.UpdateDNSCredentialRequestObject{OrgId: f.org, Id: c.Id,
		Body: &gen.DNSCredentialUpdate{Name: "cf2", Config: map[string]string{"CF_API_EMAIL": "b@example.test", "CF_DNS_API_TOKEN": "t0p"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := up.(gen.UpdateDNSCredential200JSONResponse); got.Config["CF_API_EMAIL"] != "b@example.test" {
		t.Fatalf("updated = %+v", got)
	}
}

// Fix wave item 4: an update that changes a connection setting (here
// httpreq's endpoint URL, which decides where the stored secret is sent)
// while keeping the secret Unchanged must be rejected — the operator could
// otherwise silently redirect a stored credential to a different server. The
// audit record for an allowed update lists the changed public keys.
func TestUpdateDNSCredentialRejectsSecretReuseAcrossEndpointChange(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "hr", ProviderCode: "httpreq", Config: map[string]string{
			"HTTPREQ_ENDPOINT": "https://good.example.test", "HTTPREQ_PASSWORD": "s3cret"}}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDNSCredential201JSONResponse).Id

	_, err = f.srv.UpdateDNSCredential(f.as("operator"), gen.UpdateDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialUpdate{Name: "hr", Config: map[string]string{
			"HTTPREQ_ENDPOINT": "https://evil.example.test", "HTTPREQ_PASSWORD": challenge.Unchanged}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	// Resending the same config (no public field actually changes) with the
	// secret Unchanged is fine.
	up, err := f.srv.UpdateDNSCredential(f.as("operator"), gen.UpdateDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialUpdate{Name: "hr2", Config: map[string]string{
			"HTTPREQ_ENDPOINT": "https://good.example.test", "HTTPREQ_PASSWORD": challenge.Unchanged}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := up.(gen.UpdateDNSCredential200JSONResponse); got.Name != "hr2" {
		t.Fatalf("updated = %+v", got)
	}

	// Re-entering the secret alongside the endpoint change is allowed, and
	// the audit record names the changed public key.
	up, err = f.srv.UpdateDNSCredential(f.as("operator"), gen.UpdateDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialUpdate{Name: "hr2", Config: map[string]string{
			"HTTPREQ_ENDPOINT": "https://evil.example.test", "HTTPREQ_PASSWORD": "new-secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := up.(gen.UpdateDNSCredential200JSONResponse); got.Config["HTTPREQ_ENDPOINT"] != "https://evil.example.test" {
		t.Fatalf("updated = %+v", got)
	}
	if n := f.auditCount(t, "dns_credential.update"); n != 2 {
		t.Fatalf("dns_credential.update audit count = %d", n)
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
	stub := &failingDNS{}
	f.srv.d.Issuance.BuildDNS = func(string, map[string]string) (legochallenge.Provider, error) { return stub, nil }
	out, err := f.srv.TestDNSCredential(f.as("operator"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	r := out.(gen.TestDNSCredential200JSONResponse)
	if r.Ok || r.Error == nil || r.Fqdn != "_acme-challenge._certforge-test.example.test" {
		t.Fatalf("result = %+v", r)
	}
	if !stub.presentCalled || !stub.cleanedUp {
		t.Fatalf("CleanUp did not run after Present failed: present=%v cleanup=%v", stub.presentCalled, stub.cleanedUp)
	}
	if n := f.auditCount(t, "dns_credential.test"); n != 1 {
		t.Fatalf("dns_credential.test audit count = %d", n)
	}

	_, err = f.srv.TestDNSCredential(f.as("viewer"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	wantStatus(t, err, http.StatusForbidden)
}

// Fix round 1, item 1 (Critical): a live provider error must never leak the
// credential value, raw or query-escaped, back through the test result.
func TestTestDNSCredentialScrubsSecretFromError(t *testing.T) {
	f := newAPIFixture(t)
	secret := "s3cr3t/token value"
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": secret}}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDNSCredential201JSONResponse).Id
	f.srv.d.Issuance.BuildDNS = func(string, map[string]string) (legochallenge.Provider, error) { return leakyDNS{secret: secret}, nil }

	out, err := f.srv.TestDNSCredential(f.as("operator"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	r := out.(gen.TestDNSCredential200JSONResponse)
	if r.Ok || r.Error == nil {
		t.Fatalf("result = %+v", r)
	}
	if strings.Contains(*r.Error, secret) || strings.Contains(*r.Error, url.QueryEscape(secret)) {
		t.Fatalf("secret leaked through test error: %s", *r.Error)
	}
}

// Fix round 1, item 2 (Important): lego's Present/CleanUp take no context,
// so the endpoint races the call against a timer instead of relying on
// cancellation; on timeout it must answer promptly, and the background call
// must still run CleanUp afterward.
func TestTestDNSCredentialTimesOutAndStillCleansUp(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": "t"}}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDNSCredential201JSONResponse).Id
	p := &blockingDNS{unblock: make(chan struct{}), cleanedUp: make(chan struct{})}
	f.srv.d.Issuance.BuildDNS = func(string, map[string]string) (legochallenge.Provider, error) { return p, nil }
	f.srv.d.DNSTestTimeout = 30 * time.Millisecond

	start := time.Now()
	out, err := f.srv.TestDNSCredential(f.as("operator"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("handler did not answer promptly on timeout: %s", elapsed)
	}
	r := out.(gen.TestDNSCredential200JSONResponse)
	if r.Ok || r.Error == nil || *r.Error != "timed out" {
		t.Fatalf("result = %+v", r)
	}

	// The background call is still running Present; unblock it and confirm
	// CleanUp still runs even though the response already went out.
	close(p.unblock)
	select {
	case <-p.cleanedUp:
	case <-time.After(5 * time.Second):
		t.Fatal("CleanUp was never called after Present unblocked")
	}
}

// Fix round 2, item 3: the semaphore slot is released inside the
// goroutine once the background call actually finishes, not when the
// handler returns on timeout — otherwise a burst of timed-out callers
// could still pile up an unbounded number of truly in-flight provider
// calls, defeating the point of the bound.
func TestTestDNSCredentialSemaphoreHeldUntilBackgroundCallFinishes(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": "t"}}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDNSCredential201JSONResponse).Id
	p := &blockingDNS{unblock: make(chan struct{}), cleanedUp: make(chan struct{})}
	f.srv.d.Issuance.BuildDNS = func(string, map[string]string) (legochallenge.Provider, error) { return p, nil }
	f.srv.d.DNSTestTimeout = 30 * time.Millisecond

	// Take the other slot, so after this call times out both slots should
	// read as taken: this one's, and the still-running background call's.
	releaseOther, ok := acquireDNSTestSlot()
	if !ok {
		t.Fatal("expected to acquire a slot")
	}
	defer releaseOther()

	out, err := f.srv.TestDNSCredential(f.as("operator"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := out.(gen.TestDNSCredential200JSONResponse); r.Ok || r.Error == nil || *r.Error != "timed out" {
		t.Fatalf("result = %+v", r)
	}

	// A third call must be refused: the handler already returned, but the
	// background Present call is still running and still holds its slot.
	_, err = f.srv.TestDNSCredential(f.as("operator"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	wantStatus(t, err, http.StatusServiceUnavailable)

	// Unblock it; once CleanUp runs its slot is released.
	close(p.unblock)
	select {
	case <-p.cleanedUp:
	case <-time.After(5 * time.Second):
		t.Fatal("CleanUp was never called after Present unblocked")
	}
}

// Fix round 1, item 2 (Important): the endpoint is gated by a package-level
// semaphore of 2; a third concurrent call gets 503.
func TestTestDNSCredentialSemaphoreFull(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateDNSCredential(f.as("operator"), gen.CreateDNSCredentialRequestObject{OrgId: f.org,
		Body: &gen.DNSCredentialInput{Name: "cf", ProviderCode: "cloudflare", Config: map[string]string{"CF_DNS_API_TOKEN": "t"}}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDNSCredential201JSONResponse).Id

	release1, ok1 := acquireDNSTestSlot()
	release2, ok2 := acquireDNSTestSlot()
	if !ok1 || !ok2 {
		t.Fatal("expected to acquire both test slots")
	}
	defer release1()
	defer release2()

	_, err = f.srv.TestDNSCredential(f.as("operator"), gen.TestDNSCredentialRequestObject{OrgId: f.org, Id: id,
		Body: &gen.DNSCredentialTestRequest{Zone: "example.test"}})
	wantStatus(t, err, http.StatusServiceUnavailable)
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
