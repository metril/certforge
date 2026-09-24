//go:build integration

package issuance

import (
	"context"
	"errors"
	"testing"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/signer"
)

func TestCARequiresEABForPreset(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Zero", Preset: "zerossl"})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "eabKid" {
		t.Fatalf("err = %v", err)
	}
	hmac := "c2VjcmV0"
	ca, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Zero", Preset: "zerossl", EABKid: "kid", EABHmac: &hmac})
	if err != nil || !ca.HasEAB || ca.DirectoryURL != "https://acme.zerossl.com/v2/DV90" {
		t.Fatalf("ca = %+v err = %v", ca, err)
	}
	unchanged := challenge.Unchanged
	ca, err = f.store.UpdateCA(ctx, f.org, ca.ID, CAInput{Name: "ZeroSSL", Preset: "zerossl", EABKid: "kid", EABHmac: &unchanged})
	if err != nil || !ca.HasEAB {
		t.Fatalf("update kept EAB? %+v %v", ca, err)
	}
	eab, err := f.store.CAEAB(ctx, f.org, ca.ID)
	if err != nil || eab.HMAC != hmac {
		t.Fatalf("eab = %+v %v", eab, err)
	}
}

func TestDeleteCABlockedWhileReferenced(t *testing.T) {
	f := newFixture(t)
	var iu *InUseError
	if err := f.store.DeleteCA(context.Background(), f.org, f.ca.ID); !errors.As(err, &iu) {
		t.Fatalf("err = %v", err)
	}
}

func TestDNSCredentialSecretsAndSentinel(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, err := f.store.CreateDNSCredential(ctx, f.org, "cf", "cloudflare", map[string]string{"CF_API_EMAIL": "a@example.test", "CF_DNS_API_TOKEN": "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Public["CF_DNS_API_TOKEN"] != "" || len(c.StoredSecrets) != 1 {
		t.Fatalf("secret exposed or missing: %+v", c)
	}
	var raw []byte
	_ = f.pool.QueryRow(ctx, "SELECT secret_cfg FROM dns_provider_credentials WHERE id = $1", c.ID).Scan(&raw)
	if string(raw[:7]) != "sealed:" {
		t.Fatal("secret_cfg not sealed")
	}
	if _, err := f.store.UpdateDNSCredential(ctx, f.org, c.ID, "cf", map[string]string{"CF_API_EMAIL": "b@example.test", "CF_DNS_API_TOKEN": challenge.Unchanged}); err != nil {
		t.Fatal(err)
	}
	_, cfg, err := f.store.DNSCredentialConfig(ctx, f.org, c.ID)
	if err != nil || cfg["CF_DNS_API_TOKEN"] != "t1" || cfg["CF_API_EMAIL"] != "b@example.test" {
		t.Fatalf("cfg = %v err = %v", cfg, err)
	}
	var ve *ValidationError
	if _, err := f.store.CreateDNSCredential(ctx, f.org, "bad", "cloudflare", map[string]string{"PATH": "/x"}); !errors.As(err, &ve) {
		t.Fatalf("unknown field: %v", err)
	}
}

// Review Focus: splitErr must classify challenge package errors by type
// (errors.Is), not by matching substrings of Error().
func TestSplitErrClassifiesByType(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var ve *ValidationError

	// Unknown provider code: caught before SplitConfig even runs, by Lookup.
	if _, err := f.store.CreateDNSCredential(ctx, f.org, "x", "not-a-real-provider", map[string]string{}); !errors.As(err, &ve) || ve.Field != "providerCode" {
		t.Fatalf("unknown provider: %v", err)
	}
	// __unchanged__ sent on create: not an update, so there is nothing to keep.
	if _, err := f.store.CreateDNSCredential(ctx, f.org, "y", "cloudflare", map[string]string{"CF_DNS_API_TOKEN": challenge.Unchanged}); !errors.As(err, &ve) || ve.Field != "config" {
		t.Fatalf("unchanged on create: %v", err)
	}
}

func TestCertificateUsesCredentialAndReissuesOnNameChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred := f.credential(t, "cf")
	in := CertInput{Name: "web", CommonName: "Example.test", SANs: []string{"*.example.test"},
		Rules: []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &cred}}}
	c, err := f.store.CreateCertificate(ctx, f.org, in)
	if err != nil {
		t.Fatal(err)
	}
	if c.CommonName != "example.test" || c.NextRenewAt == nil || c.Status != StatusPending {
		t.Fatalf("cert = %+v", c)
	}
	var iu *InUseError
	if err := f.store.DeleteDNSCredential(ctx, f.org, cred); !errors.As(err, &iu) {
		t.Fatalf("credential delete not blocked: %v", err)
	}
	in.Name = "web2"
	if _, reissue, err := f.store.UpdateCertificate(ctx, f.org, c.ID, in); err != nil || reissue {
		t.Fatalf("rename must not reissue: %v %v", reissue, err)
	}
	in.SANs = append(in.SANs, "www.other.test")
	if _, reissue, _ := f.store.UpdateCertificate(ctx, f.org, c.ID, in); !reissue {
		t.Fatal("name change must reissue")
	}
}

// Review Focus (P34): a certificate's rule dnsCredentialId must belong to
// the caller's org; a credential from another org (same database, so it is
// genuinely reachable, just not this caller's) is rejected as if it did
// not exist.
func TestCertificateRuleCredentialMustBeInOrg(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	otherOrg := dbtest.Org(t, f.pool)
	foreignCred, err := f.store.CreateDNSCredential(ctx, otherOrg, "cf", "cloudflare", map[string]string{"CF_DNS_API_TOKEN": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	in := CertInput{Name: "web", CommonName: "example.test",
		Rules: []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &foreignCred.ID}}}
	var ve *ValidationError
	if _, err := f.store.CreateCertificate(ctx, f.org, in); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("err = %v", err)
	}
}

// Review Focus (P34): org defaults referencing another org's CA, account or
// DNS credential (rows that exist in the same database, just owned by a
// different org) are rejected with a typed ValidationError (422), not
// silently accepted.
func TestOrgDefaultsRejectForeignReferences(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var ve *ValidationError

	otherOrg := dbtest.Org(t, f.pool)
	foreignCA, err := f.store.CreateCA(ctx, otherOrg, CAInput{Name: "Foreign", Preset: "custom", DirectoryURL: "https://foreign.test/dir"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{CAID: &foreignCA.ID}); !errors.As(err, &ve) || ve.Field != "caId" {
		t.Fatalf("foreign caId: %v", err)
	}
	foreignAcct, err := f.store.InsertAccount(ctx, otherOrg, foreignCA.ID, signer.AccountMaterial{Email: "x@example.test", KeyPKCS8: []byte("k"), RegistrationURI: "https://foreign.test/acct/1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{AccountID: &foreignAcct.ID}); !errors.As(err, &ve) || ve.Field != "accountId" {
		t.Fatalf("foreign accountId: %v", err)
	}
	foreignCred, err := f.store.CreateDNSCredential(ctx, otherOrg, "cf", "cloudflare", map[string]string{"CF_DNS_API_TOKEN": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	rules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &foreignCred.ID}}
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{VerificationRules: &rules}); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("foreign rule credential: %v", err)
	}
	// An account that exists but belongs to a different CA than the one
	// named in the same write is also rejected.
	ca2, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Second", Preset: "custom", DirectoryURL: "https://second.test/dir"})
	if err != nil {
		t.Fatal(err)
	}
	acct := f.acct.ID
	ca2ID := ca2.ID
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{CAID: &ca2ID, AccountID: &acct}); !errors.As(err, &ve) || ve.Field != "accountId" {
		t.Fatalf("mismatched ca/account: %v", err)
	}
}

// Review Focus (P34): ValidateGlobalDefaults (used by the settings write
// path for PUT /settings/issuance_defaults) verifies that any referenced
// caId, accountId or rule dnsCredentialId row exists, and that an account
// referenced alongside a caId actually belongs to it.
func TestValidateGlobalDefaults(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var ve *ValidationError

	missing := f.ca.ID
	missing[0] ^= 0xFF // corrupt into an id that does not exist
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{CAID: &missing}); !errors.As(err, &ve) || ve.Field != "caId" {
		t.Fatalf("missing caId: %v", err)
	}

	ca, acct := f.ca.ID, f.acct.ID
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{CAID: &ca, AccountID: &acct}); err != nil {
		t.Fatalf("real refs rejected: %v", err)
	}

	cred := f.credential(t, "cf")
	rules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &cred}}
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{VerificationRules: &rules}); err != nil {
		t.Fatalf("real rule credential rejected: %v", err)
	}

	missingCred := cred
	missingCred[0] ^= 0xFF
	badRules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &missingCred}}
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{VerificationRules: &badRules}); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("missing rule credential: %v", err)
	}

	// A CA that exists (in another org: the global section is not org-scoped,
	// so existence is all ValidateGlobalDefaults can check) but is not the
	// account's own CA is still a mismatch.
	otherOrg := dbtest.Org(t, f.pool)
	wrongCA, err := f.store.CreateCA(ctx, otherOrg, CAInput{Name: "Other", Preset: "custom", DirectoryURL: "https://other.test/dir"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{CAID: &wrongCA.ID, AccountID: &acct}); !errors.As(err, &ve) || ve.Field != "accountId" {
		t.Fatalf("account/CA mismatch: %v", err)
	}

	// Percent renewPolicy over 99 is still rejected at the shape level.
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{RenewPolicy: &RenewPolicy{Mode: RenewPercent, Value: 100}}); !errors.As(err, &ve) {
		t.Fatalf("percent 100: %v", err)
	}
}

// Review Focus (P34): CountCAUsers etc. only see org-scoped rows
// (certificates, issuance_defaults); a CA, account or DNS credential still
// referenced by the global issuance_defaults settings section must also be
// protected from deletion.
func TestDeleteBlockedByGlobalDefaultsReference(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	ca2, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Global", Preset: "custom", DirectoryURL: "https://global.test/dir"})
	if err != nil {
		t.Fatal(err)
	}
	cred := f.credential(t, "globalcred")
	globalCAID := ca2.ID
	rules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &cred}}
	f.store.global = fakeGlobal{d: Defaults{CAID: &globalCAID, VerificationRules: &rules}}

	var iu *InUseError
	if err := f.store.DeleteCA(ctx, f.org, ca2.ID); !errors.As(err, &iu) {
		t.Fatalf("CA referenced by global defaults not blocked: %v", err)
	}
	if err := f.store.DeleteDNSCredential(ctx, f.org, cred); !errors.As(err, &iu) {
		t.Fatalf("credential referenced by global defaults not blocked: %v", err)
	}
}

func TestEffectiveOrgSources(t *testing.T) {
	f := newFixture(t)
	f.store.global = fakeGlobal{d: Defaults{PropagationSeconds: ptr(300)}}
	e, err := f.store.EffectiveOrg(context.Background(), f.org)
	if err != nil {
		t.Fatal(err)
	}
	if e.CAID.Source != SourceOrg || e.PropagationSeconds.Value != 300 || e.PropagationSeconds.Source != SourceGlobal {
		t.Fatalf("effective = %+v", e)
	}
}

func ptr[T any](v T) *T { return &v }
