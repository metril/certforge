//go:build integration

package issuance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
)

// Review Focus (fix round 1): reference validation must map only
// ErrNotFound/pgx.ErrNoRows to a ValidationError; any other lookup error
// (DB outage, cancelled context) must come back unchanged, not be reported
// as "no such CA".
func TestReferenceValidationPropagatesNonNotFoundErrors(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	ca, acct := f.ca.ID, f.acct.ID
	rules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &cred}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var ve *ValidationError
	cases := map[string]error{
		"org caId":               f.store.PutOrgDefaults(ctx, f.org, Defaults{CAID: &ca}),
		"org accountId":          f.store.PutOrgDefaults(ctx, f.org, Defaults{AccountID: &acct}),
		"org rule credentialId":  f.store.PutOrgDefaults(ctx, f.org, Defaults{VerificationRules: &rules}),
		"global caId":            f.store.ValidateGlobalDefaults(ctx, Defaults{CAID: &ca}),
		"global accountId":       f.store.ValidateGlobalDefaults(ctx, Defaults{AccountID: &acct}),
		"global rule credential": f.store.ValidateGlobalDefaults(ctx, Defaults{VerificationRules: &rules}),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: want an error from a cancelled context", name)
			continue
		}
		if errors.As(err, &ve) {
			t.Errorf("%s: cancelled context reported as %v", name, err)
		}
	}
}

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

// Review Focus (fix round 1): challenge.Unchanged is only meaningful on
// update (it means "keep the stored secret"); sending it on create must be
// rejected, not sealed and stored as the literal HMAC.
func TestCARejectsUnchangedEABOnCreate(t *testing.T) {
	f := newFixture(t)
	unchanged := challenge.Unchanged
	_, err := f.store.CreateCA(context.Background(), f.org, CAInput{Name: "Zero", Preset: "zerossl", EABKid: "kid", EABHmac: &unchanged})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "eabHmac" {
		t.Fatalf("err = %v", err)
	}
}

func TestDeleteCABlockedWhileReferenced(t *testing.T) {
	f := newFixture(t)
	var iu *InUseError
	if err := f.store.DeleteCA(context.Background(), f.org, f.ca.ID); !errors.As(err, &iu) {
		t.Fatalf("err = %v", err)
	}
}

// Fix wave item 7: changing directoryUrl while an ACME account is
// registered against the CA is rejected (409) like a delete — the
// account's key is enrolled with the old ACME server, so silently
// repointing the CA would orphan it. f.ca already has f.acct registered
// against it. Every other field may still change freely.
func TestUpdateCARejectsDirectoryURLChangeWhileReferenced(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var iu *InUseError
	if _, err := f.store.UpdateCA(ctx, f.org, f.ca.ID, CAInput{Name: f.ca.Name, Preset: f.ca.Preset,
		DirectoryURL: "https://pebble2.test/dir", Resolvers: f.ca.Resolvers}); !errors.As(err, &iu) {
		t.Fatalf("err = %v, want InUseError", err)
	}
	ca, err := f.store.UpdateCA(ctx, f.org, f.ca.ID, CAInput{Name: "Pebble renamed", Preset: f.ca.Preset,
		DirectoryURL: f.ca.DirectoryURL, Resolvers: f.ca.Resolvers})
	if err != nil || ca.Name != "Pebble renamed" {
		t.Fatalf("ca = %+v err = %v", ca, err)
	}
}

// TestDeleteCaLockBlocksConcurrentOrgDefaultsWrite (review fix round 1):
// proves the FOR UPDATE / FOR KEY SHARE pairing actually serializes a
// delete against a concurrent org-defaults write referencing the same CA,
// not just that the two checks happen to run in the right order when
// nothing else is racing. It opens a transaction that holds DeleteCA's own
// FOR UPDATE lock (without committing), starts a concurrent PutOrgDefaults
// referencing that CA in a goroutine, asserts the write is still blocked
// after a short timeout, then commits a delete of the CA through the same
// held transaction and asserts the blocked write wakes up with a 422 (no
// dangling reference), instead of succeeding against a CA that no longer
// exists.
func TestDeleteCaLockBlocksConcurrentOrgDefaultsWrite(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ca, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Lockable", Preset: "custom", DirectoryURL: "https://lockable.test/dir"})
	if err != nil {
		t.Fatal(err)
	}

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A rollback after a successful commit below is a no-op; this only
	// matters if the test fails before reaching the commit, so the held
	// connection isn't leaked into the pool.Close t.Cleanup runs afterward.
	defer func() { _ = tx.Rollback(ctx) }()
	q := f.store.q.WithTx(tx)
	if _, err := q.LockCA(ctx, sqlcgen.LockCAParams{ID: ca.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		id := ca.ID
		done <- f.store.PutOrgDefaults(context.Background(), f.org, Defaults{CAID: &id})
	}()

	select {
	case err := <-done:
		t.Fatalf("org-defaults write did not block on the held CA lock: %v", err)
	case <-time.After(300 * time.Millisecond):
		// Still blocked, as expected: validateDefaultsTx's LockCAKeyShare
		// conflicts with the FOR UPDATE this test is holding.
	}

	if _, err := q.DeleteCA(ctx, sqlcgen.DeleteCAParams{ID: ca.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var ve *ValidationError
	select {
	case err := <-done:
		if !errors.As(err, &ve) || ve.Field != "caId" {
			t.Fatalf("want a 422 no-such-CA once the lock releases into a committed delete, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("org-defaults write never unblocked after the delete committed")
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
	// Renaming a stored secret's value: keeping CF_DNS_API_TOKEN Unchanged
	// while CF_API_EMAIL (a public field) changes is rejected (fix wave
	// item 4) — re-entering the secret alongside the change succeeds.
	var ve *ValidationError
	if _, _, err := f.store.UpdateDNSCredential(ctx, f.org, c.ID, "cf", map[string]string{"CF_API_EMAIL": "b@example.test", "CF_DNS_API_TOKEN": challenge.Unchanged}); !errors.As(err, &ve) || ve.Field != "config" {
		t.Fatalf("public change + Unchanged secret should be rejected: %v", err)
	}
	if _, changed, err := f.store.UpdateDNSCredential(ctx, f.org, c.ID, "cf", map[string]string{"CF_API_EMAIL": "b@example.test", "CF_DNS_API_TOKEN": "t1"}); err != nil {
		t.Fatal(err)
	} else if len(changed) != 1 || changed[0] != "CF_API_EMAIL" {
		t.Fatalf("changedPublic = %v", changed)
	}
	_, cfg, err := f.store.DNSCredentialConfig(ctx, f.org, c.ID)
	if err != nil || cfg["CF_DNS_API_TOKEN"] != "t1" || cfg["CF_API_EMAIL"] != "b@example.test" {
		t.Fatalf("cfg = %v err = %v", cfg, err)
	}
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
	if _, reissue, err := f.store.UpdateCertificate(ctx, f.org, c.ID, in, nil); err != nil || reissue {
		t.Fatalf("rename must not reissue: %v %v", reissue, err)
	}
	in.SANs = append(in.SANs, "www.other.test")
	if _, reissue, _ := f.store.UpdateCertificate(ctx, f.org, c.ID, in, nil); !reissue {
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

// TestCertificateNormalizesViaOffHTTP01 (4A final review, finding 3): via
// is meaningful only for http-01 (Validate no longer rejects it elsewhere,
// so a client's stale "server" default on a tls-alpn-01 rule stores
// cleanly), but the stored rule itself must not keep it: prepareCertTx
// normalizes via back to "" for any rule whose method is not http-01,
// before the rule is marshalled into the certificate row.
func TestCertificateNormalizesViaOffHTTP01(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	agent := f.client(t, f.org, "agent", []string{"tls-alpn-01"})
	in := CertInput{Name: "web", CommonName: "example.test",
		Rules: []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodTLSALPN01, ClientID: &agent, Via: challenge.ViaServer}}}
	c, err := f.store.CreateCertificate(ctx, f.org, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 1 || c.Rules[0].Via != "" {
		t.Fatalf("stored rule via = %+v, want cleared", c.Rules)
	}
	got, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Via != "" {
		t.Fatalf("read-back rule via = %+v, want cleared", got.Rules)
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

// Review Focus (Task 7): an org default rule's clientId is validated
// exactly like a certificate's own rule (validateRulesOrgTx serves both):
// another org's client is rejected as not found, and a same-org client
// missing the rule's method capability is rejected too, unless the rule is
// http-01 with its own webroot.
func TestOrgDefaultsRuleClientMustBeInOrg(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var ve *ValidationError

	otherOrg := dbtest.Org(t, f.pool)
	foreign := f.client(t, otherOrg, "foreign", []string{"tls-alpn-01"})
	rules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodTLSALPN01, ClientID: &foreign}}
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{VerificationRules: &rules}); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("foreign client: %v", err)
	}

	noCap := f.client(t, f.org, "web-1", nil)
	rules = []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodTLSALPN01, ClientID: &noCap}}
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{VerificationRules: &rules}); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("missing capability: %v", err)
	}

	rules = []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodHTTP01, Via: challenge.ViaAgent,
		ClientID: &noCap, Webroot: "/var/www/.well-known/acme-challenge"}}
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{VerificationRules: &rules}); err != nil {
		t.Fatalf("http-01 with its own webroot: %v", err)
	}

	hasCap := f.client(t, f.org, "web-2", []string{"tls-alpn-01"})
	rules = []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodTLSALPN01, ClientID: &hasCap}}
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{VerificationRules: &rules}); err != nil {
		t.Fatalf("client with the capability: %v", err)
	}
}

// TestValidateRulesLocksClientsInIDOrder (fix round 1, Important finding):
// validateRulesOrgTx must lock every distinct client referenced by a rule
// in id order, not rule order. render's own LockClientsByID always locks
// clients FOR UPDATE in id order (internal/agents/settings.go's global
// lock-order rule), so a write whose rules name two clients in the
// opposite order would otherwise deadlock against a concurrent render
// holding one and waiting on the other.
func TestValidateRulesLocksClientsInIDOrder(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.client(t, f.org, "a", []string{"tls-alpn-01"})
	b := f.client(t, f.org, "b", []string{"tls-alpn-01"})
	lo, hi := a, b
	if strings.Compare(hi.String(), lo.String()) < 0 {
		lo, hi = hi, lo
	}

	// tx1 mimics render: locks lo FOR UPDATE first, the ascending order
	// every multi-client locker in this codebase uses.
	tx1, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()
	q1 := f.store.q.WithTx(tx1)
	if _, err := q1.LockClientByID(ctx, lo); err != nil {
		t.Fatal(err)
	}

	// The write's own rules list hi before lo — the "wrong" order a
	// per-rule lock loop would follow instead of sorting first.
	rules := []challenge.RuleSpec{
		{Match: "hi.example.test", Method: challenge.MethodTLSALPN01, ClientID: &hi},
		{Match: "lo.example.test", Method: challenge.MethodTLSALPN01, ClientID: &lo},
	}
	done := make(chan error, 1)
	go func() {
		done <- f.store.PutOrgDefaults(context.Background(), f.org, Defaults{VerificationRules: &rules})
	}()

	// Give the write time to take its first lock. With the fix, that is lo
	// (sorted ascending first), which blocks immediately behind tx1 — hi is
	// never touched until lo is free. With the bug, it locks hi first (rule
	// order) and only blocks on lo afterward.
	time.Sleep(300 * time.Millisecond)

	// tx1 now takes its second lock, hi, continuing its own ascending
	// order. With the fix this is uncontended (the write is still blocked
	// on lo and has never touched hi). With the bug the write already
	// holds hi, and this forms the second half of an AB-BA deadlock:
	// Postgres detects it and aborts one side within its deadlock_timeout
	// (~1s), surfacing as an error either here or from the write below.
	lockCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := q1.LockClientByID(lockCtx, hi); err != nil {
		t.Fatalf("render-style lock on hi (clients must lock in id order): %v", err)
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("org-defaults write: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("org-defaults write never unblocked after tx1 committed")
	}
}

// TestConcurrentRenamesSharingRuleClientDoNotDeadlock (4A final review,
// finding 6): a rename used to take its rules' clientId(s) FOR KEY SHARE
// (lockRuleClientsInIDOrder, via prepareCertTx) and then, inside the same
// transaction, the rename hook (agents' render, mimicked here) locked the
// same client FOR UPDATE. Two renames sharing a client both hold the row
// FOR KEY SHARE (compatible with each other), then both try to upgrade to
// FOR UPDATE: a classic lock-upgrade deadlock, 40P01, surfaced as an
// opaque 500. The fix locks rule clients FOR UPDATE up front, in id order,
// whenever the certificate's name is changing, so no later upgrade ever
// races another session's read lock on the same row.
func TestConcurrentRenamesSharingRuleClientDoNotDeadlock(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	shared := f.client(t, f.org, "shared", []string{"tls-alpn-01"})

	mk := func(name string) Certificate {
		in := CertInput{Name: name, CommonName: name + ".example.test",
			Rules: []challenge.RuleSpec{{Match: name + ".example.test", Method: challenge.MethodTLSALPN01, ClientID: &shared}}}
		c, err := f.store.CreateCertificate(ctx, f.org, in)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1 := mk("cert1")
	c2 := mk("cert2")

	// hook mimics agents.Service.ResyncCertificateRename -> render, which
	// locks a renamed certificate's grant clients FOR UPDATE in id order
	// inside the rename's own transaction; here that is just the shared
	// client both certificates' rules reference. The sleep widens the
	// window between the rule-lock step (fast: a handful of queries) and
	// this FOR UPDATE request, so both concurrent renames below have
	// reliably taken whatever lock prepareCertTx takes on the shared
	// client before either reaches here — without it, the two calls can
	// interleave so that one finishes entirely before the other starts,
	// masking the bug.
	hook := func(hctx context.Context, q *sqlcgen.Queries, _ uuid.UUID) (func(), error) {
		time.Sleep(200 * time.Millisecond)
		if _, err := q.LockClientByID(hctx, shared); err != nil {
			return nil, err
		}
		return nil, nil
	}

	rename := func(c Certificate, newName string) error {
		in := CertInput{Name: newName, CommonName: c.CommonName,
			Rules: []challenge.RuleSpec{{Match: c.CommonName, Method: challenge.MethodTLSALPN01, ClientID: &shared}}}
		_, _, err := f.store.UpdateCertificate(ctx, f.org, c.ID, in, hook)
		return err
	}

	done := make(chan error, 2)
	go func() { done <- rename(c1, "cert1-renamed") }()
	go func() { done <- rename(c2, "cert2-renamed") }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("concurrent rename sharing a client: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent renames sharing a client never unblocked")
		}
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

	// clientId is treated exactly like dnsCredentialId (fix round 1,
	// Important finding): checked for existence, and (unless the rule is
	// http-01 with its own webroot) that the client reports the rule's
	// method capability. Checked through both ValidateGlobalDefaults and its
	// transactional, lock-taking sibling ValidateGlobalDefaultsTx, which the
	// settings write path actually uses.
	capable := f.client(t, f.org, "capable", []string{"tls-alpn-01"})
	noCap := f.client(t, f.org, "no-cap", nil)
	missingClient := capable
	missingClient[0] ^= 0xFF

	okRules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodTLSALPN01, ClientID: &capable}}
	missingClientRules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodTLSALPN01, ClientID: &missingClient}}
	noCapRules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodTLSALPN01, ClientID: &noCap}}
	webrootRules := []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodHTTP01, Via: challenge.ViaAgent,
		ClientID: &noCap, Webroot: "/var/www/acme"}}

	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{VerificationRules: &okRules}); err != nil {
		t.Fatalf("real rule client rejected: %v", err)
	}
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{VerificationRules: &missingClientRules}); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("missing rule client: %v", err)
	}
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{VerificationRules: &noCapRules}); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("missing capability: %v", err)
	}
	if err := f.store.ValidateGlobalDefaults(ctx, Defaults{VerificationRules: &webrootRules}); err != nil {
		t.Fatalf("http-01 with its own webroot rejected: %v", err)
	}

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := f.store.ValidateGlobalDefaultsTx(ctx, tx, Defaults{VerificationRules: &okRules}); err != nil {
		t.Fatalf("tx: real rule client rejected: %v", err)
	}
	if err := f.store.ValidateGlobalDefaultsTx(ctx, tx, Defaults{VerificationRules: &missingClientRules}); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("tx: missing rule client: %v", err)
	}
	if err := f.store.ValidateGlobalDefaultsTx(ctx, tx, Defaults{VerificationRules: &noCapRules}); !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("tx: missing capability: %v", err)
	}
	if err := f.store.ValidateGlobalDefaultsTx(ctx, tx, Defaults{VerificationRules: &webrootRules}); err != nil {
		t.Fatalf("tx: http-01 with its own webroot rejected: %v", err)
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
