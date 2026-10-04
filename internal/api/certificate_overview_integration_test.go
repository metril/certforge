//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/issuance"
)

type ovSeed struct {
	name, status, lastErr string
	failures              int
	rules                 []challenge.RuleSpec
	notAfterDays          *int // nil: no current version
	renewDays             *int // nil: no renewal date
}

func days(n int) *int { return &n }

func (f *apiFixture) seedOverview(t *testing.T, org uuid.UUID, s ovSeed) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	c, err := f.store.CreateCertificate(ctx, org, issuance.CertInput{Name: s.name, CommonName: s.name + ".example.test", Rules: s.rules})
	if err != nil {
		t.Fatal(err)
	}
	if s.notAfterDays != nil {
		var vid uuid.UUID
		if err := f.pool.QueryRow(ctx, `INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der, private_key)
			VALUES ($1, $2, now() - interval '30 days', now() + make_interval(days => $3), 'fp', 'ecdsa-p256', '\x00', '\x00') RETURNING id`,
			c.ID, s.name, *s.notAfterDays).Scan(&vid); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE certificates SET current_version_id = $2 WHERE id = $1`, c.ID, vid); err != nil {
			t.Fatal(err)
		}
	}
	var renew *time.Time
	if s.renewDays != nil {
		r := time.Now().AddDate(0, 0, *s.renewDays)
		renew = &r
	}
	if _, err := f.pool.Exec(ctx, `UPDATE certificates SET status = $2, failure_count = $3, last_error = $4, next_renew_at = $5 WHERE id = $1`,
		c.ID, s.status, s.failures, s.lastErr, renew); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func TestCertificateOverview(t *testing.T) {
	f := newAPIFixture(t)
	org2 := dbtest.Org(t, f.pool)
	ctx := context.Background()
	manual := []challenge.RuleSpec{{Match: "x.example.test", Method: challenge.MethodManualDNS, Via: challenge.ViaServer}}
	dns := []challenge.RuleSpec{{Match: "x.example.test", Method: challenge.MethodHTTP01, Via: challenge.ViaServer}}
	// org2 inherits manual-dns from its defaults.
	inherited := manual
	if err := f.store.PutOrgDefaults(ctx, org2, issuance.Defaults{VerificationRules: &inherited}); err != nil {
		t.Fatal(err)
	}
	seeds := []ovSeed{
		{name: "fine", status: "active", rules: dns, notAfterDays: days(200), renewDays: days(100)},
		{name: "fine-norules", status: "active", notAfterDays: days(200), renewDays: days(100)}, // not listed: nothing to look at
		{name: "soon", status: "active", rules: dns, notAfterDays: days(30), renewDays: days(20)},
		{name: "overdue", status: "active", rules: dns, notAfterDays: days(60), renewDays: days(-2)},
		{name: "expired", status: "expired", rules: dns, notAfterDays: days(-3)},
		{name: "failed", status: "failed", rules: dns, failures: 2, lastErr: "dns: NXDOMAIN\nsecond line"},
		{name: "retrying", status: "active", rules: dns, failures: 1, lastErr: "boom", notAfterDays: days(200), renewDays: days(100)},
		{name: "pending-manual", status: "pending", rules: manual},
		{name: "renewing-manual", status: "active", rules: manual, notAfterDays: days(200), renewDays: days(100)},
		{name: "revoked", status: "revoked", rules: dns, notAfterDays: days(10)},
	}
	ids := map[string]uuid.UUID{}
	for _, s := range seeds {
		ids[s.name] = f.seedOverview(t, f.org, s)
	}
	ids["inherit-pending"] = f.seedOverview(t, org2, ovSeed{name: "inherit-pending", status: "pending"})
	// No renewal date and far-out expiry: only the manual-DNS candidate rule holds.
	f.seedOverview(t, org2, ovSeed{name: "inherit-unmanaged", status: "active", notAfterDays: days(200)})
	ids["inherit-far"] = f.seedOverview(t, org2, ovSeed{name: "inherit-far", status: "active", notAfterDays: days(200), renewDays: days(100)})

	res, err := f.srv.GetCertificateOverview(f.as("viewer"), gen.GetCertificateOverviewRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	ov := res.(gen.GetCertificateOverview200JSONResponse)
	if c := ov.Counts; c.Active != 6 || c.Pending != 1 || c.Failed != 1 || c.Expired != 1 || c.Revoked != 1 || c.Total != 10 {
		t.Fatalf("counts %+v", c)
	}
	// fine, fine-norules, retrying, renewing-manual: active versions 200 d out.
	if ov.Beyond != 4 || ov.Truncated {
		t.Fatalf("beyond %d truncated %v", ov.Beyond, ov.Truncated)
	}
	got := map[string]gen.CertificateBrief{}
	for _, b := range ov.Items {
		got[b.Name] = b
	}
	for _, want := range []string{"soon", "overdue", "expired", "failed", "retrying", "pending-manual", "renewing-manual"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
	for _, not := range []string{"fine", "fine-norules", "revoked"} {
		if _, ok := got[not]; ok {
			t.Fatalf("%s must not be listed", not)
		}
	}
	if len(ov.Items) != 7 {
		t.Fatalf("items %d", len(ov.Items))
	}
	for name, manual := range map[string]bool{"pending-manual": true, "renewing-manual": true, "soon": false, "failed": false} {
		if got[name].ManualDns != manual {
			t.Fatalf("%s manualDns %v", name, got[name].ManualDns)
		}
	}
	if l := got["failed"].LastErrorLine; l == nil || *l != "dns: NXDOMAIN" || got["failed"].FailureCount != 2 {
		t.Fatalf("failed brief %+v", got["failed"])
	}
	if got["failed"].NotAfter != nil || got["soon"].NotAfter == nil || got["soon"].NotBefore == nil || got["soon"].NextRenewAt == nil {
		t.Fatalf("versions %+v %+v", got["failed"], got["soon"])
	}
	if got["soon"].Id != ids["soon"] || got["soon"].OrgId != f.org {
		t.Fatalf("soon %+v", got["soon"])
	}

	// All orgs: org2 is not readable by the org-scoped viewer, so it stays out.
	all, err := f.srv.GetAllCertificateOverview(f.as("viewer"), gen.GetAllCertificateOverviewRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	if a := all.(gen.GetAllCertificateOverview200JSONResponse); a.Counts.Total != 10 || len(a.Items) != 7 {
		t.Fatalf("viewer all %+v", a.Counts)
	}
	global := authn.WithPrincipal(ctx, authn.Principal{Kind: authn.KindUser, UserID: uuid.New(),
		Bindings: []authn.Binding{{Role: authz.RoleAdmin}}, OrgIDs: []uuid.UUID{f.org, org2}})
	all, err = f.srv.GetAllCertificateOverview(global, gen.GetAllCertificateOverviewRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	a := all.(gen.GetAllCertificateOverview200JSONResponse)
	if a.Counts.Total != 13 || a.Counts.Pending != 2 || a.Beyond != 6 || len(a.Items) != 10 {
		t.Fatalf("admin all %+v beyond %d items %d", a.Counts, a.Beyond, len(a.Items))
	}
	for _, b := range a.Items {
		switch b.Name {
		case "inherit-pending", "inherit-far", "inherit-unmanaged":
			if !b.ManualDns || b.OrgId != org2 {
				t.Fatalf("inherited manual dns not resolved: %+v", b)
			}
		}
	}

	// Authorization matches the list endpoints.
	_, err = f.srv.GetCertificateOverview(f.as("viewer"), gen.GetCertificateOverviewRequestObject{OrgId: org2})
	wantStatus(t, err, http.StatusForbidden)
	none := authn.WithPrincipal(ctx, authn.Principal{Kind: authn.KindUser, UserID: uuid.New(), OrgIDs: []uuid.UUID{}})
	_, err = f.srv.GetAllCertificateOverview(none, gen.GetAllCertificateOverviewRequestObject{})
	wantStatus(t, err, http.StatusForbidden)
}
