//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/issuance"
)

func TestGetRateLedgerAPI(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	caRes, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "LE", Preset: "letsencrypt"}})
	if err != nil {
		t.Fatal(err)
	}
	ca := caRes.(gen.CreateCa201JSONResponse)

	c, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{Name: "a", CommonName: "a.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := f.store.RecordNewOrder(ctx, ca.Id, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordCertIssued(ctx, nil, ca.Id, c.ID, []string{"a.example.test"}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordFailedValidation(ctx, ca.Id, c.ID, []string{"a.example.test"}, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	res, err := f.srv.GetRateLedger(f.as("viewer"), gen.GetRateLedgerRequestObject{OrgId: f.org, Params: gen.GetRateLedgerParams{Ca: ca.Id}})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(gen.GetRateLedger200JSONResponse)
	if got.CaId != ca.Id || !got.Enforced {
		t.Fatalf("ledger = %+v", got)
	}
	if len(got.Items) != 3 {
		t.Fatalf("items = %+v, want 3 (no certificate=)", got.Items)
	}
	for _, it := range got.Items {
		if it.Limit == gen.RateLimitName(issuance.LimitDuplicateCertsPerWeek) {
			t.Fatalf("duplicate item present without certificate=: %+v", it)
		}
		switch it.Limit {
		case gen.RateLimitName(issuance.LimitCertsPerRegisteredDomainPerWeek), gen.RateLimitName(issuance.LimitFailedValidationsPerHour):
			if it.Scope != "example.test" || it.Count != 1 {
				t.Fatalf("item = %+v", it)
			}
		case gen.RateLimitName(issuance.LimitNewOrdersPer3Hours):
			if it.Scope != "" || it.Count != 1 {
				t.Fatalf("item = %+v", it)
			}
		}
	}

	// certificate= adds the duplicate item, scoped to its own names.
	certID := c.ID
	res2, err := f.srv.GetRateLedger(f.as("viewer"), gen.GetRateLedgerRequestObject{OrgId: f.org,
		Params: gen.GetRateLedgerParams{Ca: ca.Id, Certificate: &certID}})
	if err != nil {
		t.Fatal(err)
	}
	got2 := res2.(gen.GetRateLedger200JSONResponse)
	var found bool
	for _, it := range got2.Items {
		if it.Limit == gen.RateLimitName(issuance.LimitDuplicateCertsPerWeek) {
			found = true
			if it.Scope != "a.example.test" || it.Count != 1 {
				t.Fatalf("duplicate item = %+v", it)
			}
		}
	}
	if !found {
		t.Fatal("duplicate item missing with certificate=")
	}

	// A CA belonging to another org: not found, not exposed as this org's.
	otherOrg := dbtest.Org(t, f.pool)
	otherCA, err := f.store.CreateCA(ctx, otherOrg, issuance.CAInput{Name: "Other", Preset: "letsencrypt", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.GetRateLedger(f.as("viewer"), gen.GetRateLedgerRequestObject{OrgId: f.org, Params: gen.GetRateLedgerParams{Ca: otherCA.ID}})
	wantStatus(t, err, http.StatusNotFound)
}

// TestGetRateLedgerHidesOtherOrgDomains: two orgs share one CA (the same
// ca_id backs rows for certificates in both orgs — this package's own CA
// ownership is not itself cross-org, but the ledger's item-scope query
// joins on the certificate, not the CA, and nothing stops two orgs' rows
// from sharing a ca_id at the storage layer). Org B's own registered
// domain must never appear as an item scope for org A's report, but a
// domain both orgs have certificates in must still show org A the combined
// (CA-wide) count.
func TestGetRateLedgerHidesOtherOrgDomains(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	caRes, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{Name: "LE", Preset: "letsencrypt"}})
	if err != nil {
		t.Fatal(err)
	}
	ca := caRes.(gen.CreateCa201JSONResponse)

	orgB := dbtest.Org(t, f.pool)
	certA, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{Name: "a", CommonName: "a.shared.test"})
	if err != nil {
		t.Fatal(err)
	}
	certB, err := f.store.CreateCertificate(ctx, orgB, issuance.CertInput{Name: "b", CommonName: "b.shared.test"})
	if err != nil {
		t.Fatal(err)
	}
	certBOnly, err := f.store.CreateCertificate(ctx, orgB, issuance.CertInput{Name: "only", CommonName: "x.onlyb.test"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := f.store.RecordCertIssued(ctx, nil, ca.Id, certA.ID, []string{"a.shared.test"}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordCertIssued(ctx, nil, ca.Id, certB.ID, []string{"b.shared.test"}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordCertIssued(ctx, nil, ca.Id, certBOnly.ID, []string{"x.onlyb.test"}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	res, err := f.srv.GetRateLedger(f.as("viewer"), gen.GetRateLedgerRequestObject{OrgId: f.org, Params: gen.GetRateLedgerParams{Ca: ca.Id}})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(gen.GetRateLedger200JSONResponse)
	var sharedItem *gen.RateLedgerItem
	for i, it := range got.Items {
		if it.Scope == "onlyb.test" {
			t.Fatalf("org B's own domain leaked into org A's scopes: %+v", it)
		}
		if it.Limit == gen.RateLimitName(issuance.LimitCertsPerRegisteredDomainPerWeek) && it.Scope == "shared.test" {
			sharedItem = &got.Items[i]
		}
	}
	if sharedItem == nil {
		t.Fatal("shared.test item missing")
	}
	if sharedItem.Count != 2 {
		t.Fatalf("shared.test count = %d, want 2 (CA-wide, includes org B's row)", sharedItem.Count)
	}
}
