//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/issuance"
)

func TestListAllCertificates(t *testing.T) {
	f := newAPIFixture(t)
	org2 := dbtest.Org(t, f.pool)
	ctx := context.Background()
	for _, c := range []struct {
		org  uuid.UUID
		name string
	}{{f.org, "alpha"}, {org2, "beta"}} {
		if _, err := f.store.CreateCertificate(ctx, c.org, issuance.CertInput{Name: c.name, CommonName: c.name + ".example.test"}); err != nil {
			t.Fatal(err)
		}
	}
	global := authn.WithPrincipal(ctx, authn.Principal{Kind: authn.KindUser, UserID: uuid.New(),
		Bindings: []authn.Binding{{Role: authz.RoleAdmin}}, OrgIDs: []uuid.UUID{f.org, org2}})
	limit := 1
	res, err := f.srv.ListAllCertificates(global, gen.ListAllCertificatesRequestObject{Params: gen.ListAllCertificatesParams{Limit: &limit}})
	if err != nil {
		t.Fatal(err)
	}
	page := res.(gen.ListAllCertificates200JSONResponse)
	if len(page.Items) != 1 || page.Items[0].Name != "alpha" || page.NextCursor == nil {
		t.Fatalf("page 1 %+v", page)
	}
	res, err = f.srv.ListAllCertificates(global, gen.ListAllCertificatesRequestObject{Params: gen.ListAllCertificatesParams{Limit: &limit, Cursor: page.NextCursor}})
	if err != nil {
		t.Fatal(err)
	}
	page = res.(gen.ListAllCertificates200JSONResponse)
	if len(page.Items) != 1 || page.Items[0].Name != "beta" || page.Items[0].OrgId == nil || *page.Items[0].OrgId != org2 {
		t.Fatalf("page 2 %+v", page)
	}
	res, err = f.srv.ListAllCertificates(f.as("viewer"), gen.ListAllCertificatesRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	if items := res.(gen.ListAllCertificates200JSONResponse).Items; len(items) != 1 || items[0].Name != "alpha" {
		t.Fatalf("org viewer sees %+v", items)
	}
	none := authn.WithPrincipal(ctx, authn.Principal{Kind: authn.KindUser, UserID: uuid.New(), OrgIDs: []uuid.UUID{}})
	_, err = f.srv.ListAllCertificates(none, gen.ListAllCertificatesRequestObject{})
	wantStatus(t, err, http.StatusForbidden)
}
