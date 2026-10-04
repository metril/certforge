//go:build integration

package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func TestListUsersRedactsWithoutGlobalUsersRead(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	q := sqlcgen.New(f.pool)
	var ann, bob sqlcgen.User
	for name, dst := range map[string]*sqlcgen.User{"ann": &ann, "bob": &bob} {
		u, err := q.UpsertOIDCUser(ctx, sqlcgen.UpsertOIDCUserParams{Issuer: "https://idp.test", Subject: name, DisplayName: name, Groups: []string{"ops"}})
		if err != nil {
			t.Fatal(err)
		}
		*dst = u
	}
	list := func(p authn.Principal) gen.UserList {
		t.Helper()
		res, err := f.srv.ListUsers(authn.WithPrincipal(ctx, p), gen.ListUsersRequestObject{})
		if err != nil {
			t.Fatal(err)
		}
		return gen.UserList(res.(gen.ListUsers200JSONResponse))
	}
	row := func(l gen.UserList, id uuid.UUID) gen.UserDetail {
		t.Helper()
		for _, u := range l.Items {
			if u.Id == id {
				return u
			}
		}
		t.Fatalf("user %s missing", id)
		return gen.UserDetail{}
	}

	// A global admin sees everything.
	global := list(authn.Principal{Kind: authn.KindUser, UserID: ann.ID, Bindings: []authn.Binding{{Role: authz.RoleAdmin}}, OrgIDs: []uuid.UUID{f.org}})
	if global.Limited || row(global, bob.ID).OidcIssuer == nil || len(row(global, bob.ID).Groups) != 1 {
		t.Fatalf("global admin list limited=%v bob=%+v", global.Limited, row(global, bob.ID))
	}

	// An org-admin sees names and status of others, full detail for self.
	orgAdmin := list(authn.Principal{Kind: authn.KindUser, UserID: ann.ID, Bindings: []authn.Binding{{Role: authz.RoleOrgAdmin, OrgID: &f.org}}, OrgIDs: []uuid.UUID{f.org}})
	b := row(orgAdmin, bob.ID)
	if !orgAdmin.Limited || b.OidcIssuer != nil || b.OidcSubject != nil || b.LastLogin != nil || len(b.Groups) != 0 || b.DisplayName != "bob" {
		t.Fatalf("org-admin sees bob %+v (limited=%v)", b, orgAdmin.Limited)
	}
	if a := row(orgAdmin, ann.ID); a.OidcIssuer == nil || a.OidcSubject == nil || len(a.Groups) != 1 {
		t.Fatalf("org-admin's own row incomplete: %+v", a)
	}

	// An API key scoped to one org is treated as non-global, even for its creator's own row.
	key := list(authn.Principal{Kind: authn.KindAPIKey, UserID: ann.ID, OrgIDs: []uuid.UUID{f.org},
		Bindings: []authn.Binding{{Role: authz.RoleAdmin}},
		APIKey:   &authn.APIKeyInfo{ID: uuid.New(), Scopes: []string{"admin"}, OrgID: &f.org}})
	if !key.Limited || row(key, bob.ID).OidcIssuer != nil || row(key, ann.ID).OidcIssuer != nil {
		t.Fatalf("org-scoped key list limited=%v bob=%+v ann=%+v", key.Limited, row(key, bob.ID), row(key, ann.ID))
	}
}
