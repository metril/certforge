//go:build integration

package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func adminCtx(ctx context.Context, id uuid.UUID) context.Context {
	return authn.WithPrincipal(ctx, authn.Principal{Kind: authn.KindUser, UserID: id, Roles: []string{"admin"},
		Bindings: []authn.Binding{{Role: "admin"}}, OrgIDs: []uuid.UUID{}})
}

func wantHTTPStatus(t *testing.T, err error, status int) {
	t.Helper()
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != status {
		t.Fatalf("err = %v, want HTTP %d", err, status)
	}
}

func TestDeleteUser(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	s := &Server{d: Deps{Pool: pool, Queries: q, Auditor: audit.New(pool, bytes.Repeat([]byte{5}, 32)), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	admin := mkGlobalAdmin(ctx, t, q, "del-admin")
	admin2 := mkGlobalAdmin(ctx, t, q, "del-admin2")
	victim, err := q.UpsertOIDCUser(ctx, sqlcgen.UpsertOIDCUserParams{Issuer: "https://idp.test", Subject: "victim", DisplayName: "Victim", Groups: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "user", Subject: victim.ID.String(), Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateSession(ctx, sqlcgen.CreateSessionParams{ID: "sess-victim", UserID: victim.ID, Csrf: "c", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_, prefix, hash, err := authn.NewAPIKeyToken()
	if err != nil {
		t.Fatal(err)
	}
	key, err := q.CreateAPIKey(ctx, sqlcgen.CreateAPIKeyParams{Name: "k", Prefix: prefix, SecretHash: hash, Scopes: []string{"certs:read"}, CreatedBy: &victim.ID})
	if err != nil {
		t.Fatal(err)
	}

	// 404, self, and non-admin.
	_, err = s.DeleteUser(adminCtx(ctx, admin.ID), gen.DeleteUserRequestObject{Id: uuid.New()})
	wantHTTPStatus(t, err, http.StatusNotFound)
	_, err = s.DeleteUser(adminCtx(ctx, admin.ID), gen.DeleteUserRequestObject{Id: admin.ID})
	wantHTTPStatus(t, err, http.StatusConflict)
	viewerCtx := authn.WithPrincipal(ctx, authn.Principal{Kind: authn.KindUser, UserID: victim.ID, Roles: []string{"viewer"},
		Bindings: []authn.Binding{{Role: "viewer"}}, OrgIDs: []uuid.UUID{}})
	_, err = s.DeleteUser(viewerCtx, gen.DeleteUserRequestObject{Id: admin2.ID})
	wantHTTPStatus(t, err, http.StatusForbidden)

	// Local admin is refused.
	if err := q.SetLocalPasswordHash(ctx, sqlcgen.SetLocalPasswordHashParams{ID: admin2.ID, Hash: "x"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.DeleteUser(adminCtx(ctx, admin.ID), gen.DeleteUserRequestObject{Id: admin2.ID})
	wantHTTPStatus(t, err, http.StatusConflict)

	// Success.
	res, err := s.DeleteUser(adminCtx(ctx, admin.ID), gen.DeleteUserRequestObject{Id: victim.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.(gen.DeleteUser204Response); !ok {
		t.Fatalf("response %T", res)
	}
	if _, err := q.GetUser(ctx, victim.ID); err == nil {
		t.Fatal("user still exists")
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1`, victim.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("sessions %d %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE subject_type='user' AND subject=$1`, victim.ID.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bindings %d %v", n, err)
	}
	k, err := q.GetAPIKey(ctx, key.ID)
	if err != nil || k.CreatedBy != nil || k.RevokedAt == nil {
		t.Fatalf("key = %+v err %v", k, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='user.delete' AND resource_id=$1`, victim.ID.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit rows %d %v", n, err)
	}

	// The orphaned key still lists, with the placeholder creator name.
	rows, err := q.ListAPIKeys(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.ID == key.ID {
			found = true
			if r.CreatedBy != nil || r.CreatedByName != "(deleted user)" {
				t.Fatalf("row %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("orphaned key missing from list")
	}
}

func TestDeleteUserLastAdmin(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	s := &Server{d: Deps{Pool: pool, Queries: q, Auditor: audit.New(pool, bytes.Repeat([]byte{5}, 32)), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	a := mkGlobalAdmin(ctx, t, q, "last-a")
	b := mkGlobalAdmin(ctx, t, q, "last-b")
	if err := q.SetUserDisabled(ctx, sqlcgen.SetUserDisabledParams{ID: b.ID, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	// a is the only enabled admin; a second admin acting on it is not
	// possible, so use a viewer-less synthetic actor holding admin.
	_, err := s.DeleteUser(adminCtx(ctx, uuid.New()), gen.DeleteUserRequestObject{Id: a.ID})
	wantHTTPStatus(t, err, http.StatusConflict)
}
