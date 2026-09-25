//go:build integration

package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func mkGlobalAdmin(ctx context.Context, t *testing.T, q *sqlcgen.Queries, name string) sqlcgen.User {
	t.Helper()
	u, err := q.UpsertOIDCUser(ctx, sqlcgen.UpsertOIDCUserParams{Issuer: "https://idp.test", Subject: name,
		DisplayName: name, Groups: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "user", Subject: u.ID.String(), Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	return u
}

// TestEnsureAnotherGlobalAdmin exercises the guard directly (sequentially):
// it must pass while another enabled global admin exists, refuse once the
// excluded user is the last one enabled, and never block a user who does
// not hold a global admin binding at all.
func TestEnsureAnotherGlobalAdmin(t *testing.T) {
	_, q := dbtest.New(t)
	ctx := context.Background()

	a := mkGlobalAdmin(ctx, t, q, "guard-a")
	b := mkGlobalAdmin(ctx, t, q, "guard-b")

	// Two enabled admins: excluding either one still leaves the other.
	if err := ensureAnotherGlobalAdmin(ctx, q, a.ID); err != nil {
		t.Fatalf("exclude a: %v", err)
	}
	if err := ensureAnotherGlobalAdmin(ctx, q, b.ID); err != nil {
		t.Fatalf("exclude b: %v", err)
	}

	// A user with no admin binding at all is never blocked.
	viewer, err := q.UpsertOIDCUser(ctx, sqlcgen.UpsertOIDCUserParams{Issuer: "https://idp.test", Subject: "guard-viewer",
		DisplayName: "guard-viewer", Groups: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureAnotherGlobalAdmin(ctx, q, viewer.ID); err != nil {
		t.Fatalf("non-admin excluded: %v", err)
	}

	// Disable b: now a is the sole enabled global admin.
	if err := q.SetUserDisabled(ctx, sqlcgen.SetUserDisabledParams{ID: b.ID, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	err = ensureAnotherGlobalAdmin(ctx, q, a.ID)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 409 {
		t.Fatalf("expected 409 HTTPError excluding the last enabled admin, got %v", err)
	}
	// b is already disabled, so excluding b still finds a enabled.
	if err := ensureAnotherGlobalAdmin(ctx, q, b.ID); err != nil {
		t.Fatalf("exclude already-disabled b: %v", err)
	}
}

// TestConcurrentDisableLastTwoAdmins covers ruling C2's concurrency
// requirement: with exactly two enabled global admins, each tries to
// disable the other at the same instant. UpdateUser is called directly
// (in-process, with an injected principal) rather than over HTTP, so the
// only thing racing is the transactional guard itself — not also each
// actor's own session, which disabling the other would otherwise revoke out
// from under their concurrent request and produce a misleading 401. Each
// call's transaction locks every global admin's user row (ORDER BY id FOR
// UPDATE) before checking, so the two calls serialize: exactly one must
// succeed (200, nil error) and the other must be refused (409) because it
// would leave zero enabled global admins.
func TestConcurrentDisableLastTwoAdmins(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()

	a := mkGlobalAdmin(ctx, t, q, "race-a")
	b := mkGlobalAdmin(ctx, t, q, "race-b")

	s := &Server{d: Deps{Pool: pool, Queries: q, Auditor: audit.New(pool), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	disable := func(actor, target sqlcgen.User) error {
		p := authn.Principal{Kind: authn.KindUser, UserID: actor.ID, Roles: []string{"admin"},
			Bindings: []authn.Binding{{Role: "admin"}}, OrgIDs: []uuid.UUID{}}
		_, err := s.UpdateUser(authn.WithPrincipal(ctx, p), gen.UpdateUserRequestObject{Id: target.ID, Body: &gen.UserUpdate{Disabled: true}})
		return err
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = disable(a, b) }()
	go func() { defer wg.Done(); errs[1] = disable(b, a) }()
	wg.Wait()

	ok, conflicts := 0, 0
	for _, err := range errs {
		var he *HTTPError
		switch {
		case err == nil:
			ok++
		case errors.As(err, &he) && he.Status == 409:
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatalf("expected exactly one success and one 409, got errs=%v", errs)
	}
}
