//go:build integration

package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

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

// TestLockGlobalAdminUsersBlocksConcurrentCaller is the direct proof that
// LockGlobalAdminUsers's FOR UPDATE actually holds its lock until commit,
// rather than relying on goroutine scheduling luck (TestConcurrentDisableLastTwoAdmins
// below still passes even with FOR UPDATE removed, since Go doesn't
// guarantee the two calls' SELECTs truly overlap — one call routinely runs
// to completion before the other starts). Here a second transaction's call
// is deliberately started only after the first transaction's call has
// already returned but before it commits: with the lock, the second call
// must still be blocked after a short deadline, and must only complete once
// the first transaction commits. Removing `FOR UPDATE OF u` from the query
// makes this test fail immediately (the second call returns right away,
// since a plain SELECT takes no lock under READ COMMITTED) — confirmed
// below under "RED evidence".
func TestLockGlobalAdminUsersBlocksConcurrentCaller(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	mkGlobalAdmin(ctx, t, q, "lock-a")
	mkGlobalAdmin(ctx, t, q, "lock-b")

	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()
	if _, err := q.WithTx(tx1).LockGlobalAdminUsers(ctx); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		tx2, err := pool.Begin(ctx)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = tx2.Rollback(ctx) }()
		_, err = q.WithTx(tx2).LockGlobalAdminUsers(ctx)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("second LockGlobalAdminUsers call returned (err=%v) before the first transaction committed; the query is not holding its row locks", err)
	case <-time.After(300 * time.Millisecond):
		// Still blocked, as expected.
	}

	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second call failed after commit: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second call never unblocked after the first transaction committed")
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

	s := &Server{d: Deps{Pool: pool, Queries: q, Auditor: audit.New(pool, bytes.Repeat([]byte{5}, 32)), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	disable := func(start <-chan struct{}, actor, target sqlcgen.User) error {
		<-start
		p := authn.Principal{Kind: authn.KindUser, UserID: actor.ID, Roles: []string{"admin"},
			Bindings: []authn.Binding{{Role: "admin"}}, OrgIDs: []uuid.UUID{}}
		_, err := s.UpdateUser(authn.WithPrincipal(ctx, p), gen.UpdateUserRequestObject{Id: target.ID, Body: &gen.UserUpdate{Disabled: true}})
		return err
	}

	// A shared start gate (rather than just launching both goroutines) makes
	// it far less likely one call finishes and commits before the other even
	// begins, which would prove nothing about the lock — both must actually
	// contend for it.
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = disable(start, a, b) }()
	go func() { defer wg.Done(); errs[1] = disable(start, b, a) }()
	close(start)
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

	// The real proof: exactly one of the two admins is still enabled
	// afterward. If the lock didn't hold, both disables could commit (zero
	// admins left) or neither could take effect where one should have.
	fa, err := q.GetUser(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := q.GetUser(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	enabled := 0
	if !fa.Disabled {
		enabled++
	}
	if !fb.Disabled {
		enabled++
	}
	if enabled != 1 {
		t.Fatalf("expected exactly one admin still enabled, got a.disabled=%v b.disabled=%v", fa.Disabled, fb.Disabled)
	}
}
