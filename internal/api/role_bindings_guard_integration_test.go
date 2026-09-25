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

// TestConcurrentDisableAndDeleteOwnAdminBinding covers fix-round-1's
// concurrency requirement: with exactly two enabled global admins A and B,
// A disables B (PATCH /users/{B}) at the same instant A deletes its OWN
// global admin binding (DELETE /role-bindings/{A's own}). DeleteRoleBinding
// now reuses ensureAnotherGlobalAdmin (Task 8), the same guard UpdateUser
// uses to refuse disabling the last admin, so both calls lock every global
// admin's user row (ORDER BY id FOR UPDATE) before checking: the two calls
// serialize, exactly one must succeed and the other must be refused (409),
// and exactly one enabled admin must be left still holding a binding.
//
// Before this fix, DeleteRoleBinding used its own LockGlobalUserAdminBindings
// query, which locked role_bindings rows (not users) and counted disabled
// admins as if they still granted authority. It neither serialized with
// UpdateUser's guard nor refused when the only "other" admin was disabled.
func TestConcurrentDisableAndDeleteOwnAdminBinding(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()

	a := mkGlobalAdmin(ctx, t, q, "guard10-a")
	b := mkGlobalAdmin(ctx, t, q, "guard10-b")
	rbs, err := q.ListRoleBindingsForUser(ctx, a.ID.String())
	if err != nil || len(rbs) != 1 {
		t.Fatalf("a's binding: %v %v", rbs, err)
	}
	aBindingID := rbs[0].ID

	s := &Server{d: Deps{Pool: pool, Queries: q, Auditor: audit.New(pool), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	principalFor := func(u sqlcgen.User) authn.Principal {
		return authn.Principal{Kind: authn.KindUser, UserID: u.ID, Roles: []string{"admin"},
			Bindings: []authn.Binding{{Role: "admin"}}, OrgIDs: []uuid.UUID{}}
	}

	// A shared start gate, not just launching both goroutines, makes it far
	// less likely one call finishes and commits before the other even
	// begins, which would prove nothing about the lock.
	start := make(chan struct{})
	var wg sync.WaitGroup
	var disableErr, deleteErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, disableErr = s.UpdateUser(authn.WithPrincipal(ctx, principalFor(a)), gen.UpdateUserRequestObject{Id: b.ID, Body: &gen.UserUpdate{Disabled: true}})
	}()
	go func() {
		defer wg.Done()
		<-start
		_, deleteErr = s.DeleteRoleBinding(authn.WithPrincipal(ctx, principalFor(a)), gen.DeleteRoleBindingRequestObject{Id: aBindingID})
	}()
	close(start)
	wg.Wait()

	ok, conflicts := 0, 0
	for _, err := range []error{disableErr, deleteErr} {
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
		t.Fatalf("expected exactly one success and one 409: disable=%v delete=%v", disableErr, deleteErr)
	}

	fa, err := q.GetUser(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := q.GetUser(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	rbsA, err := q.ListRoleBindingsForUser(ctx, a.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	rbsB, err := q.ListRoleBindingsForUser(ctx, b.ID.String())
	if err != nil {
		t.Fatal(err)
	}

	enabledWithBinding := 0
	if !fa.Disabled && len(rbsA) == 1 {
		enabledWithBinding++
	}
	if !fb.Disabled && len(rbsB) == 1 {
		enabledWithBinding++
	}
	if enabledWithBinding != 1 {
		t.Fatalf("expected exactly one enabled admin still holding a binding, got a(disabled=%v,bindings=%d) b(disabled=%v,bindings=%d)",
			fa.Disabled, len(rbsA), fb.Disabled, len(rbsB))
	}
}
