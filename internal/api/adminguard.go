package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// ensureAnotherGlobalAdmin returns a 409 conflict error unless some enabled
// user other than excluding holds a global (org-less) admin role binding.
// It locks every global admin's user row first (ORDER BY id FOR UPDATE, via
// LockGlobalAdminUsers), so two callers racing to disable the last two
// admins serialize: the second to acquire the locks sees the first's
// committed change and is refused. Reused by Task 10 for role-binding
// deletes.
func ensureAnotherGlobalAdmin(ctx context.Context, q *sqlcgen.Queries, excluding uuid.UUID) error {
	admins, err := q.LockGlobalAdminUsers(ctx)
	if err != nil {
		return err
	}
	isAdmin, another := false, false
	for _, u := range admins {
		if u.ID == excluding {
			isAdmin = true
			continue
		}
		if !u.Disabled {
			another = true
		}
	}
	if isAdmin && !another {
		return conflict("At least one enabled global admin must remain.")
	}
	return nil
}
