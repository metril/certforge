package api

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func userDetail(u sqlcgen.User) gen.UserDetail {
	return gen.UserDetail{Id: u.ID, DisplayName: u.DisplayName, Email: u.Email, LocalAdmin: u.LocalPasswordHash != nil,
		OidcIssuer: u.OidcIssuer, OidcSubject: u.OidcSub, Groups: append([]string{}, u.OidcGroups...),
		Disabled: u.Disabled, LastLogin: u.LastLogin, CreatedAt: u.CreatedAt}
}

// ListUsers returns every user, local and OIDC.
func (s *Server) ListUsers(ctx context.Context, _ gen.ListUsersRequestObject) (gen.ListUsersResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionUsersRead, nil); err != nil {
		return nil, err
	}
	users, err := s.d.Queries.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]gen.UserDetail, 0, len(users))
	for _, u := range users {
		out = append(out, userDetail(u))
	}
	return gen.ListUsers200JSONResponse(gen.UserList{Items: out}), nil
}

// UpdateUser enables or disables a user. Disabling revokes every session of
// the user at once. A user cannot disable themselves, and the last enabled
// global admin cannot be disabled (see ensureAnotherGlobalAdmin).
func (s *Server) UpdateUser(ctx context.Context, req gen.UpdateUserRequestObject) (gen.UpdateUserResponseObject, error) {
	p, err := authorize(ctx, authz.ActionUsersWrite, nil)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	if req.Body.Disabled && p.Kind == authn.KindUser && req.Id == p.UserID {
		return nil, conflict("You cannot disable your own account.")
	}

	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)

	// Unlocked existence check first: a nonexistent id 404s before we take
	// any locks.
	if _, err := q.GetUser(ctx, req.Id); errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("user %s", req.Id)
	} else if err != nil {
		return nil, err
	}

	if req.Body.Disabled {
		// Locks every global admin's row (including the target's, if it is
		// one), ORDER BY id, before deciding anything: a concurrent disable
		// of the last two admins serializes on this instead of both racing
		// a stale "another admin exists" read.
		if err := ensureAnotherGlobalAdmin(ctx, q, req.Id); err != nil {
			return nil, err
		}
	}
	// Lock (or re-lock, if already locked above) and re-read the target row
	// now that we hold whatever locks this request takes, so `before`
	// reflects the row's true current state under a concurrent PATCH of the
	// same user instead of the stale value from the existence check above.
	u, err := q.GetUserForUpdate(ctx, req.Id)
	if err != nil {
		return nil, err
	}

	before := u.Disabled
	var revoked int64
	if before != req.Body.Disabled {
		if err := q.SetUserDisabled(ctx, sqlcgen.SetUserDisabledParams{ID: u.ID, Disabled: req.Body.Disabled}); err != nil {
			return nil, err
		}
		if req.Body.Disabled {
			revoked, err = q.DeleteUserSessions(ctx, u.ID)
			if err != nil {
				return nil, err
			}
		}
		u.Disabled = req.Body.Disabled
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	if before != u.Disabled {
		s.audit(ctx, audit.Event{Action: "user.update", ResourceType: "user", ResourceID: u.ID.String(),
			Details: map[string]any{"before": map[string]any{"disabled": before}, "after": map[string]any{"disabled": u.Disabled}}})
		if u.Disabled {
			s.audit(ctx, audit.Event{Action: "session.revoked", ResourceType: "user", ResourceID: u.ID.String(),
				Details: map[string]any{"count": revoked, "reason": "user_disabled"}})
		}
	}
	return gen.UpdateUser200JSONResponse(userDetail(u)), nil
}
