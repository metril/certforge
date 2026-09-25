package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

var bindingRoles = []string{authz.RoleAdmin, authz.RoleOrgAdmin, authz.RoleOperator, authz.RoleViewer, authz.RoleAuditor}

var subjectTypes = []string{"user", "oidc_group", "apikey"}

func bindingOut(rb sqlcgen.RoleBinding, label string) gen.RoleBinding {
	if label == "" {
		label = rb.Subject
	}
	return gen.RoleBinding{Id: rb.ID, SubjectType: gen.SubjectType(rb.SubjectType), Subject: rb.Subject, SubjectLabel: label,
		Role: gen.Role(rb.Role), OrgId: rb.OrgID, CreatedAt: rb.CreatedAt}
}

func forbiddenAction(action authz.Action) error {
	return &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: fmt.Sprintf("missing permission %s", action)}
}

// ListRoleBindings returns the bindings the caller may read.
func (s *Server) ListRoleBindings(ctx context.Context, req gen.ListRoleBindingsRequestObject) (gen.ListRoleBindingsResponseObject, error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	rows, err := s.d.Queries.ListRoleBindingsWithLabels(ctx)
	if err != nil {
		return nil, err
	}
	out := []gen.RoleBinding{}
	for _, r := range rows {
		if req.Params.OrgId != nil && (r.OrgID == nil || *r.OrgID != *req.Params.OrgId) {
			continue
		}
		if req.Params.SubjectType != nil && r.SubjectType != string(*req.Params.SubjectType) {
			continue
		}
		if !authz.Can(p, authz.ActionBindingsRead, r.OrgID) {
			continue
		}
		rb := sqlcgen.RoleBinding{ID: r.ID, SubjectType: r.SubjectType, Subject: r.Subject, Role: r.Role, OrgID: r.OrgID, CreatedAt: r.CreatedAt}
		out = append(out, bindingOut(rb, r.SubjectLabel))
	}
	return gen.ListRoleBindings200JSONResponse(gen.RoleBindingList{Items: out}), nil
}

// CreateRoleBinding grants a role to a user, OIDC group, or API key.
//
// Authorization depends on the subject type (controller ruling C9/D1):
//   - user: caller needs bindings:write in orgId (globally when omitted);
//     an org-admin may only bind users within its own org.
//   - oidc_group: caller always needs bindings:write globally, whatever
//     orgId the binding targets. Group mappings are admin-only.
//   - apikey: caller needs apikeys:write at the key's own scope (global for
//     a global key, the key's org for an org-scoped key), not bindings:write.
func (s *Server) CreateRoleBinding(ctx context.Context, req gen.CreateRoleBindingRequestObject) (gen.CreateRoleBindingResponseObject, error) {
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	in := *req.Body
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	st, role, subject := string(in.SubjectType), string(in.Role), strings.TrimSpace(in.Subject)
	if !slices.Contains(subjectTypes, st) {
		return nil, unprocessable("subjectType", "subjectType must be user, oidc_group, or apikey")
	}
	if !slices.Contains(bindingRoles, role) {
		return nil, unprocessable("role", "role must be one of "+strings.Join(bindingRoles, ", "))
	}
	// A cheap bindings:write check up front, before the subject lookup below
	// discloses (via 422 vs some other outcome) whether a given user or key
	// id exists: a caller with no bindings:write anywhere near this scope
	// gets 403 without that leak. The apikey case still needs the scoped
	// apikeys:write check after the lookup (the key's own org isn't known
	// yet), so this pre-check only rules out callers who plainly have no
	// bindings:write at all here.
	preOrg := in.OrgId
	if st == "oidc_group" {
		preOrg = nil
	}
	if !authz.Can(p, authz.ActionBindingsWrite, preOrg) {
		return nil, forbiddenAction(authz.ActionBindingsWrite)
	}
	label, authOrg, err := s.checkSubject(ctx, st, subject, in.OrgId)
	if err != nil {
		return nil, err
	}
	action := authz.ActionBindingsWrite
	if st == "apikey" {
		action = authz.ActionAPIKeysWrite
	}
	if !authz.Can(p, action, authOrg) {
		return nil, forbiddenAction(action)
	}
	rb, err := s.d.Queries.InsertRoleBinding(ctx, sqlcgen.InsertRoleBindingParams{SubjectType: st, Subject: subject, Role: role, OrgID: in.OrgId})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("This binding already exists.")
	case pgForeignKeyViolation:
		return nil, unprocessable("orgId", "no such org")
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "role_binding.create", ResourceType: "role_binding", ResourceID: rb.ID.String(), OrgID: rb.OrgID,
		Details: map[string]any{"subjectType": st, "subject": subject, "role": role}})
	return gen.CreateRoleBinding201JSONResponse(bindingOut(rb, label)), nil
}

// checkSubject verifies the subject exists and returns its label and the
// org scope the caller must hold permission in to bind it (authOrg): the
// request's orgId for a user subject, always nil (global) for an oidc_group
// subject, and the key's own org for an apikey subject.
func (s *Server) checkSubject(ctx context.Context, subjectType, subject string, org *uuid.UUID) (label string, authOrg *uuid.UUID, err error) {
	switch subjectType {
	case "oidc_group":
		if subject == "" || len(subject) > 256 {
			return "", nil, unprocessable("subject", "group name must be 1 to 256 characters")
		}
		return subject, nil, nil
	case "user":
		id, err := uuid.Parse(subject)
		if err != nil {
			return "", nil, unprocessable("subject", "subject must be a user id")
		}
		u, err := s.d.Queries.GetUser(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, unprocessable("subject", "no such user")
		}
		if err != nil {
			return "", nil, err
		}
		return u.DisplayName, org, nil
	default: // apikey
		id, err := uuid.Parse(subject)
		if err != nil {
			return "", nil, unprocessable("subject", "subject must be an API key id")
		}
		k, err := s.d.Queries.GetAPIKey(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && k.RevokedAt != nil) {
			return "", nil, unprocessable("subject", "no such active API key")
		}
		if err != nil {
			return "", nil, err
		}
		if k.OrgID != nil && (org == nil || *org != *k.OrgID) {
			return "", nil, unprocessable("orgId", "an org-scoped API key can only be bound in its own org")
		}
		return k.Name, k.OrgID, nil
	}
}

// DeleteRoleBinding removes a binding, never the last global user admin.
func (s *Server) DeleteRoleBinding(ctx context.Context, req gen.DeleteRoleBindingRequestObject) (gen.DeleteRoleBindingResponseObject, error) {
	rb, err := s.d.Queries.GetRoleBinding(ctx, req.Id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("role binding %s", req.Id)
	}
	if err != nil {
		return nil, err
	}
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	action, authOrg := authz.ActionBindingsWrite, rb.OrgID
	switch rb.SubjectType {
	case "apikey":
		action = authz.ActionAPIKeysWrite
	case "oidc_group":
		authOrg = nil
	}
	if !authz.Can(p, action, authOrg) {
		// 404, not 403: a caller who cannot manage this binding's scope
		// must not be able to tell it apart from one that doesn't exist
		// (no existence oracle via a 403-vs-404 status difference).
		return nil, notFound("role binding %s", req.Id)
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	if rb.Role == authz.RoleAdmin && rb.SubjectType == "user" && rb.OrgID == nil && rb.SiteID == nil {
		subjectID, err := uuid.Parse(rb.Subject)
		if err != nil {
			return nil, err
		}
		// Reuse Task 8's guard: it locks users (not role_bindings) with an
		// ordered FOR UPDATE and counts only enabled ones, so it serializes
		// with a concurrent PATCH /users/{id} disable and correctly refuses
		// when the only other admin is disabled (LockGlobalUserAdminBindings
		// counted disabled admins too, and didn't serialize with the disable
		// guard at all).
		if err := ensureAnotherGlobalAdmin(ctx, q, subjectID); err != nil {
			return nil, err
		}
		// ensureAnotherGlobalAdmin locks users, not this row: a concurrent
		// caller could have already deleted this same binding while we
		// waited for the lock.
		if _, err := q.GetRoleBinding(ctx, rb.ID); errors.Is(err, pgx.ErrNoRows) {
			return nil, notFound("role binding %s", req.Id)
		} else if err != nil {
			return nil, err
		}
	}
	if err := q.DeleteRoleBinding(ctx, rb.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "role_binding.delete", ResourceType: "role_binding", ResourceID: rb.ID.String(), OrgID: rb.OrgID,
		Details: map[string]any{"subjectType": rb.SubjectType, "subject": rb.Subject, "role": rb.Role}})
	return gen.DeleteRoleBinding204Response{}, nil
}
