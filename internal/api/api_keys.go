package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func apiKeyOut(k sqlcgen.ApiKey, createdByName string) gen.ApiKey {
	scopes := make([]gen.ApiKeyScope, 0, len(k.Scopes))
	for _, s := range k.Scopes {
		scopes = append(scopes, gen.ApiKeyScope(s))
	}
	return gen.ApiKey{Id: k.ID, Name: k.Name, Prefix: k.Prefix, Scopes: scopes, OrgId: k.OrgID, CreatedBy: k.CreatedBy,
		CreatedByName: createdByName, ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt, CreatedAt: k.CreatedAt}
}

// ListApiKeys returns the keys the caller may read.
func (s *Server) ListApiKeys(ctx context.Context, req gen.ListApiKeysRequestObject) (gen.ListApiKeysResponseObject, error) { //nolint:revive // method name fixed by the listApiKeys operationId
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	if req.Params.OrgId != nil && !authz.Can(p, authz.ActionAPIKeysRead, req.Params.OrgId) {
		return nil, &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "missing permission apikeys:read"}
	}
	rows, err := s.d.Queries.ListAPIKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := []gen.ApiKey{}
	for _, r := range rows {
		if req.Params.OrgId != nil && (r.OrgID == nil || *r.OrgID != *req.Params.OrgId) {
			continue
		}
		if !authz.Can(p, authz.ActionAPIKeysRead, r.OrgID) {
			continue
		}
		k := sqlcgen.ApiKey{ID: r.ID, Name: r.Name, Prefix: r.Prefix, SecretHash: r.SecretHash, Scopes: r.Scopes, OrgID: r.OrgID,
			CreatedBy: r.CreatedBy, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt}
		out = append(out, apiKeyOut(k, r.CreatedByName))
	}
	return gen.ListApiKeys200JSONResponse(gen.ApiKeyList{Items: out}), nil
}

// CreateApiKey mints a key whose scopes never exceed the creator's role.
func (s *Server) CreateApiKey(ctx context.Context, req gen.CreateApiKeyRequestObject) (gen.CreateApiKeyResponseObject, error) { //nolint:revive // method name fixed by the createApiKey operationId
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	in := *req.Body
	p, err := authorize(ctx, authz.ActionAPIKeysWrite, in.OrgId)
	if err != nil {
		return nil, err
	}
	if p.Kind != authn.KindUser {
		return nil, &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "API keys cannot create API keys"}
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		return nil, unprocessable("name", "name must be 1 to 100 characters")
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now().Add(time.Minute)) {
		return nil, unprocessable("expiresAt", "expiresAt must be at least a minute in the future")
	}
	granted := []string{}
	for _, sc := range in.Scopes {
		act, ok := authz.ScopeGrant[string(sc)]
		if !ok {
			return nil, unprocessable("scopes", "unknown scope "+string(sc))
		}
		if authz.Can(p, act, in.OrgId) && !slices.Contains(granted, string(sc)) {
			granted = append(granted, string(sc))
		}
	}
	if len(granted) == 0 {
		return nil, unprocessable("scopes", "none of the requested scopes are within your role here")
	}
	u, err := s.d.Queries.GetUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	token, prefix, hash, err := authn.NewAPIKeyToken()
	if err != nil {
		return nil, err
	}
	k, err := s.d.Queries.CreateAPIKey(ctx, sqlcgen.CreateAPIKeyParams{Name: name, Prefix: prefix, SecretHash: hash,
		Scopes: granted, OrgID: in.OrgId, CreatedBy: p.UserID, ExpiresAt: in.ExpiresAt})
	if pgCode(err) == pgUniqueViolation {
		// The 12-hex prefix collided with an existing key's; regenerate once
		// and retry rather than fail the request over a ~1-in-2^48 event.
		token, prefix, hash, err = authn.NewAPIKeyToken()
		if err != nil {
			return nil, err
		}
		k, err = s.d.Queries.CreateAPIKey(ctx, sqlcgen.CreateAPIKeyParams{Name: name, Prefix: prefix, SecretHash: hash,
			Scopes: granted, OrgID: in.OrgId, CreatedBy: p.UserID, ExpiresAt: in.ExpiresAt})
	}
	if pgCode(err) == pgForeignKeyViolation {
		return nil, unprocessable("orgId", "no such org")
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "api_key.create", ResourceType: "api_key", ResourceID: k.ID.String(), OrgID: k.OrgID,
		Details: map[string]any{"name": k.Name, "prefix": k.Prefix, "scopes": k.Scopes, "expiresAt": k.ExpiresAt}})
	return gen.CreateApiKey201JSONResponse(gen.ApiKeyCreated{ApiKey: apiKeyOut(k, u.DisplayName), Token: token}), nil
}

// RevokeApiKey revokes a key; revoking twice is a no-op.
func (s *Server) RevokeApiKey(ctx context.Context, req gen.RevokeApiKeyRequestObject) (gen.RevokeApiKeyResponseObject, error) { //nolint:revive // method name fixed by the revokeApiKey operationId
	k, err := s.d.Queries.GetAPIKey(ctx, req.Id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("API key %s", req.Id)
	}
	if err != nil {
		return nil, err
	}
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	if !authz.Can(p, authz.ActionAPIKeysWrite, k.OrgID) {
		// 404, not 403: a caller who cannot manage this key's scope must
		// not be able to tell it apart from one that doesn't exist (no
		// existence oracle via a 403-vs-404 status difference).
		return nil, notFound("API key %s", req.Id)
	}
	n, err := s.d.Queries.RevokeAPIKey(ctx, k.ID)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		s.audit(ctx, audit.Event{Action: "api_key.revoke", ResourceType: "api_key", ResourceID: k.ID.String(), OrgID: k.OrgID,
			Details: map[string]any{"name": k.Name, "prefix": k.Prefix}})
	}
	return gen.RevokeApiKey204Response{}, nil
}
