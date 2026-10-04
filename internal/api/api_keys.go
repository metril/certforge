package api

import (
	"context"
	"errors"
	"fmt"
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

// apiKeyPolicy reads the key limits from the authentication settings; without
// a settings source or on a read error it falls back to the defaults.
func (s *Server) apiKeyPolicy(ctx context.Context) authn.AuthSettings {
	if s.d.AuthSettings != nil {
		if st, err := s.d.AuthSettings.Get(ctx); err == nil {
			return st
		}
	}
	return authn.AuthSettings{APIKeyMaxActivePerUser: authn.DefaultAPIKeyMaxActive}
}

// errAPIKeyCap means the creator already holds the maximum number of active keys.
var errAPIKeyCap = conflict("you already have the maximum number of active API keys; revoke one first")

// createKeyCapped inserts a key after counting the creator's active keys under
// a per-user advisory lock, so concurrent creates cannot both pass the cap.
// max <= 0 means unlimited.
func (s *Server) createKeyCapped(ctx context.Context, arg sqlcgen.CreateAPIKeyParams, max int) (sqlcgen.ApiKey, error) {
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return sqlcgen.ApiKey{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	if max > 0 {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cf.apikeys:'||$1::text, 0))`, arg.CreatedBy); err != nil {
			return sqlcgen.ApiKey{}, err
		}
		n, err := q.CountActiveAPIKeysByCreator(ctx, arg.CreatedBy)
		if err != nil {
			return sqlcgen.ApiKey{}, err
		}
		if n >= int64(max) {
			return sqlcgen.ApiKey{}, errAPIKeyCap
		}
	}
	k, err := q.CreateAPIKey(ctx, arg)
	if err != nil {
		return sqlcgen.ApiKey{}, err
	}
	return k, tx.Commit(ctx)
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
	rows, err := s.d.Queries.ListAPIKeys(ctx, req.Params.OrgId)
	if err != nil {
		return nil, err
	}
	out := []gen.ApiKey{}
	for _, r := range rows {
		if !authz.Can(p, authz.ActionAPIKeysRead, r.OrgID) {
			continue
		}
		k := sqlcgen.ApiKey{ID: r.ID, Name: r.Name, Prefix: r.Prefix, SecretHash: r.SecretHash, Scopes: r.Scopes, OrgID: r.OrgID,
			CreatedBy: r.CreatedBy, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt}
		out = append(out, apiKeyOut(k, r.CreatedByName))
	}
	pol := s.apiKeyPolicy(ctx)
	return gen.ListApiKeys200JSONResponse(gen.ApiKeyList{Items: out, Policy: gen.ApiKeyPolicy{
		MaxLifetimeDays: pol.APIKeyMaxLifetimeDays, MaxActivePerUser: pol.APIKeyMaxActivePerUser}}), nil
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
	pol := s.apiKeyPolicy(ctx)
	if d := pol.APIKeyMaxLifetimeDays; d > 0 {
		if in.ExpiresAt == nil {
			return nil, unprocessable("expiresAt", fmt.Sprintf("expiresAt is required: keys may live at most %d days", d))
		}
		if in.ExpiresAt.After(time.Now().Add(time.Duration(d) * 24 * time.Hour)) {
			return nil, unprocessable("expiresAt", fmt.Sprintf("expiresAt must be within %d days from now", d))
		}
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
	k, err := s.createKeyCapped(ctx, sqlcgen.CreateAPIKeyParams{Name: name, Prefix: prefix, SecretHash: hash,
		Scopes: granted, OrgID: in.OrgId, CreatedBy: p.UserID, ExpiresAt: in.ExpiresAt}, pol.APIKeyMaxActivePerUser)
	if pgCode(err) == pgUniqueViolation {
		// The 12-hex prefix collided with an existing key's; regenerate once
		// and retry rather than fail the request over a ~1-in-2^48 event.
		token, prefix, hash, err = authn.NewAPIKeyToken()
		if err != nil {
			return nil, err
		}
		k, err = s.createKeyCapped(ctx, sqlcgen.CreateAPIKeyParams{Name: name, Prefix: prefix, SecretHash: hash,
			Scopes: granted, OrgID: in.OrgId, CreatedBy: p.UserID, ExpiresAt: in.ExpiresAt}, pol.APIKeyMaxActivePerUser)
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
