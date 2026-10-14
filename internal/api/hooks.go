package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// Default limits for the public check-now hook: per client address (checked
// before any hashing) and per grant (after the token is proven).
const (
	hookIPPerMinute, hookIPBurst       = 30, 10
	hookGrantPerMinute, hookGrantBurst = 6, 6
)

// checkHook is POST /hooks/v1/grants/{grantId}/check: a device that just
// changed its certificate asks for an immediate verify check. Authenticated by
// the grant's check token as a bearer token; every auth failure is a 404 so
// the route reveals nothing about which grants exist.
func (s *Server) checkHook(w http.ResponseWriter, r *http.Request) {
	notFoundResp := func() { Write(w, http.StatusNotFound, "Not found", "") }
	tooMany := func(wait float64) {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait))))
		Write(w, http.StatusTooManyRequests, "Too many requests", "Wait before trying again.")
	}
	ip := audit.IPFrom(r.Context())
	if ok, wait := s.d.HookIPLimiter.Allow(authn.LimitKey(ip)); !ok {
		tooMany(wait.Seconds())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	grantID, err := uuid.Parse(chi.URLParam(r, "grantId"))
	if err != nil {
		notFoundResp()
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		notFoundResp()
		return
	}
	prefix, secret, ok := authn.ParseAPIKeyToken(strings.TrimSpace(tok))
	if !ok {
		notFoundResp()
		return
	}
	ctx := r.Context()
	row, err := s.queries().GetGrantCheckTokenByPrefix(ctx, prefix)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.d.Log.Error("check hook lookup failed", "err", err)
		}
		notFoundResp()
		return
	}
	if subtle.ConstantTimeCompare(row.SecretHash, authn.HashAPIKeySecret(secret)) != 1 || row.GrantID != grantID {
		notFoundResp()
		return
	}
	if ok, wait := s.d.HookGrantLimiter.Allow(grantID.String()); !ok {
		tooMany(wait.Seconds())
		return
	}
	if err := s.d.Dispatcher.EnqueueGrantCheck(ctx, grantID); err != nil {
		s.d.Log.Error("check hook enqueue failed", "grant", grantID, "err", err)
		Write(w, http.StatusInternalServerError, "Internal server error", "")
		return
	}
	if err := s.queries().TouchGrantCheckToken(ctx, grantID); err != nil {
		s.d.Log.Warn("check hook touch failed", "grant", grantID, "err", err)
	}
	s.audit(ctx, audit.Event{Action: "grant.check_hook", ResourceType: "grant", ResourceID: grantID.String(), OrgID: &row.OrgID,
		ActorType: "token", ActorID: prefix, Details: map[string]any{"ip": ip}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"queued":true}` + "\n"))
}

// CreateGrantCheckToken generates (or rotates) a server grant's check token.
func (s *Server) CreateGrantCheckToken(ctx context.Context, r gen.CreateGrantCheckTokenRequestObject) (gen.CreateGrantCheckTokenResponseObject, error) {
	p, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId)
	if err != nil {
		return nil, err
	}
	rows, err := s.queries().ServerGrantViews(ctx, sqlcgen.ServerGrantViewsParams{OrgID: r.OrgId, GrantID: &r.Id})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, notFound("grant %s", r.Id)
	}
	if rows[0].MonitorID == nil {
		return nil, conflict("the grant has no verify endpoint to check")
	}
	token, prefix, hash, err := authn.NewAPIKeyToken()
	if err != nil {
		return nil, err
	}
	var by *uuid.UUID
	if p.UserID != uuid.Nil {
		by = &p.UserID
	}
	if err := s.queries().UpsertGrantCheckToken(ctx, sqlcgen.UpsertGrantCheckTokenParams{
		GrantID: r.Id, Prefix: prefix, SecretHash: hash, CreatedBy: by}); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "grant.check_token_set", ResourceType: "grant", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"prefix": prefix}})
	url := strings.TrimRight(s.baseURL(ctx), "/") + "/hooks/v1/grants/" + r.Id.String() + "/check"
	return gen.CreateGrantCheckToken201JSONResponse(gen.GrantCheckToken{Token: token, Url: url}), nil
}

// DeleteGrantCheckToken revokes a server grant's check token.
func (s *Server) DeleteGrantCheckToken(ctx context.Context, r gen.DeleteGrantCheckTokenRequestObject) (gen.DeleteGrantCheckTokenResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.queries().ServerGrantViews(ctx, sqlcgen.ServerGrantViewsParams{OrgID: r.OrgId, GrantID: &r.Id})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, notFound("grant %s", r.Id)
	}
	if _, err := s.queries().DeleteGrantCheckToken(ctx, r.Id); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "grant.check_token_revoke", ResourceType: "grant", ResourceID: r.Id.String(), OrgID: &r.OrgId})
	return gen.DeleteGrantCheckToken204Response{}, nil
}
