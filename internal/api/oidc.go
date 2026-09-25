package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func (s *Server) callbackURL(ctx context.Context) string {
	return strings.TrimRight(s.baseURL(ctx), "/") + "/api/v1/auth/oidc/callback"
}

// safeNext keeps only same-origin absolute paths: "/x" yes; "//host",
// "/\host", schemes and relative paths become "/".
func safeNext(next *string) string {
	if next == nil {
		return "/"
	}
	n := *next
	if n == "" || len(n) > 2048 || !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") ||
		strings.HasPrefix(n, `/\`) || strings.ContainsAny(n, "\t\n\r\\") {
		return "/"
	}
	u, err := url.Parse(n)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	// A decoded path or host escape (e.g. "/%2F%2Fevil", "/%5Cevil") must
	// not resolve to something that looks like a scheme-relative or
	// backslash-prefixed URL once unescaped.
	if strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, `/\`) {
		return "/"
	}
	return n
}

func oidcErrorCode(err error) string {
	switch {
	case errors.Is(err, authn.ErrOIDCDisabled):
		return "oidc_disabled"
	case errors.Is(err, authn.ErrOIDCState):
		return "oidc_state"
	case errors.Is(err, authn.ErrOIDCDenied):
		return "oidc_denied"
	}
	return "oidc_failed"
}

// StartOidcLogin redirects the browser to the identity provider.
func (s *Server) StartOidcLogin(ctx context.Context, req gen.StartOidcLoginRequestObject) (gen.StartOidcLoginResponseObject, error) {
	w, r := httpFrom(ctx)
	st, err := s.d.AuthSettings.Get(ctx)
	if err != nil {
		return nil, err
	}
	u, cookie, err := s.d.OIDC.Begin(ctx, st, s.callbackURL(ctx), safeNext(req.Params.Next), s.secureCookie(ctx, r))
	if err != nil {
		s.d.Log.Warn("oidc start failed", "err", err)
		return gen.StartOidcLogin302Response{Headers: gen.StartOidcLogin302ResponseHeaders{Location: "/login?error=" + oidcErrorCode(err)}}, nil
	}
	http.SetCookie(w, cookie)
	return gen.StartOidcLogin302Response{Headers: gen.StartOidcLogin302ResponseHeaders{Location: u}}, nil
}

// OidcCallback finishes the flow, upserts the user and starts a session.
func (s *Server) OidcCallback(ctx context.Context, _ gen.OidcCallbackRequestObject) (gen.OidcCallbackResponseObject, error) {
	w, r := httpFrom(ctx)
	http.SetCookie(w, s.d.OIDC.ClearStateCookie(s.secureCookie(ctx, r)))
	fail := func(code string) gen.OidcCallbackResponseObject {
		s.audit(ctx, audit.Event{Action: "session.login_failed", ResourceType: "user", ActorType: "anonymous",
			Details: map[string]any{"method": "oidc", "reason": code}})
		return gen.OidcCallback302Response{Headers: gen.OidcCallback302ResponseHeaders{Location: "/login?error=" + code}}
	}
	st, err := s.d.AuthSettings.Get(ctx)
	if err != nil {
		return nil, err
	}
	id, next, err := s.d.OIDC.Finish(ctx, st, s.callbackURL(ctx), r)
	if err != nil {
		s.d.Log.Warn("oidc login failed", "err", err)
		return fail(oidcErrorCode(err)), nil
	}
	var email *string
	if id.Email != "" {
		email = &id.Email
	}
	u, err := s.d.Queries.UpsertOIDCUser(ctx, sqlcgen.UpsertOIDCUserParams{Issuer: id.Issuer, Subject: id.Subject,
		Email: email, DisplayName: id.Name, Groups: id.Groups})
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return fail("user_disabled"), nil
	}
	if _, err := s.startSession(ctx, u.ID); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "session.login", ResourceType: "user", ResourceID: u.ID.String(),
		ActorType: authn.KindUser, ActorID: u.ID.String(), Details: map[string]any{"method": "oidc", "issuer": id.Issuer, "groups": id.Groups}})
	return gen.OidcCallback302Response{Headers: gen.OidcCallback302ResponseHeaders{Location: safeNext(&next)}}, nil
}

// TestAuthentication fetches an issuer's discovery document and JWKS.
func (s *Server) TestAuthentication(ctx context.Context, req gen.TestAuthenticationRequestObject) (gen.TestAuthenticationResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsWrite, nil); err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Issuer == "" {
		return nil, unprocessable("issuer", "issuer is required")
	}
	res, err := s.d.OIDC.Test(ctx, req.Body.Issuer)
	if err != nil {
		return gen.TestAuthentication200JSONResponse{Ok: false, Detail: ptr(err.Error())}, nil
	}
	return gen.TestAuthentication200JSONResponse{Ok: true, AuthorizationEndpoint: &res.AuthorizationEndpoint,
		TokenEndpoint: &res.TokenEndpoint, Keys: &res.Keys}, nil
}
