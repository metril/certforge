package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

var errInvalidCredentials = &HTTPError{Status: http.StatusUnauthorized, Title: "Invalid credentials"}

var errPasswordTooLong = &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid password",
	Detail: fmt.Sprintf("password must not exceed %d bytes", authn.MaxPasswordLength)}

// Login authenticates the local admin and starts a session.
func (s *Server) Login(ctx context.Context, req gen.LoginRequestObject) (gen.LoginResponseObject, error) {
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	// Reject before the database round trip or any hashing: a password this
	// long can only be a resource-exhaustion attempt, not a real one.
	if len(req.Body.Password) > authn.MaxPasswordLength {
		return nil, errPasswordTooLong
	}
	admin, err := s.d.Queries.GetLocalAdmin(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		authn.EqualizeTiming(req.Body.Password)
		return nil, errInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	ok, err := authn.VerifyPassword(*admin.LocalPasswordHash, req.Body.Password)
	if errors.Is(err, authn.ErrBusy) {
		writeRetryAfter(ctx, "1")
		return nil, errTooBusy
	}
	if err != nil {
		return nil, err
	}
	if !ok || admin.Disabled {
		s.audit(ctx, audit.Event{Action: "session.login_failed", ResourceType: "user", ResourceID: admin.ID.String(),
			ActorType: "anonymous", Details: map[string]any{"method": "local"}})
		return nil, errInvalidCredentials
	}
	s.rehashPassword(ctx, admin.ID, *admin.LocalPasswordHash, req.Body.Password)
	me, err := s.startSession(ctx, admin.ID)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "session.login", ResourceType: "user", ResourceID: admin.ID.String(),
		ActorType: authn.KindUser, ActorID: admin.ID.String(), Details: map[string]any{"method": "local"}})
	return gen.Login200JSONResponse(me), nil
}

// rehashPassword stores a fresh hash after a successful login when the stored
// one used other argon2 parameters. Best effort: a busy semaphore or a failed
// write never fails the login.
func (s *Server) rehashPassword(ctx context.Context, id uuid.UUID, stored, pw string) {
	if !authn.NeedsRehash(stored) {
		return
	}
	hash, err := authn.HashPassword(pw)
	if err == nil {
		err = s.d.Queries.SetLocalPasswordHash(ctx, sqlcgen.SetLocalPasswordHashParams{ID: id, Hash: hash})
	}
	if err != nil {
		s.d.Log.Warn("password rehash skipped", "err", err)
	}
}

// Logout ends the current session.
func (s *Server) Logout(ctx context.Context, _ gen.LogoutRequestObject) (gen.LogoutResponseObject, error) {
	sess, ok := authn.SessionFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	if err := s.d.Sessions.Delete(ctx, sess.ID); err != nil {
		return nil, err
	}
	w, r := httpFrom(ctx)
	http.SetCookie(w, s.d.Sessions.ClearCookie(s.secureCookie(ctx, r)))
	s.audit(ctx, audit.Event{Action: "session.logout", ResourceType: "user", ResourceID: sess.UserID.String()})
	return gen.Logout204Response{}, nil
}

// errSessionOnly is returned by GetMe for an authenticated API-key
// principal: the endpoint returns the session's CSRF token, which an API
// key never has, so it is session-only rather than merely unauthenticated.
var errSessionOnly = &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "session-only endpoint"}

// GetMe returns the current principal and its CSRF token.
func (s *Server) GetMe(ctx context.Context, _ gen.GetMeRequestObject) (gen.GetMeResponseObject, error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	sess, ok2 := authn.SessionFrom(ctx)
	if !ok2 {
		if p.Kind == authn.KindAPIKey {
			return nil, errSessionOnly
		}
		return nil, errUnauthenticated
	}
	u, err := s.d.Queries.GetUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	me, err := s.buildMe(ctx, u, p, sess.Csrf)
	if err != nil {
		return nil, err
	}
	return gen.GetMe200JSONResponse(me), nil
}

// startSession creates a session for userID and returns Me. The cf_session
// cookie is set only once every step has succeeded; on any later failure the
// session is deleted (best effort) so a failed login never leaves a valid
// cookie or session behind.
func (s *Server) startSession(ctx context.Context, userID uuid.UUID) (gen.Me, error) {
	n, err := s.d.Queries.DeleteUserSessions(ctx, userID)
	if err != nil {
		return gen.Me{}, err
	}
	if n > 0 {
		s.audit(ctx, audit.Event{Action: "session.revoked", ResourceType: "user", ResourceID: userID.String(),
			ActorType: authn.KindUser, ActorID: userID.String(), Details: map[string]any{"count": n, "reason": "new_login"}})
	}
	token, sess, err := s.d.Sessions.CreateTTL(ctx, userID, s.sessionTTL(ctx))
	if err != nil {
		return gen.Me{}, err
	}
	me, err := s.finishSession(ctx, userID, sess)
	if err != nil {
		if delErr := s.d.Sessions.Delete(ctx, sess.ID); delErr != nil {
			s.d.Log.Error("session cleanup after failed login failed", "err", delErr)
		}
		return gen.Me{}, err
	}
	w, r := httpFrom(ctx)
	http.SetCookie(w, s.d.Sessions.Cookie(token, sess.ExpiresAt, s.secureCookie(ctx, r)))
	return me, nil
}

// sessionTTL is the configured session lifetime, or the default.
func (s *Server) sessionTTL(ctx context.Context) time.Duration {
	if s.d.AuthSettings != nil {
		if st, err := s.d.AuthSettings.Get(ctx); err == nil {
			return st.SessionTTL()
		}
	}
	return authn.DefaultSessionTTL
}

// GetAuthMethods tells the login page which sign-in methods exist. Public.
func (s *Server) GetAuthMethods(ctx context.Context, _ gen.GetAuthMethodsRequestObject) (gen.GetAuthMethodsResponseObject, error) {
	oidcOn := false
	if s.d.AuthSettings != nil {
		st, err := s.d.AuthSettings.Get(ctx)
		if err != nil {
			return nil, err
		}
		oidcOn = st.OIDCReady()
	}
	_, err := s.d.Queries.GetLocalAdmin(ctx)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	callback := strings.TrimRight(s.baseURL(ctx), "/") + "/api/v1/auth/oidc/callback"
	return gen.GetAuthMethods200JSONResponse{OidcEnabled: oidcOn, LocalEnabled: err == nil, OidcCallbackUrl: callback}, nil
}

// finishSession builds Me for a just-created session, without touching the cookie.
func (s *Server) finishSession(ctx context.Context, userID uuid.UUID, sess sqlcgen.Session) (gen.Me, error) {
	if err := s.d.Queries.TouchUserLogin(ctx, userID); err != nil {
		return gen.Me{}, err
	}
	u, err := s.d.Queries.GetUser(ctx, userID)
	if err != nil {
		return gen.Me{}, err
	}
	p, err := authn.LoadPrincipal(ctx, s.d.Queries, u)
	if err != nil {
		return gen.Me{}, err
	}
	return s.buildMe(ctx, u, p, sess.Csrf)
}

func (s *Server) buildMe(ctx context.Context, u sqlcgen.User, p authn.Principal, csrf string) (gen.Me, error) {
	orgs, err := s.d.Queries.ListOrgs(ctx)
	if err != nil {
		return gen.Me{}, err
	}
	bindings := make([]gen.MeBinding, 0, len(p.Bindings))
	for _, b := range p.Bindings {
		bindings = append(bindings, gen.MeBinding{Role: gen.Role(b.Role), OrgId: b.OrgID})
	}
	return gen.Me{
		User:      gen.User{Id: u.ID, DisplayName: u.DisplayName, LocalAdmin: u.LocalPasswordHash != nil},
		Roles:     append([]string{}, p.Roles...),
		Bindings:  bindings,
		Orgs:      visibleOrgs(p, orgs),
		CsrfToken: csrf,
	}, nil
}

// baseURL is the General section's base URL, else CF_BASE_URL.
func (s *Server) baseURL(ctx context.Context) string {
	var g struct {
		BaseURL string `json:"baseUrl"`
	}
	if err := s.d.Settings.Get(ctx, settings.SectionKey("general"), &g); err == nil && g.BaseURL != "" {
		return g.BaseURL
	}
	return s.d.Config.BaseURL
}

// secureCookie is true over TLS, when the effective base URL is https, or
// when the request arrived from a configured trusted proxy that terminated
// TLS itself (X-Forwarded-Proto: https) — otherwise a deployment behind such
// a proxy would never get Secure cookies at all.
func (s *Server) secureCookie(ctx context.Context, r *http.Request) bool {
	if r != nil && r.TLS != nil {
		return true
	}
	if r != nil && s.d.AuthSettings != nil {
		if st, err := s.d.AuthSettings.Get(ctx); err == nil && st.TrustedProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https" {
			return true
		}
	}
	return strings.HasPrefix(s.baseURL(ctx), "https://")
}
