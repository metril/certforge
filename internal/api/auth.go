package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

var errInvalidCredentials = &HTTPError{Status: http.StatusUnauthorized, Title: "Invalid credentials"}

// Login authenticates the local admin and starts a session.
func (s *Server) Login(ctx context.Context, req gen.LoginRequestObject) (gen.LoginResponseObject, error) {
	if req.Body == nil {
		return nil, badRequest("missing body")
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
	if err != nil {
		return nil, err
	}
	if !ok || admin.Disabled {
		s.audit(ctx, audit.Event{Action: "auth.login_failed", ResourceType: "user", ResourceID: admin.ID.String(), ActorType: "anonymous"})
		return nil, errInvalidCredentials
	}
	me, err := s.startSession(ctx, admin.ID)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "auth.login", ResourceType: "user", ResourceID: admin.ID.String(),
		ActorType: authn.KindUser, ActorID: admin.ID.String()})
	return gen.Login200JSONResponse(me), nil
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
	s.audit(ctx, audit.Event{Action: "auth.logout", ResourceType: "user", ResourceID: sess.UserID.String()})
	return gen.Logout204Response{}, nil
}

// GetMe returns the current principal and its CSRF token.
func (s *Server) GetMe(ctx context.Context, _ gen.GetMeRequestObject) (gen.GetMeResponseObject, error) {
	p, ok := authn.PrincipalFrom(ctx)
	sess, ok2 := authn.SessionFrom(ctx)
	if !ok || !ok2 {
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
	token, sess, err := s.d.Sessions.Create(ctx, userID)
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
	return gen.Me{
		User:      gen.User{Id: u.ID, DisplayName: u.DisplayName, LocalAdmin: u.LocalPasswordHash != nil},
		Roles:     append([]string{}, p.Roles...),
		Orgs:      visibleOrgs(p, orgs),
		CsrfToken: csrf,
	}, nil
}

// secureCookie is true over TLS or when the effective base URL is https.
func (s *Server) secureCookie(ctx context.Context, r *http.Request) bool {
	if r != nil && r.TLS != nil {
		return true
	}
	var g struct {
		BaseURL string `json:"baseUrl"`
	}
	if err := s.d.Settings.Get(ctx, settings.SectionKey("general"), &g); err == nil && g.BaseURL != "" {
		return strings.HasPrefix(g.BaseURL, "https://")
	}
	return strings.HasPrefix(s.d.Config.BaseURL, "https://")
}
