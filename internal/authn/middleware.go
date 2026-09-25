package authn

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// FailFunc writes an error response (api.Write in production).
type FailFunc func(w http.ResponseWriter, status int, title, detail string)

// MiddlewareOptions configures Middleware.
type MiddlewareOptions struct {
	Sessions *Sessions
	Queries  *sqlcgen.Queries
	Public   func(r *http.Request) bool
	Fail     FailFunc
	Log      *slog.Logger
}

// Middleware resolves the session cookie or an API key bearer token into a
// Principal. An Authorization header of the form "Bearer cf_<prefix>_<secret>"
// (the "Bearer" scheme matched case-insensitively, per RFC 9110 §11.1) is
// tried first and, when malformed, unknown, expired, revoked, or its
// creator disabled, fails the request with 401 without falling back to the
// cookie; any other scheme or bearer content (a reverse proxy's Basic
// header, a "Bearer <jwt>") is ignored and the request falls through to the
// cookie session below. Session-authenticated mutating requests to
// non-public routes must carry a matching X-CSRF-Token; API keys never
// need one. Requests without a valid session get 401 unless Public(r) is true.
func Middleware(o MiddlewareOptions) func(http.Handler) http.Handler {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if h := r.Header.Get("Authorization"); len(h) >= 10 && strings.EqualFold(h[:7], "Bearer ") && strings.HasPrefix(h[7:], "cf_") {
				p, err := o.resolveBearer(ctx, h)
				if errors.Is(err, ErrBadAPIKey) {
					o.Fail(w, http.StatusUnauthorized, "Invalid API key", "The bearer token is malformed, unknown, expired, or revoked.")
					return
				}
				if err != nil {
					o.Log.Error("api key lookup failed", "err", err)
					o.Fail(w, http.StatusInternalServerError, "Internal server error", "")
					return
				}
				next.ServeHTTP(w, r.WithContext(WithPrincipal(ctx, *p)))
				return
			}
			p, sess, err := o.resolve(ctx, r)
			if err != nil {
				o.Log.Error("session lookup failed", "err", err)
				o.Fail(w, http.StatusInternalServerError, "Internal server error", "")
				return
			}
			switch {
			case p != nil:
				public := o.Public != nil && o.Public(r)
				if isMutating(r.Method) && !public && !csrfOK(r, sess.Csrf) {
					o.Fail(w, http.StatusForbidden, "CSRF token missing or invalid",
						"Send the csrfToken from GET /api/v1/auth/me in the "+CSRFHeader+" header.")
					return
				}
				ctx = WithPrincipal(ctx, *p)
				ctx = context.WithValue(ctx, sessionKey, sess)
			case o.Public == nil || !o.Public(r):
				o.Fail(w, http.StatusUnauthorized, "Authentication required", "")
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolve returns nil when the request has no usable session.
func (o MiddlewareOptions) resolve(ctx context.Context, r *http.Request) (*Principal, sqlcgen.Session, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, sqlcgen.Session{}, nil
	}
	sess, err := o.Sessions.Lookup(ctx, c.Value)
	if errors.Is(err, ErrNoSession) {
		return nil, sqlcgen.Session{}, nil
	}
	if err != nil {
		return nil, sqlcgen.Session{}, err
	}
	u, err := o.Queries.GetUser(ctx, sess.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sqlcgen.Session{}, nil
	}
	if err != nil {
		return nil, sqlcgen.Session{}, err
	}
	if u.Disabled {
		return nil, sqlcgen.Session{}, nil
	}
	p, err := LoadPrincipal(ctx, o.Queries, u)
	if err != nil {
		return nil, sqlcgen.Session{}, err
	}
	return &p, sess, nil
}

// resolveBearer authenticates "Bearer cf_<prefix>_<secret>". API keys
// never need a CSRF token: browsers cannot attach them cross-site.
func (o MiddlewareOptions) resolveBearer(ctx context.Context, header string) (*Principal, error) {
	if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
		return nil, ErrBadAPIKey
	}
	tok := header[7:]
	prefix, secret, ok := ParseAPIKeyToken(strings.TrimSpace(tok))
	if !ok {
		return nil, ErrBadAPIKey
	}
	k, err := o.Queries.GetAPIKeyByPrefix(ctx, prefix)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrBadAPIKey
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(k.SecretHash, HashAPIKeySecret(secret)) != 1 || k.RevokedAt != nil ||
		(k.ExpiresAt != nil && !time.Now().Before(*k.ExpiresAt)) {
		return nil, ErrBadAPIKey
	}
	u, err := o.Queries.GetUser(ctx, k.CreatedBy)
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrBadAPIKey
	}
	p, err := LoadAPIKeyPrincipal(ctx, o.Queries, u, k)
	if err != nil {
		return nil, err
	}
	if err := o.Queries.TouchAPIKey(ctx, k.ID); err != nil {
		o.Log.Warn("api key last-used update failed", "err", err)
	}
	return &p, nil
}

func isMutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

func csrfOK(r *http.Request, want string) bool {
	got := r.Header.Get(CSRFHeader)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
