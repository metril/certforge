package authn

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

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

// Middleware resolves the session cookie into a Principal. Session-authenticated
// mutating requests must carry a matching X-CSRF-Token. Requests without a
// valid session get 401 unless Public(r) is true.
func Middleware(o MiddlewareOptions) func(http.Handler) http.Handler {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			p, sess, err := o.resolve(ctx, r)
			if err != nil {
				o.Log.Error("session lookup failed", "err", err)
				o.Fail(w, http.StatusInternalServerError, "Internal server error", "")
				return
			}
			switch {
			case p != nil:
				if isMutating(r.Method) && !csrfOK(r, sess.Csrf) {
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
