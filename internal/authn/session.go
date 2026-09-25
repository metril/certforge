package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// Cookie, header, and lifetime defaults.
const (
	CookieName        = "cf_session"
	CSRFHeader        = "X-CSRF-Token"
	DefaultSessionTTL = 12 * time.Hour
)

// ErrNoSession means the token is unknown or expired.
var ErrNoSession = errors.New("authn: no active session")

// Sessions manages server-side sessions stored in Postgres.
type Sessions struct {
	q   *sqlcgen.Queries
	ttl time.Duration
	now func() time.Time
}

// NewSessions returns a session manager with the given lifetime.
func NewSessions(q *sqlcgen.Queries, ttl time.Duration) *Sessions {
	return &Sessions{q: q, ttl: ttl, now: time.Now}
}

// SetClock replaces the clock (tests only).
func (s *Sessions) SetClock(now func() time.Time) { s.now = now }

// Create starts a session with the default lifetime.
func (s *Sessions) Create(ctx context.Context, userID uuid.UUID) (string, sqlcgen.Session, error) {
	return s.CreateTTL(ctx, userID, s.ttl)
}

// CreateTTL starts a session that lasts ttl. The returned token goes in the
// cookie; only its SHA-256 is stored.
func (s *Sessions) CreateTTL(ctx context.Context, userID uuid.UUID, ttl time.Duration) (string, sqlcgen.Session, error) {
	token, err := randomToken()
	if err != nil {
		return "", sqlcgen.Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", sqlcgen.Session{}, err
	}
	sess, err := s.q.CreateSession(ctx, sqlcgen.CreateSessionParams{
		ID: hashToken(token), UserID: userID, Csrf: csrf, ExpiresAt: s.now().Add(ttl),
	})
	if err != nil {
		return "", sqlcgen.Session{}, err
	}
	return token, sess, nil
}

// Lookup returns the unexpired session for token.
func (s *Sessions) Lookup(ctx context.Context, token string) (sqlcgen.Session, error) {
	sess, err := s.q.GetActiveSession(ctx, sqlcgen.GetActiveSessionParams{ID: hashToken(token), Now: s.now()})
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlcgen.Session{}, ErrNoSession
	}
	return sess, err
}

// Delete ends the session with the given stored id.
func (s *Sessions) Delete(ctx context.Context, sessionID string) error {
	return s.q.DeleteSession(ctx, sessionID)
}

// PurgeExpired deletes expired sessions and returns how many were removed.
func (s *Sessions) PurgeExpired(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredSessions(ctx, s.now())
}

// Cookie builds the session cookie.
func (s *Sessions) Cookie(token string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
}

// ClearCookie builds a cookie that deletes the session cookie.
func (s *Sessions) ClearCookie(secure bool) *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}
