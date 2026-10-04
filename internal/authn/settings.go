package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/metril/certforge/internal/settings"
)

// SettingsSection is the settings section holding OIDC, session and proxy config.
const SettingsSection = "authentication"

const authSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "enabled": {"type": "boolean", "title": "Single sign-on", "description": "Show the single sign-on button on the login page.", "default": false},
    "issuer": {"type": "string", "title": "Issuer URL", "description": "The OIDC issuer; CertForge reads its discovery document.", "pattern": "^https?://[^\\s]+$", "examples": ["https://login.example.com/realms/main"]},
    "clientId": {"type": "string", "title": "Client ID", "description": "The client registered for CertForge at the identity provider.", "maxLength": 200, "examples": ["certforge"]},
    "clientSecret": {"type": "string", "title": "Client secret", "description": "Leave empty for a public client using PKCE only.", "secret": true, "maxLength": 1024},
    "scopes": {"type": "array", "title": "Scopes", "description": "Requested scopes; must include openid.", "items": {"type": "string"}, "default": ["openid", "profile", "email", "groups"]},
    "groupsClaim": {"type": "string", "title": "Groups claim", "description": "ID token claim listing the user's groups; group role bindings match these. A dotted path (realm_access.roles) reads a nested claim.", "default": "groups", "maxLength": 128},
    "sessionTtlHours": {"type": "integer", "title": "Session lifetime (hours)", "description": "How long a sign-in lasts. Applies to new sessions.", "minimum": 1, "maximum": 720, "default": 12},
    "trustedProxies": {"type": "array", "title": "Trusted proxies", "description": "Addresses or CIDRs of reverse proxies whose X-Forwarded-For is believed.", "items": {"type": "string"}, "default": [], "examples": [["10.0.0.0/8"]]},
    "loginRatePerMinute": {"type": "integer", "title": "Login rate limit (per minute)", "description": "Login attempts allowed per client address per minute. 0 disables the limit.", "minimum": 0, "default": 10},
    "loginBurst": {"type": "integer", "title": "Login rate limit burst", "description": "Login attempts a client may make in a single burst before the per-minute rate applies.", "minimum": 1, "default": 5}
  }
}`

const authDefault = `{"enabled":false,"scopes":["openid","profile","email","groups"],"groupsClaim":"groups","sessionTtlHours":12,"trustedProxies":[],"loginRatePerMinute":10,"loginBurst":5}`

// AuthSettings is the decoded authentication section plus its secret.
type AuthSettings struct {
	Enabled         bool     `json:"enabled"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"clientId"`
	Scopes          []string `json:"scopes"`
	GroupsClaim     string   `json:"groupsClaim"`
	SessionTTLHours int      `json:"sessionTtlHours"`
	TrustedProxies  []string `json:"trustedProxies"`
	// LoginRatePerMinute is the per-client login attempt limit; <= 0 disables
	// the limit (matches Limiter's own semantics).
	LoginRatePerMinute int    `json:"loginRatePerMinute"`
	LoginBurst         int    `json:"loginBurst"`
	ClientSecret       string `json:"-"`
	proxies            []netip.Prefix
}

// LogValue redacts ClientSecret so AuthSettings is safe to log.
func (s AuthSettings) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("enabled", s.Enabled),
		slog.String("issuer", s.Issuer),
		slog.String("clientId", s.ClientID),
		slog.Int("sessionTtlHours", s.SessionTTLHours),
		slog.Int("loginRatePerMinute", s.LoginRatePerMinute),
		slog.Int("loginBurst", s.LoginBurst),
	)
}

// String redacts ClientSecret so AuthSettings is safe to print or interpolate.
func (s AuthSettings) String() string {
	return fmt.Sprintf("AuthSettings{Enabled:%v Issuer:%q ClientID:%q ClientSecret:REDACTED SessionTTLHours:%d LoginRatePerMinute:%d LoginBurst:%d}",
		s.Enabled, s.Issuer, s.ClientID, s.SessionTTLHours, s.LoginRatePerMinute, s.LoginBurst)
}

// RegisterSettings adds the authentication section and its extra checks.
// allowInsecureIssuer (CF_OIDC_ALLOW_INSECURE_ISSUER) admits a plain http://
// issuer on a non-loopback host; otherwise http is accepted for loopback only.
func RegisterSettings(r *settings.Registry, allowInsecureIssuer bool) error {
	if err := r.Register(SettingsSection, json.RawMessage(authSchema), json.RawMessage(authDefault)); err != nil {
		return err
	}
	return r.AddCheck(SettingsSection, func(raw json.RawMessage) error { return checkAuthSettings(raw, allowInsecureIssuer) })
}

func checkAuthSettings(raw json.RawMessage, allowInsecureIssuer bool) error {
	var s AuthSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	if _, err := parseProxies(s.TrustedProxies); err != nil {
		return err
	}
	if err := checkIssuerScheme(s.Issuer, allowInsecureIssuer); err != nil {
		return err
	}
	if s.Enabled && (s.Issuer == "" || s.ClientID == "") {
		return errors.New("issuer and clientId are required when single sign-on is enabled")
	}
	if len(s.Scopes) > 0 && !slices.Contains(s.Scopes, "openid") {
		return errors.New("scopes must include openid")
	}
	return nil
}

// checkIssuerScheme requires an https issuer, except plain http on a
// loopback host (localhost, 127.0.0.0/8, ::1) or when allowInsecure is set.
func checkIssuerScheme(issuer string, allowInsecure bool) error {
	if issuer == "" || allowInsecure {
		return nil
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("issuer: invalid URL: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Unmap().IsLoopback() {
			return nil
		}
	} else if strings.EqualFold(host, "localhost") {
		return nil
	}
	return errors.New("issuer: must use https unless the host is loopback")
}

func parseProxies(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("trustedProxies: %q is not an IP address or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func (s *AuthSettings) normalize() {
	if len(s.Scopes) == 0 {
		s.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	if s.GroupsClaim == "" {
		s.GroupsClaim = "groups"
	}
	switch {
	case s.SessionTTLHours <= 0:
		s.SessionTTLHours = int(DefaultSessionTTL / time.Hour)
	case s.SessionTTLHours > 720:
		s.SessionTTLHours = 720
	}
	if s.LoginBurst <= 0 {
		// A zero burst would reject every login outright; only the rate
		// itself (LoginRatePerMinute) is allowed to mean "unlimited".
		s.LoginBurst = DefaultLoginBurst
	}
	s.proxies, _ = parseProxies(s.TrustedProxies)
}

// OIDCReady reports whether single sign-on is enabled and configured.
func (s AuthSettings) OIDCReady() bool { return s.Enabled && s.Issuer != "" && s.ClientID != "" }

// SessionTTL is the lifetime of new sessions.
func (s AuthSettings) SessionTTL() time.Duration { return time.Duration(s.SessionTTLHours) * time.Hour }

// RemoteIP is the request's socket peer address without the port.
func RemoteIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// ClientIP returns the client address. X-Forwarded-For is believed only when
// the peer is a trusted proxy; the walk goes right to left over trusted hops
// and returns the first untrusted one, so a client cannot prepend a fake hop.
func (s AuthSettings) ClientIP(r *http.Request) string {
	remote := RemoteIP(r)
	addr, err := netip.ParseAddr(remote)
	if err != nil {
		return remote
	}
	addr = addr.Unmap()
	if !s.trusted(addr) {
		return addr.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			return addr.String()
		}
		a = a.Unmap()
		if !s.trusted(a) {
			return a.String()
		}
		addr = a
	}
	return addr.String()
}

// TrustedProxy reports whether r's TCP peer is one of the configured
// trusted proxies, for callers (such as the cookie Secure flag) that need to
// know whether X-Forwarded-Proto from this request can be believed.
func (s AuthSettings) TrustedProxy(r *http.Request) bool {
	addr, err := netip.ParseAddr(RemoteIP(r))
	if err != nil {
		return false
	}
	return s.trusted(addr)
}

func (s AuthSettings) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// negativeCacheTTL is how long Get keeps returning a reload error before
// trying the store again, so a client whose store is down (or whose KEK is
// briefly wrong) does not get hammered by every request that needs settings.
const negativeCacheTTL = 5 * time.Second

// SettingsSource caches the authentication section for 30 s. PUT
// /settings/authentication calls Invalidate.
type SettingsSource struct {
	sec *settings.Section
	ttl time.Duration
	now func() time.Time
	// load reads the section fresh from the store; a field (not a direct
	// store call) so tests can substitute a fake without a database.
	load func(ctx context.Context) (AuthSettings, error)

	mu      sync.Mutex
	cond    *sync.Cond
	cur     AuthSettings
	at      time.Time
	valid   bool
	loading bool // a reload is already in flight in another goroutine
	// gen counts Invalidate calls. It is captured before a load starts;
	// if it has changed by the time the load finishes, Invalidate ran
	// concurrently and the load's result (success or error) is discarded
	// instead of being cached — otherwise a load that read the store just
	// before a settings PUT could finish just after Invalidate and
	// resurrect the pre-PUT values as "fresh" for up to ttl.
	gen     uint64
	lastErr error
	errAt   time.Time
}

// NewSettingsSource reads the registered authentication section from store.
func NewSettingsSource(store *settings.Store, reg *settings.Registry) (*SettingsSource, error) {
	sec, ok := reg.Section(SettingsSection)
	if !ok {
		return nil, errors.New("authn: authentication settings section not registered")
	}
	s := &SettingsSource{sec: sec, ttl: 30 * time.Second, now: time.Now}
	s.cond = sync.NewCond(&s.mu)
	s.load = func(ctx context.Context) (AuthSettings, error) {
		raw, _, err := store.GetSection(ctx, sec)
		if err != nil {
			return AuthSettings{}, err
		}
		var st AuthSettings
		if err := json.Unmarshal(raw, &st); err != nil {
			return AuthSettings{}, fmt.Errorf("authn: decode settings: %w", err)
		}
		secrets, err := store.SectionSecrets(ctx, sec)
		if err != nil {
			return AuthSettings{}, err
		}
		st.ClientSecret = secrets["clientSecret"]
		st.normalize()
		return st, nil
	}
	return s, nil
}

// Get returns the current settings, reloading after the cache expires. The
// mutex is never held across the store round trip. Once the cache is known
// stale (or there is nothing cached yet), at most one goroutine actually
// reloads; a caller that arrives while a reload is already in flight either
// gets the still-valid stale value back immediately (if there is one) or
// waits on that same reload via cond (cold start, so there is nothing
// better to serve). With no cached value at all yet and every reload so far
// failing, a reload error is remembered for negativeCacheTTL so repeated
// callers don't retry a failing store on every request. A generation
// counter (see gen) stops a load that was already in flight when Invalidate
// ran from caching its now-stale result.
func (s *SettingsSource) Get(ctx context.Context) (AuthSettings, error) {
	s.mu.Lock()
	for {
		if s.valid && s.now().Sub(s.at) < s.ttl {
			cur := s.cur
			s.mu.Unlock()
			return cur, nil
		}
		if s.loading {
			if s.valid {
				// Someone else is already reloading; the stale value is
				// still better than blocking on a second concurrent DB
				// round trip.
				cur := s.cur
				s.mu.Unlock()
				return cur, nil
			}
			// Cold start (or every load so far has failed): there is
			// nothing useful to serve without waiting, so wait for the
			// in-flight load instead of racing it with a duplicate.
			s.cond.Wait()
			continue
		}
		if !s.valid && s.lastErr != nil && s.now().Sub(s.errAt) < negativeCacheTTL {
			err := s.lastErr
			s.mu.Unlock()
			return AuthSettings{}, err
		}
		break
	}
	s.loading = true
	gen := s.gen
	s.mu.Unlock()

	st, err := s.load(ctx)

	s.mu.Lock()
	s.loading = false
	s.cond.Broadcast()
	if gen != s.gen {
		// Invalidated while this load was in flight: its result (success
		// or error) is stale/moot either way. Discard it and retry rather
		// than caching pre-invalidation data as if it were fresh, or a
		// spurious error past the point the caller asked to drop the cache.
		s.mu.Unlock()
		return s.Get(ctx)
	}
	if err != nil {
		s.lastErr, s.errAt = err, s.now()
		if s.valid {
			cur := s.cur
			s.mu.Unlock()
			return cur, nil // keep serving the last known-good value
		}
		s.mu.Unlock()
		return AuthSettings{}, err
	}
	s.lastErr = nil
	s.cur, s.at, s.valid = st, s.now(), true
	s.mu.Unlock()
	return st, nil
}

// Invalidate drops the cached settings. A load already in flight when this
// runs is not allowed to resurrect the value being dropped (see gen).
func (s *SettingsSource) Invalidate() {
	s.mu.Lock()
	s.valid = false
	s.lastErr = nil
	s.gen++
	s.mu.Unlock()
}
