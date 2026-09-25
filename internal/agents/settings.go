// Package agents is the server side of certforge-agent: clients and
// enrolment, grants and desired revisions, assignments, bundles, reports,
// heartbeat drift, and the agents settings section.
package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/metril/certforge/internal/settings"
)

// SettingsSection is the global settings section for agents.
const SettingsSection = "agents"

const settingsSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "agentUrl": {"type": "string", "title": "Agent URL", "description": "The address agents dial, put into every enrolment token. Empty means https://<CF_BASE_URL host>:8443.", "pattern": "^(https://[^\\s/]+/?)?$", "examples": ["https://certforge.example.com:8443"]},
    "listenerNames": {"type": "array", "title": "Listener names", "description": "DNS names and IP addresses on the agent listener's certificate. The Agent URL's host is always added. Empty means the CF_BASE_URL host and localhost.", "items": {"type": "string", "maxLength": 253}, "maxItems": 20, "default": []},
    "tokenTtlHours": {"type": "integer", "title": "Enrolment token lifetime (hours)", "description": "How long a new client's one-time token stays usable.", "minimum": 1, "maximum": 720, "default": 24},
    "agentCertDays": {"type": "integer", "title": "Agent certificate lifetime (days)", "description": "Lifetime of the client certificate an agent gets at enrolment; agents renew at two thirds.", "minimum": 7, "maximum": 365, "default": 90},
    "heartbeatSeconds": {"type": "integer", "title": "Heartbeat interval (seconds)", "description": "How often agents report installed files for drift detection.", "minimum": 15, "maximum": 3600, "default": 60},
    "offlineAfterSeconds": {"type": "integer", "title": "Offline after (seconds)", "description": "A client not seen for this long shows as offline.", "minimum": 30, "maximum": 86400, "default": 180}
  }
}`

const settingsDefault = `{"agentUrl":"","listenerNames":[],"tokenTtlHours":24,"agentCertDays":90,"heartbeatSeconds":60,"offlineAfterSeconds":180}`

// Settings is the agents section. Get and Resolve return it with defaults filled.
type Settings struct {
	AgentURL            string   `json:"agentUrl"`
	ListenerNames       []string `json:"listenerNames"`
	TokenTTLHours       int      `json:"tokenTtlHours"`
	AgentCertDays       int      `json:"agentCertDays"`
	HeartbeatSeconds    int      `json:"heartbeatSeconds"`
	OfflineAfterSeconds int      `json:"offlineAfterSeconds"`
}

// RegisterSettings adds the agents section and its extra checks.
func RegisterSettings(r *settings.Registry) error {
	if err := r.Register(SettingsSection, json.RawMessage(settingsSchema), json.RawMessage(settingsDefault)); err != nil {
		return err
	}
	return r.AddCheck(SettingsSection, checkSettings)
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validDNSName(s string) bool {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !dnsLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func checkSettings(raw json.RawMessage) error {
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	if s.AgentURL != "" {
		u, err := url.Parse(s.AgentURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return errors.New("agentUrl must be https://host[:port] with no path")
		}
	}
	for _, n := range s.ListenerNames {
		if net.ParseIP(n) == nil && !validDNSName(n) {
			return fmt.Errorf("listenerNames: %q is not a DNS name or IP address", n)
		}
	}
	if s.HeartbeatSeconds > 0 && s.OfflineAfterSeconds > 0 && s.OfflineAfterSeconds <= s.HeartbeatSeconds {
		return errors.New("offlineAfterSeconds must be longer than heartbeatSeconds")
	}
	return nil
}

// Resolve fills defaults: agentUrl from baseURL's host on port 8443, listener
// names from that host plus localhost, and zero numbers from the schema defaults.
func Resolve(s Settings, baseURL string) Settings {
	host := "localhost"
	if u, err := url.Parse(baseURL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	if s.AgentURL == "" {
		s.AgentURL = "https://" + net.JoinHostPort(host, "8443")
	}
	s.AgentURL = strings.TrimRight(s.AgentURL, "/")
	if len(s.ListenerNames) == 0 {
		s.ListenerNames = []string{host, "localhost"}
	}
	if s.TokenTTLHours <= 0 {
		s.TokenTTLHours = 24
	}
	if s.AgentCertDays <= 0 {
		s.AgentCertDays = 90
	}
	if s.HeartbeatSeconds <= 0 {
		s.HeartbeatSeconds = 60
	}
	if s.OfflineAfterSeconds <= 0 {
		s.OfflineAfterSeconds = 180
	}
	return s
}

// Names are the agent listener certificate's names: listenerNames plus the
// agentUrl host, lower-cased and de-duplicated, in that order.
func (s Settings) Names() []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(n string) {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range s.ListenerNames {
		add(n)
	}
	if u, err := url.Parse(s.AgentURL); err == nil {
		add(u.Hostname())
	}
	return out
}

// TokenTTL is the enrolment token lifetime.
func (s Settings) TokenTTL() time.Duration { return time.Duration(s.TokenTTLHours) * time.Hour }

// AgentCertLifetime is the lifetime of an agent client certificate.
func (s Settings) AgentCertLifetime() time.Duration {
	return time.Duration(s.AgentCertDays) * 24 * time.Hour
}

// SettingsSource caches the resolved agents section for 30 s. PUT
// /settings/agents calls Invalidate.
type SettingsSource struct {
	baseURL string
	ttl     time.Duration
	now     func() time.Time
	load    func(ctx context.Context) (Settings, error)

	mu    sync.Mutex
	cur   Settings
	at    time.Time
	valid bool
	gen   uint64
}

// NewSettingsSource reads the registered agents section from store.
func NewSettingsSource(store *settings.Store, reg *settings.Registry, baseURL string) (*SettingsSource, error) {
	sec, ok := reg.Section(SettingsSection)
	if !ok {
		return nil, errors.New("agents: settings section not registered")
	}
	return &SettingsSource{baseURL: baseURL, ttl: 30 * time.Second, now: time.Now,
		load: func(ctx context.Context) (Settings, error) {
			raw, _, err := store.GetSection(ctx, sec)
			if err != nil {
				return Settings{}, err
			}
			var s Settings
			if err := json.Unmarshal(raw, &s); err != nil {
				return Settings{}, fmt.Errorf("agents: decode settings: %w", err)
			}
			return s, nil
		}}, nil
}

// StaticSettings always yields Resolve(st, baseURL) (tests and tools).
func StaticSettings(st Settings, baseURL string) *SettingsSource {
	return &SettingsSource{baseURL: baseURL, ttl: time.Hour, now: time.Now,
		load: func(context.Context) (Settings, error) { return st, nil }}
}

// BaseURL is the CF_BASE_URL the defaults derive from.
func (s *SettingsSource) BaseURL() string { return s.baseURL }

// Get returns the resolved settings; on a load error it keeps serving the
// last good value, or returns the error when there is none.
func (s *SettingsSource) Get(ctx context.Context) (Settings, error) {
	s.mu.Lock()
	if s.valid && s.now().Sub(s.at) < s.ttl {
		cur := s.cur
		s.mu.Unlock()
		return cur, nil
	}
	gen := s.gen
	s.mu.Unlock()
	raw, err := s.load(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if s.valid {
			return s.cur, nil
		}
		return Settings{}, err
	}
	r := Resolve(raw, s.baseURL)
	if gen == s.gen {
		s.cur, s.at, s.valid = r, s.now(), true
	}
	return r, nil
}

// Invalidate drops the cache; a load in flight does not repopulate it.
func (s *SettingsSource) Invalidate() {
	s.mu.Lock()
	s.valid = false
	s.gen++
	s.mu.Unlock()
}
