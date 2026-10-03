package challenge

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/metril/certforge/internal/notify/httpx"
)

// Unchanged is the write-only sentinel: on update, a secret field with this
// value keeps the stored secret.
const Unchanged = "__unchanged__"

// ErrUnknownField is returned for config keys absent from the provider schema.
var ErrUnknownField = errors.New("unknown field")

// ErrUnknownProvider is returned for a provider code with no registered schema.
var ErrUnknownProvider = errors.New("unknown DNS provider")

// ErrUnchangedOnCreate is returned when Unchanged is used outside an update,
// where there is no stored secret for it to refer to.
var ErrUnchangedOnCreate = errors.New("value is only valid when updating a stored secret")

// ErrServerPath is returned for a config key that reads a local file path
// on the server (a schema field marked serverPath: true, named with a
// _FILE or _PATH suffix): the API has no access to the caller's server
// filesystem, so these are rejected in favor of the provider's inline
// field for the same credential.
var ErrServerPath = errors.New("reads a file path on the server and is not accepted from the API; use the inline field instead")

// ErrNoAuthMethod is returned when a config satisfies none of the provider's
// auth methods.
var ErrNoAuthMethod = errors.New("no complete auth method")

// ErrAliasConflict is returned when an alias key and its canonical key are
// both set to different values.
var ErrAliasConflict = errors.New("alias and canonical field set to different values")

// SplitConfig validates cfg against the provider schema and splits it into
// public (stored as jsonb) and secret (stored encrypted) parts. Empty values
// are dropped.
func SplitConfig(code string, cfg map[string]string) (public, secret map[string]string, err error) {
	e, ok := lookupEntry(code)
	if !ok {
		return nil, nil, fmt.Errorf("%w %q", ErrUnknownProvider, code)
	}
	public, secret = map[string]string{}, map[string]string{}
	cfg, err = canonicalize(e, cfg)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range cfg {
		isSecret, known := e.secret[k]
		if !known {
			return nil, nil, fmt.Errorf("%w %q for provider %s", ErrUnknownField, k, e.meta.Code)
		}
		if v == "" {
			continue
		}
		if e.serverPath[k] {
			return nil, nil, fmt.Errorf("%s: %w", k, ErrServerPath)
		}
		if v == Unchanged {
			return nil, nil, fmt.Errorf("%s: %q: %w", k, Unchanged, ErrUnchangedOnCreate)
		}
		if strings.ContainsRune(v, 0) {
			return nil, nil, fmt.Errorf("%s: value contains a NUL byte", k)
		}
		if isSecret {
			secret[k] = v
		} else {
			public[k] = v
		}
	}
	if err := checkAuth(e, public, secret); err != nil {
		return nil, nil, err
	}
	return public, secret, nil
}

// CanonicalizeStored renames alias keys in a stored (legacy) config to their
// canonical keys. On an alias conflict or unknown provider the input is
// returned unchanged.
func CanonicalizeStored(code string, cfg map[string]string) map[string]string {
	e, ok := lookupEntry(code)
	if !ok {
		return cfg
	}
	out, err := canonicalize(e, cfg)
	if err != nil {
		return cfg
	}
	return out
}

// canonicalize returns cfg with alias keys renamed to their canonical key.
// Unknown keys pass through untouched (the caller rejects them). An alias and
// canonical key both non-empty with different values is ErrAliasConflict.
func canonicalize(e *entry, cfg map[string]string) (map[string]string, error) {
	if len(e.aliasOf) == 0 {
		return cfg, nil
	}
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if _, isAlias := e.aliasOf[k]; !isAlias {
			out[k] = v
		}
	}
	keys := make([]string, 0, len(e.aliasOf))
	for a := range e.aliasOf {
		keys = append(keys, a)
	}
	sort.Strings(keys)
	for _, a := range keys {
		v, ok := cfg[a]
		if !ok {
			continue
		}
		c := e.aliasOf[a]
		if cur := out[c]; cur != "" && v != "" && cur != v {
			return nil, fmt.Errorf("%w: %s and %s", ErrAliasConflict, c, a)
		}
		if out[c] == "" {
			out[c] = v
		}
	}
	return out, nil
}

// checkAuth requires some auth method's fields to all be non-empty in the
// union of public and secret. Providers without methods are not checked.
func checkAuth(e *entry, public, secret map[string]string) error {
	ms := e.meta.AuthMethods
	if len(ms) == 0 {
		return nil
	}
	for _, m := range ms {
		ok := true
		for _, f := range m.Fields {
			if public[f] == "" && secret[f] == "" {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
	}
	parts := make([]string, len(ms))
	for i, m := range ms {
		if len(m.Fields) == 0 {
			parts[i] = m.Label + " (no fields)"
		} else {
			parts[i] = m.Label + " (" + strings.Join(m.Fields, ", ") + ")"
		}
	}
	return fmt.Errorf("%w: supply one of: %s", ErrNoAuthMethod, strings.Join(parts, " | "))
}

// MergeUpdate applies a full-replacement update. Secret keys set to Unchanged
// keep oldSecret's value (dropped if nothing was stored); every other key is
// taken from in, so a secret omitted from in is removed.
//
// changedPublic lists the public (non-secret) keys whose resolved value
// differs from oldPublic — added, removed or changed — sorted. reusedSecret
// reports whether in set any *secret* field to Unchanged. A caller that
// allows both at once lets an update silently repoint a stored secret at a
// changed connection setting (for example a provider's endpoint URL): the
// old secret value would be sent to the new destination without the caller
// ever having re-entered it. See issuance.Store.UpdateDNSCredential, which
// rejects that combination.
func MergeUpdate(code string, oldPublic, oldSecret, in map[string]string) (public, secret map[string]string, changedPublic []string, reusedSecret bool, err error) {
	e, ok := lookupEntry(code)
	if !ok {
		return nil, nil, nil, false, fmt.Errorf("%w %q", ErrUnknownProvider, code)
	}
	oldPublic, oldSecret = CanonicalizeStored(code, oldPublic), CanonicalizeStored(code, oldSecret)
	resolved := make(map[string]string, len(in))
	for k, v := range in {
		if v == Unchanged {
			if e.secret[k] {
				reusedSecret = true
			}
			if old, ok := oldSecret[k]; ok {
				resolved[k] = old
			}
			continue
		}
		resolved[k] = v
	}
	public, secret, err = SplitConfig(code, resolved)
	if err != nil {
		return nil, nil, nil, false, err
	}
	changedPublic = changedKeys(oldPublic, public)
	return public, secret, changedPublic, reusedSecret, nil
}

// changedKeys returns the sorted keys where new differs from old (added,
// removed, or a different value).
func changedKeys(old, new map[string]string) []string {
	var out []string
	for k, v := range new {
		if ov, ok := old[k]; !ok || ov != v {
			out = append(out, k)
		}
	}
	for k := range old {
		if _, ok := new[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// IsSecretField reports whether field is a secret property of the provider's
// schema (aliases of the provider code are resolved).
func IsSecretField(code, field string) bool {
	e, ok := lookupEntry(code)
	return ok && e.secret[field]
}

// SecretKeys returns the sorted secret keys present in secret, for API
// responses ("storedSecrets").
func SecretKeys(secret map[string]string) []string {
	out := make([]string, 0, len(secret))
	for k := range secret {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isURLField reports whether a schema property names a URL, endpoint or
// network host. The provider schemas carry no format marker, so this goes by
// the property name: a _URL, _ENDPOINT, _HOST, _HOSTNAME, _ADDRESS or
// _NAMESERVER suffix, or _BASE_URL / _API_BASE in the name.
func isURLField(name string) bool {
	for _, suf := range []string{"_URL", "_ENDPOINT", "_HOST", "_HOSTNAME", "_ADDRESS", "_NAMESERVER", "_API_BASE"} {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return strings.Contains(name, "_BASE_URL")
}

// regionAlias matches the symbolic OVH endpoint names (ovh-eu, kimsufi-ca,
// ...) that an _ENDPOINT field accepts instead of a URL.
var regionAlias = regexp.MustCompile(`^(ovh|kimsufi|soyoustart|runabove)-[a-z]{2}$`)

// CheckURLFields runs every URL-typed field of cfg through the notifier URL
// policy (httpx.CheckURL) so a credential cannot point the server at a
// loopback, link-local or cloud-metadata address. allowLoopback is the
// notifications section's allowLoopbackUrls; the metadata addresses stay
// blocked regardless. Empty values and the Unchanged sentinel are skipped, as
// are unknown fields (SplitConfig rejects those). A value without a scheme is
// checked as the host of https://<value>; the symbolic OVH region names
// ("ovh-eu") are skipped. The error names the first offending field (sorted order).
func CheckURLFields(code string, cfg map[string]string, allowLoopback bool) error {
	e, ok := lookupEntry(code)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.TrimSpace(cfg[k])
		if _, known := e.secret[k]; !known || !isURLField(k) || v == "" || v == Unchanged {
			continue
		}
		if regionAlias.MatchString(v) {
			continue
		}
		if !strings.Contains(v, "://") {
			// A bare host or host:port is checked as the host of an https URL.
			v = "https://" + v
		}
		if err := httpx.CheckURL(v, allowLoopback); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}
