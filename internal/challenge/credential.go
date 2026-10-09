package challenge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

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
	return dropRetired(e, out, false)
}

// dropRetired returns cfg without keys the provider schema no longer defines
// (a schema regeneration can retire a field that older stored credentials
// still carry). Only stored config goes through here; API input keeps being
// rejected with ErrUnknownField. With warn, one line per dropped key names the
// provider and key, never the value.
func dropRetired(e *entry, cfg map[string]string, warn bool) map[string]string {
	var out map[string]string
	for k := range cfg {
		if _, known := e.secret[k]; known {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(cfg))
			for k2, v := range cfg {
				out[k2] = v
			}
		}
		delete(out, k)
		if warn {
			slog.Warn("dropping stored DNS credential key the provider schema no longer defines", "provider", e.meta.Code, "key", k)
		}
	}
	if out == nil {
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
	oldPublic, oldSecret = dropRetired(e, oldPublic, true), dropRetired(e, oldSecret, true)
	oldPublic, oldSecret = CanonicalizeStored(code, oldPublic), CanonicalizeStored(code, oldSecret)
	resolved := make(map[string]string, len(in))
	for k, v := range in {
		if v == Unchanged {
			if e.secret[k] {
				reusedSecret = true
			}
			// oldSecret is canonical; an alias key must look up its canonical name.
			ck := k
			if c, isAlias := e.aliasOf[k]; isAlias {
				ck = c
			}
			if old, ok := oldSecret[ck]; ok {
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

// HostResolver resolves a hostname to its addresses; *net.Resolver
// satisfies it. Injectable so tests need no real DNS.
type HostResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// resolveTimeout bounds the save-time lookup of one credential field.
const resolveTimeout = 3 * time.Second

// metadataNames are well-known cloud-metadata hostnames, refused by name
// whatever they resolve to.
var metadataNames = map[string]bool{
	"metadata.google.internal": true, "metadata": true, "instance-data": true,
	"instance-data.ec2.internal": true, "metadata.azure.internal": true, "metadata.tencentyun.com": true,
}

// CheckURLFields runs every URL- or host-typed field of cfg through the
// notifier URL policy (httpx.CheckURL) and then resolves its hostname and
// classifies every resolved address the same way, so a credential cannot
// point the server at a loopback, link-local or cloud-metadata address, by
// literal or by name (lego providers dial with their own HTTP clients, so
// the dial-time check httpx applies is not available). allowLoopback is the
// notifications section's allowLoopbackUrls; the metadata addresses and
// names stay blocked regardless. A hostname that does not resolve is
// refused. Empty values and the Unchanged sentinel are skipped, as are
// unknown fields (SplitConfig rejects those). A value without a scheme is
// checked as the host of https://<value>; the symbolic OVH region names
// ("ovh-eu") are skipped. r nil uses net.DefaultResolver. The error names the
// first offending field (sorted order). The check runs at save time only.
func CheckURLFields(ctx context.Context, code string, cfg map[string]string, allowLoopback bool, r HostResolver) error {
	e, ok := lookupEntry(code)
	if !ok {
		return nil
	}
	if r == nil {
		r = net.DefaultResolver
	}
	// An alias key is checked under its canonical name (isURLField goes by name).
	if c, err := canonicalize(e, cfg); err == nil {
		cfg = c
	}
	if err := checkComposedHost(ctx, code, cfg, allowLoopback, r); err != nil {
		return err
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
		u, _ := url.Parse(v) // CheckURL parsed it
		if err := checkResolved(ctx, u.Hostname(), allowLoopback, r); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

// composedHost describes a provider whose library joins config fields into
// a request host (lego f5xc: https://<tenant>.<server>). Each field must be
// a bare DNS-name fragment, and the composed host is run through the same
// SSRF policy as a URL field.
type composedHost struct {
	fields   []string // in host order
	defaults map[string]string
}

var composedHosts = map[string]composedHost{
	"f5xc": {fields: []string{"F5XC_TENANT_NAME", "F5XC_SERVER"}, defaults: map[string]string{"F5XC_SERVER": "console.ves.volterra.io"}},
}

// hostFragmentForbidden are characters that would let a field change the
// authority, path or query of the host it is spliced into.
const hostFragmentForbidden = "@/#?:\\"

func checkComposedHost(ctx context.Context, code string, cfg map[string]string, allowLoopback bool, r HostResolver) error {
	ch, ok := composedHosts[code]
	if !ok {
		return nil
	}
	parts := make([]string, 0, len(ch.fields))
	for _, f := range ch.fields {
		v := strings.TrimSpace(cfg[f])
		if v == Unchanged {
			return nil // the stored value was checked when it was saved
		}
		if v == "" {
			v = ch.defaults[f]
		}
		if v == "" {
			return nil // required-field validation reports the gap
		}
		if strings.ContainsAny(v, hostFragmentForbidden) || strings.IndexFunc(v, unicode.IsSpace) >= 0 {
			return fmt.Errorf("%s: must be a plain host name part (no @ / # ? : \\ or whitespace)", f)
		}
		parts = append(parts, v)
	}
	host := strings.Join(parts, ".")
	last := ch.fields[len(ch.fields)-1]
	if err := httpx.CheckURL("https://"+host, allowLoopback); err != nil {
		return fmt.Errorf("%s: %w", last, err)
	}
	if err := checkResolved(ctx, host, allowLoopback, r); err != nil {
		return fmt.Errorf("%s: %w", last, err)
	}
	return nil
}

// CheckURLResolved applies the notifier SSRF policy to one URL: the URL
// check itself, then a resolution of its hostname with every address checked
// (r nil = system DNS).
func CheckURLResolved(ctx context.Context, rawURL string, allowLoopback bool, r HostResolver) error {
	if err := httpx.CheckURL(rawURL, allowLoopback); err != nil {
		return err
	}
	if r == nil {
		r = net.DefaultResolver
	}
	u, _ := url.Parse(rawURL) // CheckURL parsed it
	return checkResolved(ctx, u.Hostname(), allowLoopback, r)
}

// checkResolved refuses a metadata name, an unresolvable name, and a name
// with any resolved address the policy blocks. A literal IP was already
// classified by CheckURL.
func checkResolved(ctx context.Context, host string, allowLoopback bool, r HostResolver) error {
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if metadataNames[strings.ToLower(strings.TrimSuffix(host, "."))] {
		return fmt.Errorf("host %q is a cloud-metadata name and is not allowed", host)
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("host %q could not be resolved; the address must resolve when it is saved", host)
	}
	for _, a := range addrs {
		if err := httpx.CheckHost(a.String(), allowLoopback); err != nil {
			return fmt.Errorf("host %q resolves to %s, which is not allowed", host, a)
		}
	}
	return nil
}

// ErrAmbientCredentials is returned for a config that would authenticate as
// the CertForge server's own cloud identity (instance role, ADC, managed
// identity, a server-side profile) instead of keys the caller supplied.
var ErrAmbientCredentials = errors.New("uses the server's own cloud identity; only a global administrator (settings:write) may configure this")

// ambientFields name settings that select the server's own identity or
// delegate through it even when keys are supplied.
var ambientFields = []string{"AWS_ASSUME_ROLE_ARN", "AWS_PROFILE"}

// CheckNoAmbient rejects a split config that relies on ambient (server
// environment) credentials: the provider's no-field auth method being the
// only one satisfied, or any of ambientFields being set. Callers apply it to
// everyone but a global settings:write holder, so an org-scoped user cannot
// borrow the deployment's cloud identity.
func CheckNoAmbient(code string, public, secret map[string]string) error {
	e, ok := lookupEntry(code)
	if !ok {
		return nil
	}
	for _, f := range ambientFields {
		if public[f] != "" || secret[f] != "" {
			return fmt.Errorf("%w: %s", ErrAmbientCredentials, f)
		}
	}
	// AZURE_AUTH_METHOD: only "env" (the supplied client secret) is safe;
	// msi/cli/wli use the server's identity. Build forces env when the
	// client-secret fields are complete (see forceAzureEnvAuth).
	if m := public["AZURE_AUTH_METHOD"] + secret["AZURE_AUTH_METHOD"]; m != "" && !strings.EqualFold(m, "env") {
		return fmt.Errorf("%w: AZURE_AUTH_METHOD=%s", ErrAmbientCredentials, m)
	}
	hasAmbient, hasKeyed := false, false
	for _, m := range e.meta.AuthMethods {
		if len(m.Fields) == 0 {
			hasAmbient = true
			continue
		}
		ok := true
		for _, f := range m.Fields {
			if public[f] == "" && secret[f] == "" {
				ok = false
				break
			}
		}
		hasKeyed = hasKeyed || ok
	}
	if hasAmbient && !hasKeyed {
		return fmt.Errorf("%w: no explicit credentials supplied", ErrAmbientCredentials)
	}
	return nil
}
