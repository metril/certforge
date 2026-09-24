package challenge

import (
	"errors"
	"fmt"
	"sort"
	"strings"
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

// SplitConfig validates cfg against the provider schema and splits it into
// public (stored as jsonb) and secret (stored encrypted) parts. Empty values
// are dropped.
func SplitConfig(code string, cfg map[string]string) (public, secret map[string]string, err error) {
	e, ok := lookupEntry(code)
	if !ok {
		return nil, nil, fmt.Errorf("%w %q", ErrUnknownProvider, code)
	}
	public, secret = map[string]string{}, map[string]string{}
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
	return public, secret, nil
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
