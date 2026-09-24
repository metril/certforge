package challenge

import (
	"errors"
	"fmt"
	"sort"
)

// Unchanged is the write-only sentinel: on update, a secret field with this
// value keeps the stored secret.
const Unchanged = "__unchanged__"

// ErrUnknownField is returned for config keys absent from the provider schema.
var ErrUnknownField = errors.New("unknown field")

// SplitConfig validates cfg against the provider schema and splits it into
// public (stored as jsonb) and secret (stored encrypted) parts. Empty values
// are dropped.
func SplitConfig(code string, cfg map[string]string) (public, secret map[string]string, err error) {
	e, ok := lookupEntry(code)
	if !ok {
		return nil, nil, fmt.Errorf("unknown DNS provider %q", code)
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
		if v == Unchanged {
			return nil, nil, fmt.Errorf("%s: %q is only valid when updating a stored secret", k, Unchanged)
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
func MergeUpdate(code string, oldSecret, in map[string]string) (public, secret map[string]string, err error) {
	resolved := make(map[string]string, len(in))
	for k, v := range in {
		if v == Unchanged {
			if old, ok := oldSecret[k]; ok {
				resolved[k] = old
			}
			continue
		}
		resolved[k] = v
	}
	return SplitConfig(code, resolved)
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
