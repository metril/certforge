package targets

import (
	"encoding/json"
	"fmt"
	"sort"
)

// SecretProps returns schema's top-level string properties marked
// "secret": true, sorted. Copied from notify/registry.go's secretProps
// (Task 2 brief): secret properties must be plain strings with no
// pattern/enum/const/format — jsonschema v6 echoes a failed
// pattern/enum/const/format check's rejected instance value into its error
// text, which would leak the secret itself into a 422 body. Unlike a
// settings section's secretProps, a target schema's secret property may be
// required: Parse always hands the type's own Parse a fully resolved
// config (Unchanged/omitted already merged back to the stored value), so
// there is no path where a required secret could be legitimately absent.
func SecretProps(schema json.RawMessage) ([]string, error) {
	var doc struct {
		Properties map[string]struct {
			Secret  bool            `json:"secret"`
			Type    any             `json:"type"`
			Pattern string          `json:"pattern"`
			Enum    json.RawMessage `json:"enum"`
			Const   json.RawMessage `json:"const"`
			Format  string          `json:"format"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &doc); err != nil {
		return nil, err
	}
	var out []string
	for k, p := range doc.Properties {
		if !p.Secret {
			continue
		}
		if p.Type != "string" {
			return nil, fmt.Errorf("targets: secret property %q must have type string", k)
		}
		if p.Pattern != "" || len(p.Enum) > 0 || len(p.Const) > 0 || p.Format != "" {
			return nil, fmt.Errorf("targets: secret property %q cannot use pattern, enum, const, or format", k)
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// Split separates schema's secret properties out of canonical (a fully
// resolved config, secrets included) into a map, leaving the rest as
// public. A secret property holding "" is dropped rather than returned: an
// empty string means the value was cleared, not that it is stored as "".
func Split(schema, canonical json.RawMessage) (json.RawMessage, map[string]string, error) {
	keys, err := SecretProps(schema)
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &doc); err != nil {
		return nil, nil, fmt.Errorf("targets: %w", err)
	}
	if doc == nil {
		doc = map[string]json.RawMessage{}
	}
	secrets := map[string]string{}
	for _, k := range keys {
		raw, ok := doc[k]
		if !ok {
			continue
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, nil, fmt.Errorf("targets: %s must be a string", k)
		}
		delete(doc, k)
		if v != "" {
			secrets[k] = v
		}
	}
	pub, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	return pub, secrets, nil
}

// Merge is Split's inverse: it adds secrets' keys back into public as
// string values, producing the canonical config Split would split again.
func Merge(public json.RawMessage, secrets map[string]string) (json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if len(public) > 0 {
		if err := json.Unmarshal(public, &doc); err != nil {
			return nil, fmt.Errorf("targets: %w", err)
		}
	}
	if doc == nil {
		doc = map[string]json.RawMessage{}
	}
	for k, v := range secrets {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		doc[k] = b
	}
	return json.Marshal(doc)
}
