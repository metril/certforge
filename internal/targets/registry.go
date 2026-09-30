package targets

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Unchanged, sent as a secret field's value, keeps the field's stored value
// (Global Constraints, Target operations row).
const Unchanged = "__unchanged__"

// ErrUnchangedWithoutStored means Unchanged — or an omitted secret field,
// which Parse treats the same way — was sent for a secret that has no
// stored value.
var ErrUnchangedWithoutStored = errors.New("targets: __unchanged__ sent for a secret with no stored value")

// Registry holds the known deploy target types, keyed by Type().
type Registry struct {
	mu      sync.RWMutex
	targets map[string]Target
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{targets: map[string]Target{}} }

// Register adds t, keyed by t.Type(). It panics on a duplicate type: every
// caller registers a fixed, compile-time-known set of types (RegisterBuiltins,
// a test's own targetstest types), so a collision is a programming error,
// never live input.
func (r *Registry) Register(t Target) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.targets[t.Type()]; dup {
		panic(fmt.Sprintf("targets: type %q already registered", t.Type()))
	}
	r.targets[t.Type()] = t
}

// Get returns the target type registered as typ.
func (r *Registry) Get(typ string) (Target, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.targets[typ]
	return t, ok
}

// Each calls fn for every registered type, sorted by Type().
func (r *Registry) Each(fn func(Target)) {
	r.mu.RLock()
	list := make([]Target, 0, len(r.targets))
	for _, t := range r.targets {
		list = append(list, t)
	}
	r.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Type() < list[j].Type() })
	for _, t := range list {
		fn(t)
	}
}

// Parse resolves raw's secret fields against stored (the target's currently
// decrypted secrets; empty on create) and hands the fully merged config to
// the type's own Parse. For each of typ's secret properties (Schema via
// SecretProps): the Unchanged sentinel takes stored[k] and is reported in
// reused, or is ErrUnchangedWithoutStored (wrapped with the field name)
// when stored has none; an omitted field takes stored[k] and is reported in
// reused when stored has one, or is simply left absent when it does not —
// the type's own Parse enforces which of its secrets are actually
// required, so an absent optional secret is never an error here; any other
// value, including an explicit "", replaces the field (an explicit ""
// clears the stored value and is not reused — whether that is actually
// allowed is up to the type's own Parse).
func (r *Registry) Parse(typ string, raw json.RawMessage, stored map[string]string) (Config, []string, error) {
	t, ok := r.Get(typ)
	if !ok {
		return Config{}, nil, fmt.Errorf("targets: unknown type %q", typ)
	}
	secretKeys, err := SecretProps(t.Schema())
	if err != nil {
		return Config{}, nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Config{}, nil, fmt.Errorf("targets: %w", err)
	}
	if doc == nil {
		doc = map[string]json.RawMessage{}
	}
	var reused []string
	for _, k := range secretKeys {
		fieldRaw, present := doc[k]
		var str string
		if present {
			if err := json.Unmarshal(fieldRaw, &str); err != nil {
				return Config{}, nil, fmt.Errorf("targets: %s must be a string", k)
			}
		}
		if present && str != Unchanged {
			continue
		}
		v, ok := stored[k]
		if !ok {
			if !present {
				// Omitted, no stored value: leave it absent. The type's
				// own Parse enforces which of its secrets are required, so
				// this is only an error when that secret turns out to be
				// required — never here, unconditionally.
				continue
			}
			return Config{}, nil, fmt.Errorf("%s: %w", k, ErrUnchangedWithoutStored)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return Config{}, nil, err
		}
		doc[k] = b
		reused = append(reused, k)
	}
	merged, err := json.Marshal(doc)
	if err != nil {
		return Config{}, nil, err
	}
	cfg, err := t.Parse(merged)
	if err != nil {
		return Config{}, nil, err
	}
	sort.Strings(reused)
	return cfg, reused, nil
}

// NeedsKey reports whether typ's config needs the certificate's private
// key: always for KeyPolicy Always, or, for Optional, when public's
// includeKey is true. public is the target's public config (no secrets),
// so this never needs the decrypted secret map.
func (r *Registry) NeedsKey(typ string, public json.RawMessage) (bool, error) {
	t, ok := r.Get(typ)
	if !ok {
		return false, fmt.Errorf("targets: unknown type %q", typ)
	}
	switch t.KeyPolicy() {
	case Always:
		return true, nil
	case Optional:
		var doc struct {
			IncludeKey bool `json:"includeKey"`
		}
		if err := json.Unmarshal(public, &doc); err != nil {
			return false, fmt.Errorf("targets: %w", err)
		}
		return doc.IncludeKey, nil
	default:
		return false, nil
	}
}

// ResolveSide resolves the effective Mode for t given requested (an empty
// string, "server" or "agent" from the API). An Either type requires
// requested to name one of the two ("choose where this target runs"); a
// forced-mode type accepts an empty requested or its own mode and rejects
// anything else, naming the forced mode.
func ResolveSide(t Target, requested string) (Mode, error) {
	mode := t.RunsOn()
	if mode == Either {
		switch Mode(requested) {
		case Server, Agent:
			return Mode(requested), nil
		default:
			return "", fmt.Errorf("targets: choose where this target runs")
		}
	}
	if requested == "" || Mode(requested) == mode {
		return mode, nil
	}
	return "", fmt.Errorf("targets: %s runs on %s", t.Name(), mode)
}
