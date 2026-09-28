// Package deploy is the server-side counterpart to internal/delivery: deploy
// target types whose grants run on this server rather than an enrolled
// agent (client-less "server grants", Deviations R9/R6). Deviations R6:
// there is no Probe in 5A — Target has no probe method, and nothing calls
// one.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/metril/certforge/internal/render"
)

// Request is one server-side deploy: the certificate's own identity, its
// rendered files (the four canonical PEM parts — fullchain.pem, cert.pem,
// chain.pem, privkey.pem — when the grant has no layout, or a layout's own
// files otherwise), and the target instance's own stored config.
type Request struct {
	OrgSlug  string
	CertID   string
	CertName string
	Files    []render.File
	Config   map[string]any
}

// Result is what a Deploy call reports back, stored on the
// server_deployments row.
type Result struct {
	Path    string
	Version int
}

// Target is a server-side deploy target type.
type Target interface {
	// Type is the deploy target type code (deploy_targets.type /
	// DeployTargetType).
	Type() string
	// Schema is the type's config JSON schema (GET /meta/schemas).
	Schema() json.RawMessage
	// Deploy writes req's certificate material to the target.
	Deploy(ctx context.Context, req Request) (Result, error)
}

// RunsOn reports where a deploy target type runs: "server" for a
// server-run type (vault-kv), "agent" for every other type. A target's
// runsOn is always derived from its type; the API never takes it from
// client input (DeployTargetInput has no runsOn field).
func RunsOn(targetType string) string {
	if targetType == TypeVaultKV {
		return "server"
	}
	return "agent"
}

// configParser is implemented by every target type this package ships: it
// validates and canonicalizes a target's raw config before storage. Kept
// out of the Target interface itself (Shared contract: Type/Schema/Deploy
// only) so Task 11's dispatcher and Registry.Get keep exactly that shape;
// Registry.ParseConfig reaches it through a type assertion instead.
type configParser interface {
	ParseConfig(raw json.RawMessage) (json.RawMessage, error)
}

type regEntry struct {
	name   string
	target Target
}

// Registry holds server-side deploy target types, keyed by their Type().
// A nil *Registry behaves like an empty one (Get and ParseConfig report
// "not found" rather than panicking), so callers that never wire one (a
// test with no server-run targets) need no special case.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]regEntry
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{entries: map[string]regEntry{}} }

// Register adds t under its own Type(), with name as its GET
// /meta/schemas display name.
func (r *Registry) Register(name string, t Target) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = map[string]regEntry{}
	}
	r.entries[t.Type()] = regEntry{name: name, target: t}
}

// Get returns the Target registered for typ, or false when none is.
func (r *Registry) Get(typ string) (Target, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[typ]
	return e.target, ok
}

// ParseConfig validates and canonicalizes raw for typ using the registered
// target's own rules, returning the config to store. ok is false when typ
// is not a registered server-run type.
func (r *Registry) ParseConfig(typ string, raw json.RawMessage) (cfg json.RawMessage, ok bool, err error) {
	t, ok := r.Get(typ)
	if !ok {
		return nil, false, nil
	}
	cp, isParser := t.(configParser)
	if !isParser {
		return nil, true, fmt.Errorf("deploy: target type %q has no config parser", typ)
	}
	cfg, err = cp.ParseConfig(raw)
	return cfg, true, err
}

// each iterates reg's entries under lock; used by AddToMeta (meta.go).
func (r *Registry) each(f func(typ string, e regEntry)) {
	if r == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for typ, e := range r.entries {
		f(typ, e)
	}
}
