// Package meta keeps the registry of pluggable type schemas (DNS providers,
// deploy targets, notifiers, signers) served at GET /api/v1/meta/schemas.
package meta

import (
	"encoding/json"
	"sort"
	"sync"
)

// Kind groups entries; values match the JSON field names of MetaSchemas.
type Kind string

// Kinds.
const (
	KindDNSProvider  Kind = "dnsProviders"
	KindDeployTarget Kind = "deployTargets"
	KindNotifier     Kind = "notifiers"
	KindSigner       Kind = "signers"
)

// Entry is one pluggable type and its configuration schema.
type Entry struct {
	Code   string          `json:"code"`
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
}

// Registry is safe for concurrent use.
type Registry struct {
	mu      sync.RWMutex
	entries map[Kind]map[string]Entry
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{entries: map[Kind]map[string]Entry{}} }

// Add registers e under k, replacing any entry with the same code.
func (r *Registry) Add(k Kind, e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.entries[k]
	if m == nil {
		m = map[string]Entry{}
		r.entries[k] = m
	}
	m[e.Code] = e
}

// List returns entries of kind k sorted by code; never nil.
func (r *Registry) List(k Kind) []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, 0, len(r.entries[k]))
	for _, e := range r.entries[k] {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}
