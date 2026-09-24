package challenge

//go:generate go run ../../tools/gen-lego-schemas -out schemas -docs ../../docs/dns-providers.md

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	legochallenge "github.com/go-acme/lego/v4/challenge"
)

//go:embed schemas/*.json
var schemaFS embed.FS

// ProviderMeta describes one DNS provider for GET /meta/schemas.
type ProviderMeta struct {
	Code    string          `json:"code"`
	Name    string          `json:"name"`
	Schema  json.RawMessage `json:"schema"`
	Aliases []string        `json:"aliases,omitempty"`
	URL     string          `json:"url,omitempty"`

	// Unsupported and UnsupportedReason are parsed out of Schema's own
	// top-level "unsupported"/"unsupportedReason" (Register does this, not
	// the init loop above, so Lookup/Providers expose them as plain Go
	// fields, not just embedded JSON the caller would have to parse
	// itself): the provider's only lego credential input is a server-side
	// file (tools/gen-lego-schemas' unsupportedProviders), so it cannot be
	// configured through this API at all yet. Still listed, not removed,
	// so the UI can show and grey it out instead of silently omitting it.
	Unsupported       bool   `json:"unsupported,omitempty"`
	UnsupportedReason string `json:"unsupportedReason,omitempty"`
}

// Factory builds a provider without lego's env-var path (used by the e2e
// challtestsrv provider).
type Factory func(cfg map[string]string) (legochallenge.Provider, error)

type entry struct {
	meta       ProviderMeta
	secret     map[string]bool // every schema property; true = secret
	serverPath map[string]bool // every schema property; true = reads a local path/file on the server, rejected by SplitConfig
	factory    Factory
}

var (
	regMu   sync.RWMutex
	entries = map[string]*entry{}
	aliases = map[string]string{}
)

func init() {
	files, err := fs.Glob(schemaFS, "schemas/*.json")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		b, err := schemaFS.ReadFile(f)
		if err != nil {
			panic(err)
		}
		var m ProviderMeta
		if err := json.Unmarshal(b, &m); err != nil {
			panic(fmt.Sprintf("%s: %v", f, err))
		}
		if err := Register(m, nil); err != nil {
			panic(err)
		}
	}
}

// Register adds or replaces a provider. f may be nil for lego providers.
func Register(m ProviderMeta, f Factory) error {
	var s struct {
		Unsupported       bool   `json:"unsupported"`
		UnsupportedReason string `json:"unsupportedReason"`
		Properties        map[string]struct {
			Secret     bool `json:"secret"`
			ServerPath bool `json:"serverPath"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(m.Schema, &s); err != nil {
		return fmt.Errorf("provider %s schema: %w", m.Code, err)
	}
	m.Unsupported, m.UnsupportedReason = s.Unsupported, s.UnsupportedReason
	e := &entry{meta: m, secret: map[string]bool{}, serverPath: map[string]bool{}, factory: f}
	for k, p := range s.Properties {
		e.secret[k] = p.Secret
		e.serverPath[k] = p.ServerPath
	}
	regMu.Lock()
	defer regMu.Unlock()
	entries[m.Code] = e
	for _, a := range m.Aliases {
		aliases[a] = m.Code
	}
	return nil
}

func lookupEntry(code string) (*entry, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	if e, ok := entries[code]; ok {
		return e, true
	}
	if c, ok := aliases[code]; ok {
		e, ok := entries[c]
		return e, ok
	}
	return nil, false
}

// Providers lists every provider sorted by name.
func Providers() []ProviderMeta {
	regMu.RLock()
	out := make([]ProviderMeta, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.meta)
	}
	regMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Lookup finds a provider by code or alias.
func Lookup(code string) (ProviderMeta, bool) {
	e, ok := lookupEntry(code)
	if !ok {
		return ProviderMeta{}, false
	}
	return e.meta, true
}
