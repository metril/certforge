package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ErrInvalid wraps a value that fails its section schema.
var ErrInvalid = errors.New("settings: invalid value")

var sectionName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// Section is one UI settings page: a JSON Schema and a default value.
type Section struct {
	Name    string
	Schema  json.RawMessage
	Default json.RawMessage
	schema  *jsonschema.Schema
}

// SectionKey is the settings-table key that stores section name.
func SectionKey(name string) string { return "section." + name }

// Key returns the settings-table key for s.
func (s *Section) Key() string { return SectionKey(s.Name) }

// Validate checks raw JSON against the section schema.
func (s *Section) Validate(raw []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := s.schema.Validate(inst); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

// Registry holds the known settings sections.
type Registry struct {
	mu       sync.RWMutex
	sections map[string]*Section
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{sections: map[string]*Section{}} }

// Register compiles schema, validates def against it, and adds the section.
func (r *Registry) Register(name string, schema, def json.RawMessage) error {
	if !sectionName.MatchString(name) {
		return fmt.Errorf("settings: invalid section name %q", name)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return fmt.Errorf("settings: schema %s: %w", name, err)
	}
	url := "https://certforge.invalid/schemas/settings/" + name + ".json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(url, doc); err != nil {
		return fmt.Errorf("settings: schema %s: %w", name, err)
	}
	compiled, err := c.Compile(url)
	if err != nil {
		return fmt.Errorf("settings: schema %s: %w", name, err)
	}
	sec := &Section{Name: name, Schema: schema, Default: def, schema: compiled}
	if err := sec.Validate(def); err != nil {
		return fmt.Errorf("settings: default for %s: %w", name, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.sections[name]; dup {
		return fmt.Errorf("settings: section %q already registered", name)
	}
	r.sections[name] = sec
	return nil
}

// MustRegister is Register that panics; use it for built-in sections at startup.
func (r *Registry) MustRegister(name string, schema, def json.RawMessage) {
	if err := r.Register(name, schema, def); err != nil {
		panic(err)
	}
}

// Section looks up a section by name.
func (r *Registry) Section(name string) (*Section, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sections[name]
	return s, ok
}

// Names returns the registered section names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.sections))
	for n := range r.sections {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

const generalSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "baseUrl": {
      "type": "string",
      "title": "Base URL",
      "description": "Public URL people and agents use to reach CertForge.",
      "pattern": "^https?://[^/\\s]+(/.*)?$"
    }
  }
}`

const backupSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "kekEscrowConfirmed": {
      "type": "boolean",
      "title": "KEK escrow confirmed",
      "description": "The KEK is stored safely outside this server. Backups refuse to run until this is on.",
      "default": false
    }
  }
}`

// DefaultRegistry returns a registry with the sections owned by Phase 1A.
// Other packages add theirs (for example issuance_defaults) with MustRegister.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.MustRegister("general", json.RawMessage(generalSchema), json.RawMessage(`{}`))
	r.MustRegister("backup", json.RawMessage(backupSchema), json.RawMessage(`{"kekEscrowConfirmed":false}`))
	return r
}
