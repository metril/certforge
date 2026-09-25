package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ErrInvalid wraps a value that fails its section schema.
var ErrInvalid = errors.New("settings: invalid value")

var sectionName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// Section is one UI settings page: a JSON Schema and a default value.
// Top-level string properties marked "secret": true are write-only: they are
// stored encrypted in the secret column and never appear in the value.
type Section struct {
	Name    string
	Schema  json.RawMessage
	Default json.RawMessage
	schema  *jsonschema.Schema
	secrets []string
	checks  []func(json.RawMessage) error
}

// SectionKey is the settings-table key that stores section name.
func SectionKey(name string) string { return "section." + name }

// Key returns the settings-table key for s.
func (s *Section) Key() string { return SectionKey(s.Name) }

// SecretKeys lists the section's write-only properties, sorted.
func (s *Section) SecretKeys() []string { return slices.Clone(s.secrets) }

// Validate checks raw JSON against the section schema, then the extra checks.
func (s *Section) Validate(raw []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := s.schema.Validate(inst); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	for _, check := range s.checks {
		if err := check(raw); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	return nil
}

// Public returns raw without the section's secret properties.
func (s *Section) Public(raw json.RawMessage) (json.RawMessage, error) {
	pub, _, err := s.split(raw)
	return pub, err
}

// split separates the secret properties (as strings) from the rest.
func (s *Section) split(raw json.RawMessage) (json.RawMessage, map[string]string, error) {
	if len(s.secrets) == 0 {
		return raw, nil, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	in := map[string]string{}
	for _, k := range s.secrets {
		v, ok := doc[k]
		if !ok {
			continue
		}
		var str string
		if err := json.Unmarshal(v, &str); err != nil {
			return nil, nil, fmt.Errorf("%w: %s must be a string", ErrInvalid, k)
		}
		in[k] = str
		delete(doc, k)
	}
	pub, err := json.Marshal(doc)
	return pub, in, err
}

func secretProps(schema json.RawMessage) ([]string, error) {
	var doc struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Secret bool `json:"secret"`
			Type   any  `json:"type"`
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
			return nil, fmt.Errorf("secret property %q must have type string", k)
		}
		if slices.Contains(doc.Required, k) {
			return nil, fmt.Errorf("secret property %q cannot be required", k)
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
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
	secrets, err := secretProps(schema)
	if err != nil {
		return fmt.Errorf("settings: schema %s: %w", name, err)
	}
	sec := &Section{Name: name, Schema: schema, Default: def, schema: compiled, secrets: secrets}
	if err := sec.Validate(def); err != nil {
		return fmt.Errorf("settings: default for %s: %w", name, err)
	}
	if _, in, err := sec.split(def); err != nil || len(in) > 0 {
		return fmt.Errorf("settings: default for %s must not hold secrets", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.sections[name]; dup {
		return fmt.Errorf("settings: section %q already registered", name)
	}
	r.sections[name] = sec
	return nil
}

// AddCheck adds a validation step that runs after the schema. Call it at
// startup, before the registry serves requests.
func (r *Registry) AddCheck(name string, fn func(raw json.RawMessage) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sections[name]
	if !ok {
		return fmt.Errorf("settings: section %q not registered", name)
	}
	s.checks = append(s.checks, fn)
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
