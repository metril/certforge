package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Name         string
	Schema       json.RawMessage
	Default      json.RawMessage
	schema       *jsonschema.Schema
	secrets      []string
	checks       []func(json.RawMessage) error
	updateChecks []func(stored, next json.RawMessage) error
	// ignored are properties the schema no longer declares but an older stored
	// value or client may still carry: dropped on read, validate and write.
	ignored []string
}

// SectionKey is the settings-table key that stores section name.
func SectionKey(name string) string { return "section." + name }

// Key returns the settings-table key for s.
func (s *Section) Key() string { return SectionKey(s.Name) }

// SecretKeys lists the section's write-only properties, sorted.
func (s *Section) SecretKeys() []string { return slices.Clone(s.secrets) }

// Validate checks raw JSON against the section schema, then the extra checks.
func (s *Section) Validate(raw []byte) error {
	raw = s.stripIgnored(raw)
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

// ValidateUpdate runs the section's update checks (AddUpdateCheck) against
// stored (the section's previous public value, nil when never saved) and
// next (the incoming raw value, before its secrets are split out). Called
// by PutSectionTx and by a provider's own Test method (vault.Provider.Test)
// wherever a section needs to compare the stored value against a candidate
// one — for example rejecting a re-sent secret sentinel when the address it
// would apply to has changed.
func (s *Section) ValidateUpdate(stored, next json.RawMessage) error {
	for _, check := range s.updateChecks {
		if err := check(stored, next); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	return nil
}

// stripIgnored removes the section's ignored (retired) properties from raw.
// A value that is not a JSON object is returned unchanged for the schema to reject.
func (s *Section) stripIgnored(raw []byte) json.RawMessage {
	if len(s.ignored) == 0 {
		return raw
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw
	}
	changed := false
	for _, k := range s.ignored {
		if _, ok := doc[k]; ok {
			delete(doc, k)
			changed = true
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

// Public returns raw without the section's secret properties.
func (s *Section) Public(raw json.RawMessage) (json.RawMessage, error) {
	pub, _, err := s.split(raw)
	return pub, err
}

// split separates the secret properties (as strings) from the rest.
func (s *Section) split(raw json.RawMessage) (json.RawMessage, map[string]string, error) {
	raw = s.stripIgnored(raw)
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
			return nil, fmt.Errorf("secret property %q must have type string", k)
		}
		if slices.Contains(doc.Required, k) {
			return nil, fmt.Errorf("secret property %q cannot be required", k)
		}
		// jsonschema v6 echoes the rejected instance value into its error
		// text for a failed pattern/enum/const/format check, which would
		// leak the secret itself into a 422 response; disallow all four on
		// a secret property instead of trying to redact the error later.
		if p.Pattern != "" || len(p.Enum) > 0 || len(p.Const) > 0 || p.Format != "" {
			return nil, fmt.Errorf("secret property %q cannot use pattern, enum, const, or format", k)
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

// IgnoreProperties marks retired properties of a section: an older stored
// value or client may still carry them, so they are dropped silently on
// read, validate and write instead of failing the schema. Call it at startup.
func (r *Registry) IgnoreProperties(name string, keys ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sections[name]
	if !ok {
		return fmt.Errorf("settings: section %q not registered", name)
	}
	s.ignored = append(s.ignored, keys...)
	return nil
}

// AddUpdateCheck adds a check comparing a section's previous stored public
// value against an incoming candidate value (Section.ValidateUpdate). Call
// it at startup, before the registry serves requests.
func (r *Registry) AddUpdateCheck(name string, fn func(stored, next json.RawMessage) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sections[name]
	if !ok {
		return fmt.Errorf("settings: section %q not registered", name)
	}
	s.updateChecks = append(s.updateChecks, fn)
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
    "schedule": {
      "type": "string",
      "title": "Schedule",
      "description": "How often an encrypted backup is written to disk automatically.",
      "enum": ["off", "daily", "weekly"],
      "default": "off"
    },
    "retainCount": {
      "type": "integer",
      "title": "Retain count",
      "description": "Number of scheduled backup files kept on disk before the oldest is pruned.",
      "minimum": 1,
      "maximum": 90,
      "default": 7
    },
    "directory": {
      "type": "string",
      "title": "Directory",
      "description": "Absolute path on the server where scheduled backups are written. Required once schedule is not off, and must be a writable directory.",
      "maxLength": 1024,
      "pattern": "^/"
    }
  }
}`

// checkBackupDirectory enforces what the schema alone cannot express
// (Shared contract, Settings row): directory is required, must be an
// absolute path and must be a writable directory once schedule is not off.
// Writability is checked by actually creating and removing a probe file,
// not just statting the directory (a directory can exist and still be
// read-only to the server's process).
func checkBackupDirectory(raw json.RawMessage) error {
	var b struct {
		Schedule  string `json:"schedule"`
		Directory string `json:"directory"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return err
	}
	schedule := b.Schedule
	if schedule == "" {
		schedule = "off"
	}
	if schedule == "off" {
		return nil
	}
	if b.Directory == "" {
		return errors.New("directory is required when schedule is not off")
	}
	if !filepath.IsAbs(b.Directory) {
		return fmt.Errorf("directory %q must be an absolute path", b.Directory)
	}
	info, err := os.Stat(b.Directory)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("directory %q is not a directory", b.Directory)
	}
	probe, err := os.CreateTemp(b.Directory, ".certforge-probe-*")
	if err != nil {
		return fmt.Errorf("directory %q is not writable: %w", b.Directory, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return nil
}

// DefaultRegistry returns a registry with the sections owned by Phase 1A.
// Other packages add theirs (for example issuance_defaults) with MustRegister.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.MustRegister("general", json.RawMessage(generalSchema), json.RawMessage(`{}`))
	r.MustRegister("backup", json.RawMessage(backupSchema), json.RawMessage(`{"schedule":"off","retainCount":7}`))
	if err := r.AddCheck("backup", checkBackupDirectory); err != nil {
		panic(err)
	}
	// kekEscrowConfirmed was retired: backups no longer need the confirmation,
	// but a stored value (or an older client) may still carry it.
	if err := r.IgnoreProperties("backup", "kekEscrowConfirmed"); err != nil {
		panic(err)
	}
	return r
}
