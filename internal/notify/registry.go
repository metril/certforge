package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Target is the server-side context a Notifier needs beyond the event
// itself and the channel's own config/secrets: the event's org name (empty
// for a global event), CertForge's own base URL (Home Assistant's webhook
// call, and a future web link) and version (webhook's User-Agent).
type Target struct {
	OrgName string
	BaseURL string
	Version string
}

// Notifier delivers one Event to one channel type (webhook, smtp, discord,
// ntfy, homeassistant — Task 4/5 implement these; Task 3 only defines the
// interface and DeliverWorker's use of it). Send must not log or return cfg
// or secrets verbatim in its error: DeliverWorker redacts every secrets
// value from the error it gets back, but Send should not need that as its
// only protection.
type Notifier interface {
	// Type is the channel type this Notifier handles (matches
	// ChannelType/notification_channels.type).
	Type() string
	// Name is the type's display name (meta.Entry.Name, e.g. "Webhook").
	Name() string
	// Schema is the type's JSON Schema for its config (meta.Entry.Schema;
	// Shared contract's "Notifier configs" row).
	Schema() []byte
	// Send delivers ev to this channel. cfg is the channel's public config
	// (notification_channels.config); secrets is its decrypted secret_cfg.
	// ctx carries DeliverWorker's 45s bound.
	Send(ctx context.Context, ev Event, target Target, cfg map[string]any, secrets map[string]string) error
}

// ConfigChecker is implemented by a Notifier whose config needs a check
// beyond its JSON Schema (webhook: a credential-looking header name;
// discord: webhookUrl's scheme; homeassistant: webhookId's character set).
// Those three checks live in Go rather than the schema's own "pattern"
// keyword because the field they check is secret: jsonschema v6 echoes a
// failed pattern/enum/const/format check's rejected instance value into its
// error text (the same reason internal/settings.secretProps forbids those
// keywords on a secret settings property), which would leak the secret
// itself into a stored notification_deliveries.last_error or a 422 body.
// Kept out of the Notifier interface itself (same pattern as
// deploy.configParser): ValidateConfig reaches it through a type assertion.
type ConfigChecker interface {
	// CheckConfig runs after cfg has already passed the type's JSON Schema.
	// cfg is the channel's full submitted config, secret field values
	// included (Task 6 calls ValidateConfig before splitting them out to
	// storage — the same order internal/settings.Section.Validate then
	// split() uses).
	CheckConfig(cfg map[string]any) error
}

// registryEntry is one registered Notifier plus its compiled config schema
// (compiled once, at Register, rather than on every ValidateConfig call).
type registryEntry struct {
	notifier Notifier
	schema   *jsonschema.Schema
}

// Registry holds the known Notifier implementations, keyed by Type().
// Safe for concurrent use.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]registryEntry
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{entries: map[string]registryEntry{}} }

// Register adds n, keyed by n.Type(). It panics on a duplicate type or an
// invalid Schema(): every registration happens at boot, from a fixed list
// of built-in notifiers (cmd/certforge/serve.go), so either is a
// programming error, not a runtime condition to recover from.
func (r *Registry) Register(n Notifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.entries[n.Type()]; dup {
		panic(fmt.Sprintf("notify: notifier type %q already registered", n.Type()))
	}
	schema, err := compileNotifierSchema(n.Type(), n.Schema())
	if err != nil {
		panic(fmt.Sprintf("notify: notifier type %q schema: %v", n.Type(), err))
	}
	r.entries[n.Type()] = registryEntry{notifier: n, schema: schema}
}

// Get looks up a Notifier by channel type.
func (r *Registry) Get(typ string) (Notifier, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[typ]
	return e.notifier, ok
}

// Types returns the registered channel types, sorted.
func (r *Registry) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for t := range r.entries {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ValidateConfig validates cfg — a channel's full submitted config, secret
// field values included — against typ's registered JSON Schema, then runs
// the notifier's own CheckConfig when it implements ConfigChecker. Task 6
// calls this from channel create/update, before splitting cfg's secret
// properties out to notification_channels.secret_cfg; a schema or
// CheckConfig failure is a 422.
func (r *Registry) ValidateConfig(typ string, cfg map[string]any) error {
	r.mu.RLock()
	e, ok := r.entries[typ]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("notify: unknown channel type %q", typ)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("notify: encode config: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	if err := e.schema.Validate(inst); err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	if cc, ok := e.notifier.(ConfigChecker); ok {
		return cc.CheckConfig(cfg)
	}
	return nil
}

// compileNotifierSchema compiles a notifier type's JSON Schema (the same
// draft 2020-12 compiler internal/settings.Registry.Register uses).
func compileNotifierSchema(typ string, raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	url := "https://certforge.invalid/schemas/notifiers/" + typ + ".json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	return c.Compile(url)
}
