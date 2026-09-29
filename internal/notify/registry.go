package notify

import (
	"context"
	"fmt"
	"sort"
	"sync"
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

// Registry holds the known Notifier implementations, keyed by Type().
// Safe for concurrent use.
type Registry struct {
	mu        sync.RWMutex
	notifiers map[string]Notifier
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{notifiers: map[string]Notifier{}} }

// Register adds n, keyed by n.Type(). It panics on a duplicate type: every
// registration happens at boot, from a fixed list of built-in notifiers
// (cmd/certforge/serve.go), so a collision is a programming error, not a
// runtime condition to recover from.
func (r *Registry) Register(n Notifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.notifiers[n.Type()]; dup {
		panic(fmt.Sprintf("notify: notifier type %q already registered", n.Type()))
	}
	r.notifiers[n.Type()] = n
}

// Get looks up a Notifier by channel type.
func (r *Registry) Get(typ string) (Notifier, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.notifiers[typ]
	return n, ok
}

// Types returns the registered channel types, sorted.
func (r *Registry) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.notifiers))
	for t := range r.notifiers {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
