// Package targets is the shared, database-free deploy-target model used by
// both the server-side dispatcher (internal/deploy) and certforge-agent:
// the Target and FileTarget interfaces every deploy target type implements,
// the split between a config's public fields and its write-only secret
// fields, request/result types, an outbound HTTP client factory, and error
// redaction. Product types (vault-kv, traefik) and the registry wiring that
// exposes them to the API and agent are internal/targets' own builtins and
// internal/deploy (a later task); this package only defines the shape they
// implement.
package targets

import (
	"context"
	"encoding/json"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
)

// Mode is where a deploy target type runs (Shared contract, DeployTarget.runsOn).
type Mode string

// Mode values.
const (
	Server Mode = "server"
	Agent  Mode = "agent"
	Either Mode = "either"
)

// KeyPolicy says whether a target type ever needs the certificate's private
// key (Shared contract, MetaSchemaEntry.keyPolicy).
type KeyPolicy string

// KeyPolicy values.
const (
	Never    KeyPolicy = "never"
	Optional KeyPolicy = "optional"
	Always   KeyPolicy = "always"
)

// MaxDetail bounds a redacted deploy error kept in a stored or reported
// field (server_deployments.last_error, a deploy.failed payload, an agent
// report) — Global Constraints, Secrets row.
const MaxDetail = 200

// Target is one deploy target type: its JSON Schema, how it runs, whether
// it needs the certificate's private key, config parsing, and delivery.
type Target interface {
	// Type is the wire type code (deploy_targets.type, DeployTargetType).
	Type() string
	// Name is the display name (MetaSchemaEntry.name).
	Name() string
	// Schema is the type's JSON Schema for its config (MetaSchemaEntry.schema).
	// Secret properties are marked "secret": true (SecretProps).
	Schema() json.RawMessage
	// RunsOn is the type's forced mode, or Either when the operator chooses
	// at create time (ResolveSide).
	RunsOn() Mode
	// KeyPolicy says whether the target ever needs the private key.
	KeyPolicy() KeyPolicy
	// Parse decodes and validates raw — a fully resolved config, every
	// secret already merged in, never the Unchanged sentinel — into a
	// Config, enforcing which of the type's own secret properties are
	// actually required.
	Parse(raw json.RawMessage) (Config, error)
	// Deploy delivers material to this target. A FileTarget's Deploy
	// returns Result{Files} with no side effects; the files themselves are
	// written by the agent, not here (Deviations R2).
	Deploy(ctx context.Context, req Request) (Result, error)
}

// FileTarget is a Target whose delivery is a set of files an agent writes
// (traefik, targetstest.File), rather than a live server-side call.
type FileTarget interface {
	Target
	// Files renders the files this target writes for req.
	Files(req Request) ([]delivery.File, error)
	// Paths returns the paths Files would write for cfg and certName, with
	// no material needed — used by agents.grantPaths to prune stale files
	// left by a config change.
	Paths(cfg json.RawMessage, certName string) ([]string, error)
}

// Reloader is implemented by a FileTarget whose files need a service
// reloaded after they change.
type Reloader interface {
	Reload(ctx context.Context, req Request) (string, error)
}

// Config is a target's parsed config: the public part (no secrets), its
// resolved secret values (never the Unchanged sentinel), whether it needs
// the private key, and any URLs the API checks against the URL policy at
// create/update (Deviations R2).
type Config struct {
	Public   json.RawMessage
	Secrets  map[string]string
	NeedsKey bool
	URLs     []string
}

// Request is everything a Target.Deploy or FileTarget.Files/Paths call
// needs to deliver one grant.
type Request struct {
	GrantID     string
	OrgSlug     string
	CertID      string
	CertName    string
	Names       []string
	Fingerprint string
	// Material is the certificate's canonical material; nil for a
	// version-less grant (a file target may still render a
	// material-independent file, such as Traefik's ACME router file).
	Material *render.Material
	// Files are the grant's own rendered layout files, in write order,
	// ahead of whatever this target's own Deploy/Files adds.
	Files []render.File
	// Config is the target's fully merged config (public fields plus
	// resolved secrets), as JSON — what Target.Parse returned Config for,
	// re-merged (Merge).
	Config json.RawMessage
	Side   Mode
	HTTP   HTTPFactory
}

// Result is what Deploy produced: any files (unwritten until an agent
// installs them) and a short human-readable detail.
type Result struct {
	Files  []delivery.File
	Detail string
}
