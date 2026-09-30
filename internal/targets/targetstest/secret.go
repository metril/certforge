// Package targetstest provides test-only deploy target types — Secret (a
// server- or agent-side type with a required and an optional secret field)
// and File (an agent-side FileTarget) — used by internal/targets,
// internal/deploy and internal/agent tests to exercise the registry without
// depending on a product type. Neither type is ever registered into a
// product registry: TestProductRegistriesHaveNoTestTypes (serve wiring) and
// TestAgentImports (the agent binary) both guard against it, and
// certforge-agent never imports this package at all.
package targetstest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/metril/certforge/internal/targets"
)

// Secret is a test deploy target type with one required secret (token) and
// one optional secret (note), for exercising secret split/merge/reuse and
// redaction. Mode and Policy fix its RunsOn/KeyPolicy. Calls records every
// Deploy call's Request, in order. Err, when set, is returned by every
// Deploy call — a caller testing redaction constructs it embedding the
// token's own value.
type Secret struct {
	Code   string
	Mode   targets.Mode
	Policy targets.KeyPolicy
	Calls  []targets.Request
	Err    error
}

// Type implements targets.Target.
func (s *Secret) Type() string { return s.Code }

// Name implements targets.Target.
func (s *Secret) Name() string { return s.Code }

// Schema implements targets.Target: url (uri), token (required secret),
// note (optional secret), includeKey (bool, honored when Policy is
// targets.Optional).
func (s *Secret) Schema() json.RawMessage {
	return json.RawMessage(`{
  "type": "object",
  "additionalProperties": false,
  "required": ["url", "token"],
  "properties": {
    "url": {"type": "string", "format": "uri", "description": "Endpoint URL."},
    "token": {"type": "string", "secret": true, "description": "Authentication token."},
    "note": {"type": "string", "secret": true, "description": "Optional secret note."},
    "includeKey": {"type": "boolean", "description": "Include the certificate's private key."}
  }
}`)
}

// RunsOn implements targets.Target.
func (s *Secret) RunsOn() targets.Mode { return s.Mode }

// KeyPolicy implements targets.Target.
func (s *Secret) KeyPolicy() targets.KeyPolicy { return s.Policy }

// Parse implements targets.Target: validates url as a URI and token as
// non-empty (so clearing the required secret fails, the same as any
// product type's own required-secret check), and returns Config.URLs =
// [url] and NeedsKey from Policy/includeKey.
func (s *Secret) Parse(raw json.RawMessage) (targets.Config, error) {
	var doc struct {
		URL        string `json:"url"`
		Token      string `json:"token"`
		IncludeKey bool   `json:"includeKey"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return targets.Config{}, fmt.Errorf("targetstest: %w", err)
	}
	if doc.URL == "" {
		return targets.Config{}, fmt.Errorf("targetstest: url: required")
	}
	if u, err := url.ParseRequestURI(doc.URL); err != nil || u.Scheme == "" || u.Host == "" {
		return targets.Config{}, fmt.Errorf("targetstest: url: must be an absolute uri")
	}
	if doc.Token == "" {
		return targets.Config{}, fmt.Errorf("targetstest: token: required")
	}
	pub, secrets, err := targets.Split(s.Schema(), raw)
	if err != nil {
		return targets.Config{}, err
	}
	needsKey := s.Policy == targets.Always || (s.Policy == targets.Optional && doc.IncludeKey)
	return targets.Config{Public: pub, Secrets: secrets, NeedsKey: needsKey, URLs: []string{doc.URL}}, nil
}

// Deploy implements targets.Target: records req and returns Err.
func (s *Secret) Deploy(_ context.Context, req targets.Request) (targets.Result, error) {
	s.Calls = append(s.Calls, req)
	if s.Err != nil {
		return targets.Result{}, s.Err
	}
	return targets.Result{}, nil
}
