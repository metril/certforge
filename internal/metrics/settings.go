// Package metrics exposes CertForge's Prometheus /metrics endpoint: a
// bearer-token-protected scrape target for certificate, deployment,
// notification, monitor and backup series (Shared contract, Metrics row).
// This file adds the "prometheus" global settings section (Shared contract,
// Settings row); the collector, registry and HTTP handler land in Phase 6A
// Task 8.
package metrics

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/metril/certforge/internal/settings"
)

// SectionName is the global settings section gating and securing /metrics.
const SectionName = "prometheus"

//go:embed prometheus.schema.json
var settingsSchema []byte

const settingsDefault = `{"enabled":false}`

// Settings is the "prometheus" section.
type Settings struct {
	Enabled     bool   `json:"enabled"`
	BearerToken string `json:"bearerToken"`
}

// RegisterSettings adds the prometheus section and its extra check.
func RegisterSettings(r *settings.Registry) error {
	if err := r.Register(SectionName, json.RawMessage(settingsSchema), json.RawMessage(settingsDefault)); err != nil {
		return err
	}
	return r.AddUpdateCheck(SectionName, checkTokenRequired)
}

// minBearerTokenLen is the token's minimum length. It lives here, not as
// the schema's own minLength (batch-1 review finding 2): Section.Validate
// runs the schema against the full incoming value, secret fields included,
// before ValidateUpdate (this check) ever sees it — so a schema-level
// minLength would 422 the ordinary "keep what's stored" update
// {"enabled":true,"bearerToken":"__unchanged__"} on the sentinel's own
// length (13), never reaching the "was it actually fresh" question at all.
// Enforcing the minimum here, for a fresh value only, keeps that update
// working while still bounding a real token the same way the schema's
// maxLength already does for every value, fresh or not.
const minBearerTokenLen = 16

// checkTokenRequired enforces "bearerToken required when enabled" (Shared
// contract, Settings row): the schema alone cannot express a conditional
// requirement on a secret property (settings.secretProps forbids
// pattern/enum/const/format on one, and a plain "required" would also
// reject an update that means to keep an already-stored token). A token
// counts as present either freshly sent on next, or, when the previous save
// had enabled=true, already sealed in storage: every save that reached
// enabled=true already passed this same check, so by induction a stored
// token exists whenever stored.enabled is true. stored is nil on the
// section's first save.
func checkTokenRequired(stored, next json.RawMessage) error {
	var n Settings
	if err := json.Unmarshal(next, &n); err != nil {
		return err
	}
	if !n.Enabled {
		return nil
	}
	if n.BearerToken != "" && n.BearerToken != settings.Unchanged {
		if len(n.BearerToken) < minBearerTokenLen {
			return fmt.Errorf("bearerToken must be at least %d characters", minBearerTokenLen)
		}
		return nil
	}
	if stored != nil {
		var s Settings
		if err := json.Unmarshal(stored, &s); err != nil {
			return err
		}
		if s.Enabled {
			return nil
		}
	}
	return errors.New("bearerToken is required when enabled")
}
