package issuance

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"

	"github.com/metril/certforge/internal/settings"
)

//go:embed defaults.schema.json
var defaultsSchema []byte

// RegisterSettings adds the global "issuance_defaults" section (schema plus
// built-in values) to the registry that serves /settings/{section}.
func RegisterSettings(r *settings.Registry) error {
	def, err := json.Marshal(BuiltinDefaults())
	if err != nil {
		return err
	}
	return r.Register(SettingsKey, defaultsSchema, def)
}

//go:embed issuance.schema.json
var issuanceSchema []byte

// SettingsSectionIssuance is the global settings section holding
// IssuanceSettings: CAA checking and the ACME rate-limit ledger's limits.
// Unlike SettingsKey (issuance_defaults), it does not inherit down to orgs
// or certificates.
const SettingsSectionIssuance = "issuance"

// RateLimits are the CA's own ACME rate limits, tracked locally so an order
// can be refused before the CA itself rejects it. 0 disables a limit.
type RateLimits struct {
	CertsPerRegisteredDomainPerWeek int `json:"certsPerRegisteredDomainPerWeek"`
	DuplicateCertsPerWeek           int `json:"duplicateCertsPerWeek"`
	FailedValidationsPerHour        int `json:"failedValidationsPerHour"`
	NewOrdersPer3Hours              int `json:"newOrdersPer3Hours"`
}

// IssuanceSettings is the "issuance" global settings section.
type IssuanceSettings struct {
	CAACheck   bool       `json:"caaCheck"`
	RateLimits RateLimits `json:"rateLimits"`
}

// defaultIssuanceSettings is IssuanceSettings' built-in value: CAA checking
// on, and the rate limits Let's Encrypt itself publishes.
func defaultIssuanceSettings() IssuanceSettings {
	return IssuanceSettings{
		CAACheck: true,
		RateLimits: RateLimits{
			CertsPerRegisteredDomainPerWeek: 50,
			DuplicateCertsPerWeek:           5,
			FailedValidationsPerHour:        5,
			NewOrdersPer3Hours:              300,
		},
	}
}

// RegisterIssuanceSettings adds the global "issuance" section (schema plus
// built-in values) to the registry that serves /settings/{section}.
func RegisterIssuanceSettings(r *settings.Registry) error {
	def, err := json.Marshal(defaultIssuanceSettings())
	if err != nil {
		return err
	}
	return r.Register(SettingsSectionIssuance, issuanceSchema, def)
}

// LoadIssuanceSettings reads the global "issuance" section, falling back to
// its built-in defaults when it has never been saved. The schema has no
// "required", and a PUT replaces the whole section, so a saved document
// that omits a field (a partial {"rateLimits":{...}}, or a bare "{}") must
// not decode as that field's zero value — decoding starts from the
// built-in defaults so json.Unmarshal only overwrites the fields the
// stored document actually names, matching agents.Settings' own
// Resolve-from-defaults behaviour.
func LoadIssuanceSettings(ctx context.Context, store *settings.Store) (IssuanceSettings, error) {
	s := defaultIssuanceSettings()
	err := store.Get(ctx, settings.SectionKey(SettingsSectionIssuance), &s)
	if errors.Is(err, settings.ErrNotFound) {
		return defaultIssuanceSettings(), nil
	}
	return s, err
}
