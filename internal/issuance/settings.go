package issuance

import (
	_ "embed"
	"encoding/json"

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
