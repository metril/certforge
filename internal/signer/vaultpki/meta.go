package vaultpki

import (
	"encoding/json"

	"github.com/metril/certforge/internal/meta"
)

// ConfigSchema is VaultPkiConfig's JSON schema for GET /meta/schemas
// (Shared contract: signers[vaultpki]).
const ConfigSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Vault PKI",
  "description": "A private CA backed by Vault's (or OpenBao's) PKI secrets engine. Requires Settings → Integrations → Vault to be configured first.",
  "type": "object",
  "additionalProperties": false,
  "required": ["role"],
  "properties": {
    "mount": {
      "type": "string", "pattern": "^[A-Za-z0-9_-][A-Za-z0-9_/-]{0,127}$", "default": "pki",
      "title": "Mount", "description": "Vault PKI secrets engine mount path."
    },
    "role": {
      "type": "string", "minLength": 1, "maxLength": 128,
      "title": "Role", "description": "Vault PKI role to sign leaves against."
    },
    "ttl": {
      "type": "string", "title": "TTL",
      "description": "Go duration string for issued leaf validity, 1h to 19800h (825 days); Vault's own role or mount ceiling still applies."
    }
  }
}`

// AddToMeta publishes vaultpki's config schema under meta.KindSigner for
// GET /api/v1/meta/schemas.
func AddToMeta(r *meta.Registry) {
	r.Add(meta.KindSigner, meta.Entry{Code: Code, Name: "Vault PKI", Schema: json.RawMessage(ConfigSchema)})
}
