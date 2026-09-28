package localca

import (
	"encoding/json"

	"github.com/metril/certforge/internal/meta"
)

// Code is this signer's CaType/meta.Entry code.
const Code = "localca"

// ConfigSchema is LocalCaConfig's JSON schema for GET /meta/schemas
// (Shared contract: signers[localca]). importKeyPem carries the same
// "secret": true marker DNS provider schemas use (internal/challenge) so
// the UI never echoes it back after a write.
const ConfigSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Private CA (built-in)",
  "description": "CertForge's built-in root-plus-issuing-intermediate CA. Generates its own key material, or imports an operator-supplied issuing certificate and key.",
  "type": "object",
  "additionalProperties": false,
  "required": ["subject"],
  "properties": {
    "subject": {
      "type": "object",
      "title": "Subject",
      "description": "Root and issuing certificate subject. Immutable after create.",
      "additionalProperties": false,
      "required": ["commonName"],
      "properties": {
        "commonName": {"type": "string", "minLength": 1, "maxLength": 64, "title": "Common name"},
        "organization": {"type": "string", "maxLength": 64, "title": "Organization"},
        "country": {"type": "string", "pattern": "^[A-Z]{2}$", "title": "Country", "description": "ISO 3166-1 alpha-2 code."}
      }
    },
    "keyType": {
      "type": "string", "enum": ["ec256", "ec384", "rsa2048", "rsa4096"], "default": "ec256",
      "title": "Key type", "description": "Key algorithm for the root and issuing keys. Immutable after create."
    },
    "rootValidityYears": {"type": "integer", "minimum": 1, "maximum": 30, "default": 10, "title": "Root validity (years)", "description": "Immutable after create."},
    "issuingValidityYears": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3, "title": "Issuing validity (years)", "description": "Immutable after create."},
    "maxLeafDays": {"type": "integer", "minimum": 1, "maximum": 825, "default": 397, "title": "Max leaf validity (days)", "description": "Longest validity this CA will issue a leaf for. Editable after create."},
    "crl": {"type": "boolean", "default": true, "title": "Publish CRL", "description": "Publish a CRL at GET /crl/{caId}.crl. Editable after create."},
    "importPem": {
      "type": "string", "title": "Import: certificate chain",
      "description": "Create only, immutable after: PEM to import instead of generating a root — the issuing certificate followed by its chain (the last certificate is the trust anchor)."
    },
    "importKeyPem": {
      "type": "string", "secret": true, "title": "Import: private key",
      "description": "Create only, immutable after: PEM private key for importPem's issuing certificate. Never returned."
    }
  }
}`

// AddToMeta publishes localca's config schema under meta.KindSigner for
// GET /api/v1/meta/schemas.
func AddToMeta(r *meta.Registry) {
	r.Add(meta.KindSigner, meta.Entry{Code: Code, Name: "Private CA (built-in)", Schema: json.RawMessage(ConfigSchema)})
}
