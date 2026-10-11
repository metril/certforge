package adcs

import (
	"encoding/json"

	"github.com/metril/certforge/internal/meta"
)

// ConfigSchema is AdcsConfig's JSON schema for GET /meta/schemas
// (Shared contract: signers[adcs]).
const ConfigSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Active Directory Certificate Services",
  "description": "A private CA backed by Microsoft AD CS through the Certificate Enrollment Policy and Enrollment web services with username/password authentication. Revocation is manual in AD CS.",
  "type": "object",
  "additionalProperties": false,
  "required": ["cepUrl", "template", "username"],
  "properties": {
    "cepUrl": {"type": "string", "format": "uri", "title": "Policy (CEP) URL", "description": "https://<host>/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP"},
    "cesUrl": {"type": "string", "format": "uri", "title": "Enrollment (CES) URL", "description": "Optional; resolved from the policy when empty."},
    "template": {"type": "string", "minLength": 1, "title": "Template", "description": "Certificate template name; must permit Read+Enroll for the service account and supply the subject in the request."},
    "username": {"type": "string", "minLength": 1, "title": "Username", "description": "Service account (DOMAIN\\user or UPN)."},
    "caBundlePem": {"type": "string", "title": "TLS CA bundle", "description": "PEM roots to trust for the web services' HTTPS certificate."},
    "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 300, "default": 30, "title": "Timeout (seconds)"}
  }
}`

// AddToMeta publishes adcs's config schema under meta.KindSigner for
// GET /api/v1/meta/schemas.
func AddToMeta(r *meta.Registry) {
	r.Add(meta.KindSigner, meta.Entry{Code: Code, Name: "Active Directory (AD CS)", Schema: json.RawMessage(ConfigSchema)})
}
