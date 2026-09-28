package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/vault"
)

// TypeVaultKV is the vault-kv deploy target type: a server-run target that
// writes a certificate's rendered files as one KV v2 secret document
// (Shared contract: deploy_targets.type, DeployTargetType).
const TypeVaultKV = "vault-kv"

// Defaults for a vault-kv target's config (Shared contract Meta row).
const (
	defaultMount     = "secret"
	defaultPath      = "certforge/{org}/{name}"
	defaultFullchain = "fullchain.pem"
	defaultCert      = "cert.pem"
	defaultChain     = "chain.pem"
	defaultKey       = "privkey.pem"
)

var (
	// mountRe matches a Vault secrets-engine mount path (same character
	// set the vaultpki signer's mount uses).
	mountRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_/-]{0,127}$`)
	// keyNameRe matches a KV document field name.
	keyNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	// pathCharsRe matches a rendered KV path.
	pathCharsRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,512}$`)
	// placeholderRe matches one {...} placeholder in a path template.
	placeholderRe = regexp.MustCompile(`\{[^{}]*\}`)
)

// KeyNames is the KV document field name each PEM part is written under.
type KeyNames struct {
	Fullchain string `json:"fullchain,omitempty"`
	Cert      string `json:"cert,omitempty"`
	Chain     string `json:"chain,omitempty"`
	Key       string `json:"key,omitempty"`
}

// VaultKVConfig is a vault-kv target's config (Shared contract Meta row:
// deployTargets[vault-kv]).
type VaultKVConfig struct {
	Mount      string   `json:"mount,omitempty"`
	Path       string   `json:"path,omitempty"`
	Keys       KeyNames `json:"keys,omitempty"`
	IncludeKey bool     `json:"includeKey,omitempty"`
}

// fillDefaults sets every empty field to its default.
func (c *VaultKVConfig) fillDefaults() {
	if c.Mount == "" {
		c.Mount = defaultMount
	}
	if c.Path == "" {
		c.Path = defaultPath
	}
	if c.Keys.Fullchain == "" {
		c.Keys.Fullchain = defaultFullchain
	}
	if c.Keys.Cert == "" {
		c.Keys.Cert = defaultCert
	}
	if c.Keys.Chain == "" {
		c.Keys.Chain = defaultChain
	}
	if c.Keys.Key == "" {
		c.Keys.Key = defaultKey
	}
}

// vaultKVSchema is VaultKVConfig's JSON schema for GET /meta/schemas
// (Shared contract: deployTargets[vault-kv]).
const vaultKVSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Vault KV",
  "description": "Writes a certificate's files as one document in a Vault (or OpenBao) KV v2 secrets engine. Runs on the server; needs Settings → Integrations → Vault to be configured first.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "mount": {
      "type": "string", "pattern": "^[A-Za-z0-9_-][A-Za-z0-9_/-]{0,127}$", "default": "secret",
      "title": "Mount", "description": "Vault KV v2 secrets engine mount path."
    },
    "path": {
      "type": "string", "default": "certforge/{org}/{name}",
      "title": "Path", "description": "Secret path within the mount. May use {org} (org slug), {cert} (certificate id) and {name} (certificate name); no other placeholder is allowed. The rendered path must not start with / or contain .."
    },
    "keys": {
      "type": "object", "additionalProperties": false,
      "title": "Document fields", "description": "KV document field name each PEM part is written under.",
      "properties": {
        "fullchain": {"type": "string", "default": "fullchain.pem", "title": "Fullchain field"},
        "cert": {"type": "string", "default": "cert.pem", "title": "Certificate field"},
        "chain": {"type": "string", "default": "chain.pem", "title": "Chain field"},
        "key": {"type": "string", "default": "privkey.pem", "title": "Private key field"}
      }
    },
    "includeKey": {
      "type": "boolean", "default": false,
      "title": "Include private key", "description": "Also write the private key. A grant onto a target with this set needs keys:export."
    }
  }
}`

// VaultKV is the "vault-kv" server-run deploy target: it writes a
// certificate's rendered files as one KV v2 secret document. Vault is nil
// only in tests that never call Deploy.
type VaultKV struct {
	Vault *vault.Provider
}

// Type returns TypeVaultKV.
func (VaultKV) Type() string { return TypeVaultKV }

// Schema returns vault-kv's config JSON schema.
func (VaultKV) Schema() json.RawMessage { return json.RawMessage(vaultKVSchema) }

// ParseConfig validates raw against vault-kv's rules and returns the
// canonical config to store, with defaults filled in.
func (VaultKV) ParseConfig(raw json.RawMessage) (json.RawMessage, error) {
	var c VaultKVConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, &delivery.FieldError{Field: "config", Msg: err.Error()}
	}
	c.fillDefaults()
	if !mountRe.MatchString(c.Mount) {
		return nil, &delivery.FieldError{Field: "config.mount", Msg: "must match ^[A-Za-z0-9_-][A-Za-z0-9_/-]{0,127}$"}
	}
	// A static smoke test of the template's shape: safe, pattern-valid
	// placeholder values, so a failure here is always about the template
	// itself (an unknown placeholder, a leading /, .. or a bad literal
	// character), never about a real org/cert/name value (checked again,
	// for real, at Deploy time).
	if _, err := renderPath(c.Path, "org", "00000000-0000-0000-0000-000000000000", "name"); err != nil {
		return nil, &delivery.FieldError{Field: "config.path", Msg: err.Error()}
	}
	for field, v := range map[string]string{"fullchain": c.Keys.Fullchain, "cert": c.Keys.Cert, "chain": c.Keys.Chain, "key": c.Keys.Key} {
		if !keyNameRe.MatchString(v) {
			return nil, &delivery.FieldError{Field: "config.keys." + field, Msg: "must match ^[A-Za-z0-9._-]{1,128}$"}
		}
	}
	return json.Marshal(c)
}

// renderPath renders tmpl, substituting {org}, {cert} and {name}; any other
// {...} placeholder is an error. The result must not start with /, must
// not contain .. and must match pathCharsRe.
func renderPath(tmpl, org, cert, name string) (string, error) {
	var badPlaceholder string
	rendered := placeholderRe.ReplaceAllStringFunc(tmpl, func(ph string) string {
		switch ph {
		case "{org}":
			return org
		case "{cert}":
			return cert
		case "{name}":
			return name
		default:
			if badPlaceholder == "" {
				badPlaceholder = ph
			}
			return ph
		}
	})
	if badPlaceholder != "" {
		return "", fmt.Errorf("unknown placeholder %s; only {org}, {cert} and {name} are allowed", badPlaceholder)
	}
	if strings.HasPrefix(rendered, "/") {
		return "", errors.New("must not start with /")
	}
	if strings.Contains(rendered, "..") {
		return "", errors.New(`must not contain a ".." segment`)
	}
	if !pathCharsRe.MatchString(rendered) {
		return "", errors.New("must match ^[A-Za-z0-9._/-]{1,512}$")
	}
	return rendered, nil
}

// vaultKVData builds the KV v2 document from a target's rendered files:
// the four canonical PEM names (fullchain.pem, cert.pem, chain.pem,
// privkey.pem, as render.PEM.Render produces them) map to the field names
// cfg.Keys holds; any other file (a layout's own output) is written under
// its own base name. A key-bearing file (Secret) is dropped unless
// cfg.IncludeKey.
func vaultKVData(files []render.File, cfg VaultKVConfig) map[string]any {
	data := make(map[string]any, len(files))
	for _, f := range files {
		if f.Secret && !cfg.IncludeKey {
			continue
		}
		key := path.Base(f.Name)
		switch f.Name {
		case "fullchain.pem":
			key = cfg.Keys.Fullchain
		case "cert.pem":
			key = cfg.Keys.Cert
		case "chain.pem":
			key = cfg.Keys.Chain
		case "privkey.pem":
			key = cfg.Keys.Key
		}
		data[key] = string(f.Data)
	}
	return data
}

// Deploy writes req's certificate material to Vault as one KV v2 document
// and returns the path it wrote and the resulting version.
func (t VaultKV) Deploy(ctx context.Context, req Request) (Result, error) {
	raw, err := json.Marshal(req.Config)
	if err != nil {
		return Result{}, err
	}
	canon, err := VaultKV{}.ParseConfig(raw)
	if err != nil {
		return Result{}, err
	}
	var cfg VaultKVConfig
	if err := json.Unmarshal(canon, &cfg); err != nil {
		return Result{}, err
	}
	kvPath, err := renderPath(cfg.Path, req.OrgSlug, req.CertID, delivery.SafeName(req.CertName))
	if err != nil {
		return Result{}, err
	}
	if t.Vault == nil {
		return Result{}, errors.New("deploy: vault-kv: Vault is not configured")
	}
	client, err := t.Vault.Client(ctx)
	if err != nil {
		return Result{}, err
	}
	version, err := client.KVPut(ctx, cfg.Mount, kvPath, vaultKVData(req.Files, cfg), nil)
	if err != nil {
		return Result{}, err
	}
	return Result{Path: kvPath, Version: version}, nil
}
