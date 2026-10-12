package targets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Credential kinds. Field names match the target fields a credential supplies.
const (
	CredKindSSH      = "ssh"
	CredKindPassword = "password"
	CredKindAPIKey   = "apiKey"
	CredKindToken    = "token"
)

// credentialKindSchemas holds each kind's JSON Schema. Secret properties are
// marked "secret": true like a target schema's, so Split separates them.
var credentialKindSchemas = map[string]json.RawMessage{
	CredKindSSH: json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "SSH login",
  "description": "A username with a password, a private key, or both.",
  "type": "object",
  "additionalProperties": false,
  "required": ["username"],
  "anyOf": [{"required": ["password"]}, {"required": ["privateKey"]}],
  "properties": {
    "username": {"type": "string", "minLength": 1, "title": "Username"},
    "password": {"type": "string", "secret": true, "title": "Password"},
    "privateKey": {"type": "string", "secret": true, "maxLength": 8192, "title": "Private key", "description": "PEM private key (not passphrase-protected)."}
  }
}`),
	CredKindPassword: json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Username and password",
  "type": "object",
  "additionalProperties": false,
  "required": ["username", "password"],
  "properties": {
    "username": {"type": "string", "minLength": 1, "title": "Username"},
    "password": {"type": "string", "secret": true, "minLength": 1, "title": "Password"}
  }
}`),
	CredKindAPIKey: json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "API key",
  "type": "object",
  "additionalProperties": false,
  "required": ["apiKey"],
  "properties": {
    "apiKey": {"type": "string", "secret": true, "minLength": 1, "title": "API key"},
    "username": {"type": "string", "title": "Username"}
  }
}`),
	CredKindToken: json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "API token",
  "type": "object",
  "additionalProperties": false,
  "required": ["token"],
  "properties": {
    "token": {"type": "string", "secret": true, "minLength": 1, "title": "Token"}
  }
}`),
}

// Kinds returns the credential kind names, sorted.
func Kinds() []string {
	out := make([]string, 0, len(credentialKindSchemas))
	for k := range credentialKindSchemas {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// KindSchema returns kind's JSON Schema, and false for an unknown kind.
func KindSchema(kind string) (json.RawMessage, bool) {
	s, ok := credentialKindSchemas[kind]
	return s, ok
}

// AcceptedKinds returns the credential kinds a target schema accepts, read
// from its top-level "credentialKinds" keyword; nil when absent.
func AcceptedKinds(schema json.RawMessage) []string {
	var doc struct {
		Kinds []string `json:"credentialKinds"`
	}
	if err := json.Unmarshal(schema, &doc); err != nil {
		return nil
	}
	return doc.Kinds
}

// Credential is a stored credential's resolved content: its kind, public
// fields (JSON object) and opened secret fields.
type Credential struct {
	Kind    string
	Public  json.RawMessage
	Secrets map[string]string
}

// fields returns every field name the credential supplies, sorted.
func (c Credential) fields() ([]string, map[string]json.RawMessage, error) {
	var pub map[string]json.RawMessage
	if len(c.Public) > 0 {
		if err := json.Unmarshal(c.Public, &pub); err != nil {
			return nil, nil, fmt.Errorf("targets: credential public: %w", err)
		}
	}
	if pub == nil {
		pub = map[string]json.RawMessage{}
	}
	names := make([]string, 0, len(pub)+len(c.Secrets))
	for k := range pub {
		names = append(names, k)
	}
	for k := range c.Secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, pub, nil
}

// Conflicts returns the sorted names of fields the credential supplies that
// config or targetSecrets also set; nil when cred is nil or none overlap.
func Conflicts(config json.RawMessage, targetSecrets map[string]string, cred *Credential) ([]string, error) {
	if cred == nil {
		return nil, nil
	}
	names, _, err := cred.fields()
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if len(config) > 0 {
		if err := json.Unmarshal(config, &doc); err != nil {
			return nil, fmt.Errorf("targets: %w", err)
		}
	}
	var out []string
	for _, n := range names {
		if _, ok := doc[n]; ok {
			out = append(out, n)
		} else if _, ok := targetSecrets[n]; ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// Resolve returns the full target config: Merge(config, targetSecrets) with
// the credential's public and secret fields overlaid. It fails when the
// config also holds a field the credential supplies. A nil cred is plain
// Merge, so embedded-secret targets are unaffected.
func Resolve(config json.RawMessage, targetSecrets map[string]string, cred *Credential) (json.RawMessage, error) {
	if cred == nil {
		return Merge(config, targetSecrets)
	}
	if bad, err := Conflicts(config, targetSecrets, cred); err != nil {
		return nil, err
	} else if len(bad) > 0 {
		return nil, fmt.Errorf("targets: config sets fields the credential supplies: %s", strings.Join(bad, ", "))
	}
	merged, err := Merge(config, targetSecrets)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(merged, &doc); err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}
	_, pub, err := cred.fields()
	if err != nil {
		return nil, err
	}
	for k, v := range pub {
		doc[k] = v
	}
	for k, v := range cred.Secrets {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		doc[k] = b
	}
	return json.Marshal(doc)
}

var (
	credSchemaMu    sync.Mutex
	credSchemaCache = map[string]*jsonschema.Schema{}
)

func compiledKindSchema(kind string) (*jsonschema.Schema, error) {
	credSchemaMu.Lock()
	defer credSchemaMu.Unlock()
	if sc, ok := credSchemaCache[kind]; ok {
		return sc, nil
	}
	raw, ok := credentialKindSchemas[kind]
	if !ok {
		return nil, fmt.Errorf("targets: unknown credential kind %q", kind)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	url := "https://certforge.invalid/schemas/deploy-credentials/" + kind + ".json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	sc, err := c.Compile(url)
	if err != nil {
		return nil, err
	}
	credSchemaCache[kind] = sc
	return sc, nil
}

// ValidateCredential checks a credential's full config (secrets included)
// against its kind's schema. The kind schemas carry no pattern, enum, const
// or format keyword on a secret field, so the error never echoes a secret.
func ValidateCredential(kind string, config json.RawMessage) error {
	sc, err := compiledKindSchema(kind)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(config))
	if err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	if err := sc.Validate(inst); err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	return nil
}

// SplitCredential separates a credential config into its public JSON and its
// secret fields, by the kind's schema.
func SplitCredential(kind string, config json.RawMessage) (json.RawMessage, map[string]string, error) {
	schema, ok := credentialKindSchemas[kind]
	if !ok {
		return nil, nil, fmt.Errorf("targets: unknown credential kind %q", kind)
	}
	return Split(schema, config)
}

// SecretFields returns kind's secret property names, sorted; nil for an
// unknown kind.
func SecretFields(kind string) []string {
	schema, ok := credentialKindSchemas[kind]
	if !ok {
		return nil
	}
	keys, err := SecretProps(schema)
	if err != nil {
		return nil
	}
	return keys
}

// OpenCredential builds a Credential from a joined row's columns; nil when
// kind is nil (the target has no credential). open decrypts sealed.
func OpenCredential(ctx context.Context, open func(context.Context, []byte) ([]byte, error), kind *string, public, sealed []byte) (*Credential, error) {
	if kind == nil {
		return nil, nil
	}
	c := &Credential{Kind: *kind, Public: public, Secrets: map[string]string{}}
	if len(sealed) > 0 {
		pt, err := open(ctx, sealed)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(pt, &c.Secrets); err != nil {
			return nil, fmt.Errorf("targets: credential secrets: %w", err)
		}
	}
	return c, nil
}
