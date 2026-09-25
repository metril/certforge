package delivery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// TargetTraefik is the Traefik file-provider target type.
const TargetTraefik = "traefik"

// TraefikSchema is the target's config schema (GET /meta/schemas).
const TraefikSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["dir"],
  "properties": {
    "dir": {"type": "string", "title": "Directory on the agent", "description": "Traefik's file-provider directory as the agent sees it; the agent writes certforge-<name>.yml and certs/<name>/ here.", "pattern": "^/", "examples": ["/etc/traefik/dynamic"]},
    "pathPrefix": {"type": "string", "title": "Directory as Traefik sees it", "description": "Prefix for certFile and keyFile in the generated YAML when Traefik mounts the directory elsewhere. Empty means the same as the directory.", "pattern": "^(/.*)?$"},
    "defaultCert": {"type": "boolean", "title": "Default certificate", "description": "Also serve this certificate when no SNI matches (tls.stores.<store>.defaultCertificate).", "default": false},
    "stores": {"type": "array", "title": "TLS stores", "description": "Traefik TLS stores for the certificate. Empty means default.", "items": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}, "default": ["default"]}
  }
}`

// TraefikConfig is a traefik target's config.
type TraefikConfig struct {
	Dir         string   `json:"dir"`
	PathPrefix  string   `json:"pathPrefix,omitempty"`
	DefaultCert bool     `json:"defaultCert,omitempty"`
	Stores      []string `json:"stores,omitempty"`
}

var storeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ParseTarget decodes and validates a deploy target's type and config.
func ParseTarget(typ string, raw json.RawMessage) (TraefikConfig, error) {
	var c TraefikConfig
	if typ != TargetTraefik {
		return c, &FieldError{"type", "the only deploy target type is traefik"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, &FieldError{"config", err.Error()}
	}
	if err := CleanPath("config.dir", c.Dir); err != nil {
		return c, err
	}
	if c.PathPrefix != "" {
		if err := CleanPath("config.pathPrefix", c.PathPrefix); err != nil {
			return c, err
		}
	}
	for _, s := range c.Stores {
		if !storeRe.MatchString(s) {
			return c, &FieldError{"config.stores", fmt.Sprintf("store %q must be 1 to 64 letters, digits, - or _", s)}
		}
	}
	return c, nil
}

var unsafeName = regexp.MustCompile(`[^a-z0-9._-]+`)

// SafeName turns a certificate name into one path component: lower case,
// runs of other characters become a hyphen, no leading or trailing dots or
// hyphens, "cert" when nothing is left.
func SafeName(s string) string {
	n := strings.Trim(unsafeName.ReplaceAllString(strings.ToLower(s), "-"), "-.")
	if len(n) > 100 {
		n = strings.Trim(n[:100], "-.")
	}
	if n == "" {
		return "cert"
	}
	return n
}

// RenderTraefik returns the files the target writes, in write order:
// fullchain.pem, privkey.pem, then certforge-<name>.yml. Removal deletes in
// reverse order, so Traefik drops the certificate before its files vanish.
func RenderTraefik(certName string, cfg TraefikConfig, fullchain, key []byte) []File {
	name := SafeName(certName)
	prefix := cfg.PathPrefix
	if prefix == "" {
		prefix = cfg.Dir
	}
	stores := cfg.Stores
	if len(stores) == 0 {
		stores = []string{"default"}
	}
	certRel := path.Join("certs", name, "fullchain.pem")
	keyRel := path.Join("certs", name, "privkey.pem")
	certFile := strconv.Quote(path.Join(prefix, certRel))
	keyFile := strconv.Quote(path.Join(prefix, keyRel))
	var y strings.Builder
	y.WriteString("# Managed by CertForge. Do not edit; changes are overwritten.\n")
	y.WriteString("tls:\n  certificates:\n")
	fmt.Fprintf(&y, "    - certFile: %s\n      keyFile: %s\n      stores:\n", certFile, keyFile)
	for _, s := range stores {
		fmt.Fprintf(&y, "        - %s\n", strconv.Quote(s))
	}
	if cfg.DefaultCert {
		y.WriteString("  stores:\n")
		for _, s := range stores {
			fmt.Fprintf(&y, "    %s:\n      defaultCertificate:\n        certFile: %s\n        keyFile: %s\n", strconv.Quote(s), certFile, keyFile)
		}
	}
	return []File{
		{Path: path.Join(cfg.Dir, certRel), Mode: "0644", Data: fullchain},
		{Path: path.Join(cfg.Dir, keyRel), Mode: "0600", Data: key},
		{Path: path.Join(cfg.Dir, "certforge-"+name+".yml"), Mode: "0644", Data: []byte(y.String())},
	}
}
