// Command gen-lego-schemas turns lego's per-provider TOML metadata
// (providers/dns/<code>/<code>.toml) into JSON Schemas embedded by
// internal/challenge, and writes docs/dns-providers.md from the same data.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

type providerTOML struct {
	Name          string
	Code          string
	URL           string
	Aliases       []string
	Configuration struct {
		Credentials map[string]string
		Additional  map[string]string
	}
}

type property struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Secret      bool   `json:"secret"`
	ServerPath  bool   `json:"serverPath,omitempty"`
	Group       string `json:"x-group"`
}

type schema struct {
	Schema               string              `json:"$schema"`
	Title                string              `json:"title"`
	Type                 string              `json:"type"`
	AdditionalProperties bool                `json:"additionalProperties"`
	Properties           map[string]property `json:"properties"`
}

type providerFile struct {
	Code    string   `json:"code"`
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
	Schema  schema   `json:"schema"`
}

// secretName marks fields as write-only based on their name. It runs over
// both the Credentials and Additional groups: lego's "Additional" section is
// a mix of tuning knobs and secondary credentials (session tokens, shared
// secrets, TOTP seeds), so grouping alone is not a safe secret signal.
var secretName = regexp.MustCompile(`(?i)(secret|token|key|password|pass)`)

// nonSecretSuffix marks fields that name-match secretName but hold an
// identifier, file path, or other non-sensitive value, not the secret
// itself (an access key *id*, a path to a key file, ...).
var nonSecretSuffix = regexp.MustCompile(`(?:_KEY_ID|_PATH|_FILE)$`)

// serverPathSuffix marks fields that hold a local file path lego reads on
// the server (a credentials JSON file, a private key file, ...). The API
// rejects these (they name a path on the certforge server's own
// filesystem, not something a remote caller can supply) in favor of the
// provider's inline field carrying the same material.
var serverPathSuffix = regexp.MustCompile(`(?:_FILE|_PATH)$`)

// forceSecret overrides the name-based rules for fields that are secrets in
// practice but whose names don't match secretName.
var forceSecret = map[string]bool{
	"GCE_SERVICE_ACCOUNT":   true, // gcloud: JSON service-account key material
	"EPIK_SIGNATURE":        true, // epik: API signature
	"DNSHOMEDE_CREDENTIALS": true, // dnshomede: domain:password pairs
	"NICMANAGER_API_OTP":    true, // nicmanager: TOTP secret
}

// forceNonSecret overrides secretName/nonSecretSuffix for fields that
// name-match "secret" but hold public or non-sensitive material.
var forceNonSecret = map[string]bool{
	"OCI_PUBKEY_FINGERPRINT":     true, // oraclecloud: fingerprint of a public key
	"RFC2136_TSIG_KEY":           true, // rfc2136: TSIG key *name*, not the secret payload (RFC2136_TSIG_SECRET)
	"AKAMAI_ACCOUNT_SWITCH_KEY":  true, // edgedns: target account id
	"SCW_ACCESS_KEY":             true, // scaleway: access key id, paired with the secret SCW_SECRET_KEY
	"HYPERONE_PASSPORT_LOCATION": true, // hyperone: local file path
}

// isSecret decides whether field k is write-only, in order: explicit
// force-secret, explicit force-non-secret or non-secret suffix, then the
// name regex.
func isSecret(k string) bool {
	if forceSecret[k] {
		return true
	}
	if forceNonSecret[k] || nonSecretSuffix.MatchString(k) {
		return false
	}
	return secretName.MatchString(k)
}

// validKey rejects lego TOML entries whose "key" is prose, not an
// environment variable name (for example gcloud's 'Application Default
// Credentials' or azure's 'instance metadata service' documentation rows).
var validKey = regexp.MustCompile(`^[A-Z0-9_]+$`)

// skipped providers: "manual" reads stdin, "exec" runs an arbitrary program
// on the server; neither is safe to expose as a stored credential.
var skipped = map[string]bool{"manual": true, "exec": true}

// legoVersion is the pinned lego version this generator's overrides
// (forceSecret, forceNonSecret) were reviewed against. Bumping lego's
// go.mod pin requires bumping this constant and reviewing the regenerated
// schema diff for new or renamed fields the overrides above should cover.
const legoVersion = "v4.24.0"

func main() {
	legoDir := flag.String("lego-dir", "", "lego module dir (default: resolved via go mod download)")
	out := flag.String("out", "schemas", "output directory for <code>.json")
	docs := flag.String("docs", "", "markdown output path (optional)")
	flag.Parse()
	if *legoDir == "" {
		dir, err := resolveLegoDir()
		if err != nil {
			log.Fatal(err)
		}
		*legoDir = dir
	}
	if err := generate(*legoDir, *out, *docs); err != nil {
		log.Fatal(err)
	}
}

// modDownload is the subset of `go mod download -json`'s output this tool
// needs.
type modDownload struct {
	Version string
	Dir     string
}

// resolveLegoDir locates (and, on a cold module cache, downloads) the lego
// module directory. `go list -m -f '{{.Dir}}'` prints an empty Dir when the
// module isn't already extracted in the cache; `go mod download -json`
// downloads it first, so Dir is always populated on success.
func resolveLegoDir() (string, error) {
	b, err := exec.Command("go", "mod", "download", "-json", "github.com/go-acme/lego/v4").Output()
	if err != nil {
		return "", fmt.Errorf("go mod download github.com/go-acme/lego/v4: %w", err)
	}
	var m modDownload
	if err := json.Unmarshal(b, &m); err != nil {
		return "", fmt.Errorf("parse go mod download output: %w", err)
	}
	if m.Dir == "" {
		return "", fmt.Errorf("go mod download github.com/go-acme/lego/v4: resolved an empty module directory")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "providers", "dns")); err != nil {
		return "", fmt.Errorf("%s has no providers/dns directory: %w", m.Dir, err)
	}
	if m.Version != legoVersion {
		return "", fmt.Errorf("resolved lego %s, want %s: bump legoVersion in tools/gen-lego-schemas/main.go and review the regenerated schema diff", m.Version, legoVersion)
	}
	return m.Dir, nil
}

func generate(legoDir, outDir, docsPath string) error {
	paths, err := filepath.Glob(filepath.Join(legoDir, "providers", "dns", "*", "*.toml"))
	if err != nil {
		return err
	}
	var files []providerFile
	for _, p := range paths {
		var t providerTOML
		if _, err := toml.DecodeFile(p, &t); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if t.Code == "" || skipped[t.Code] {
			continue
		}
		files = append(files, convert(t))
	}
	// A misresolved lego module dir (for example an empty extracted module
	// cache) would otherwise glob to zero files and silently wipe outDir.
	if len(files) == 0 {
		return fmt.Errorf("no providers found under %s: refusing to overwrite %s", legoDir, outDir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Code < files[j].Code })
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	old, err := filepath.Glob(filepath.Join(outDir, "*.json"))
	if err != nil {
		return err
	}
	for _, o := range old {
		if err := os.Remove(o); err != nil {
			return err
		}
	}
	for _, f := range files {
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outDir, f.Code+".json"), append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	if docsPath != "" {
		return os.WriteFile(docsPath, renderDocs(files), 0o644)
	}
	return nil
}

func convert(t providerTOML) providerFile {
	props := map[string]property{}
	for k, d := range t.Configuration.Credentials {
		if !validKey.MatchString(k) {
			continue
		}
		props[k] = property{Type: "string", Title: k, Description: d, Secret: isSecret(k), ServerPath: serverPathSuffix.MatchString(k), Group: "credentials"}
	}
	// Additional fields are mostly tuning knobs, but a few (session tokens,
	// shared secrets, TOTP seeds) are secondary credentials, so they run
	// through the same classifier as Credentials.
	for k, d := range t.Configuration.Additional {
		if !validKey.MatchString(k) {
			continue
		}
		props[k] = property{Type: "string", Title: k, Description: d, Secret: isSecret(k), ServerPath: serverPathSuffix.MatchString(k), Group: "additional"}
	}
	return providerFile{
		Code: t.Code, Name: t.Name, URL: t.URL, Aliases: t.Aliases,
		Schema: schema{
			Schema: "https://json-schema.org/draft/2020-12/schema", Title: t.Name, Type: "object",
			AdditionalProperties: false, Properties: props,
		},
	}
}

func renderDocs(files []providerFile) []byte {
	var b bytes.Buffer
	b.WriteString("# DNS providers\n\n")
	b.WriteString("Generated by `tools/gen-lego-schemas` from lego's provider metadata. Do not edit by hand.\n\n")
	b.WriteString("Fields marked secret are write-only: the API never returns them, and a PUT with `__unchanged__` keeps the stored value. Fields in the additional group are optional tuning knobs.\n\n")
	b.WriteString("The lego `exec` provider (runs an arbitrary program on the server) and `manual` provider (reads stdin) are not offered here; use verification rule method `manual-dns` instead.\n\n")
	b.WriteString("Fields whose name ends in `_FILE` or `_PATH` (schema `serverPath: true`) name a path on lego's own host filesystem; the API rejects a value for these with a 422 and expects the provider's inline field with the same material instead.\n\n")
	for _, f := range files {
		fmt.Fprintf(&b, "## %s\n\nCode: `%s`", f.Name, f.Code)
		if len(f.Aliases) > 0 {
			fmt.Fprintf(&b, " (aliases: `%s`)", strings.Join(f.Aliases, "`, `"))
		}
		if f.URL != "" {
			fmt.Fprintf(&b, ". Website: <%s>", f.URL)
		}
		b.WriteString("\n\n| Field | Group | Secret | Description |\n|---|---|---|---|\n")
		keys := make([]string, 0, len(f.Schema.Properties))
		for k := range f.Schema.Properties {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			pi, pj := f.Schema.Properties[keys[i]], f.Schema.Properties[keys[j]]
			if pi.Group != pj.Group {
				return pi.Group == "credentials"
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			p := f.Schema.Properties[k]
			secret := "no"
			if p.Secret {
				secret = "yes"
			}
			desc := strings.ReplaceAll(p.Description, "|", `\|`)
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", k, p.Group, secret, desc)
		}
		b.WriteString("\n")
	}
	return b.Bytes()
}
