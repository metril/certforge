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
	// AliasOf names the canonical field this one duplicates (lego accepts
	// both spellings); alias fields are never shown as inputs.
	AliasOf string `json:"x-alias-of,omitempty"`
}

type schema struct {
	Schema               string `json:"$schema"`
	Title                string `json:"title"`
	Type                 string `json:"type"`
	AdditionalProperties bool   `json:"additionalProperties"`
	// Unsupported and UnsupportedReason mark a provider whose only lego
	// input is a server-side file this API cannot accept (no inline
	// alternative exists): the registry parses these into ProviderMeta so
	// Providers()/Lookup() can refuse it (422 on create/update) and the UI
	// can grey it out, without removing it from the list.
	Unsupported       bool                `json:"unsupported,omitempty"`
	UnsupportedReason string              `json:"unsupportedReason,omitempty"`
	Properties        map[string]property `json:"properties"`
	// AuthMethods lists the complete ways to authenticate; the UI offers a
	// choice and the server requires one to be satisfied.
	AuthMethods []authMethod `json:"x-auth-methods,omitempty"`
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

// extraCredentialFields adds a Credentials-group field lego's own TOML
// metadata omits, but that its provider actually accepts as an inline env
// var: oraclecloud's configprovider.go (getPrivateKey) reads OCI_PRIVKEY
// directly via os.Getenv and base64.StdEncoding.DecodeString's it — it is
// the base64 encoding of the whole PEM file, not the PEM text itself, and
// falls back to OCI_PRIVKEY_FILE (raw PEM bytes, no base64) only when unset.
// The TOML only documents the _FILE form; without this override oraclecloud
// would be unusable through the API (its only credential field would be a
// rejected serverPath one). Keyed by provider code, then field name to
// description.
var extraCredentialFields = map[string]map[string]string{
	"oraclecloud": {"OCI_PRIVKEY": "Base64-encoded PEM private key (base64 of the whole PEM file), inline; alternative to OCI_PRIVKEY_FILE"},
	// transip and hyperone (below) accept their file-backed credential
	// only as a server-side path through lego's own env var
	// (TRANSIP_PRIVATE_KEY_PATH, HYPERONE_PASSPORT_LOCATION); neither has
	// a lego-native inline alternative like oraclecloud's OCI_PRIVKEY.
	// These entries are certforge's own inline fields, with no lego env
	// var counterpart: internal/challenge.Build (fileBacked) writes the
	// value to a private temp file and points the provider at that path,
	// so the API accepts the credential content directly instead of a
	// path on the certforge server's own filesystem.
	"transip":  {"TRANSIP_PRIVATE_KEY": "PEM-encoded private key, inline; alternative to TRANSIP_PRIVATE_KEY_PATH"},
	"hyperone": {"HYPERONE_PASSPORT": "Passport file contents (JSON), inline; alternative to HYPERONE_PASSPORT_LOCATION"},
}

// unsupportedProviders lists providers whose only lego credential input is
// a server-side file (no inline alternative like oraclecloud's OCI_PRIVKEY
// exists): the API cannot accept a value for that field (serverPathSuffix),
// so there is no way to configure them at all today. Keyed by provider
// code, to the reason shown to the UI. A provider added here should also
// get an extraCredentialFields entry once an inline path exists, same as
// oraclecloud; transip and hyperone got theirs in Phase 5 (see
// extraCredentialFields) and are no longer listed here.
var unsupportedProviders = map[string]string{}

// forceServerPath overrides serverPathSuffix for fields that read a local
// path on the server despite a name that doesn't end in _FILE or _PATH.
var forceServerPath = map[string]bool{
	"INFOBLOX_CA_CERTIFICATE":    true, // infoblox: "The path to the CA certificate (PEM encoded)"
	"HYPERONE_PASSPORT_LOCATION": true, // hyperone: local file path; only HYPERONE_PASSPORT (extraCredentialFields) is accepted inline
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

// isServerPath decides whether field k reads a local path on the server: the
// _FILE/_PATH suffix convention, plus forceServerPath's explicit overrides
// for fields that don't follow it.
func isServerPath(k string) bool {
	return serverPathSuffix.MatchString(k) || forceServerPath[k] || hiddenFields[k]
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
		f, err := convert(filepath.Dir(p), t)
		if err != nil {
			return err
		}
		files = append(files, f)
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

func convert(pkgDir string, t providerTOML) (providerFile, error) {
	props := map[string]property{}
	for k, d := range t.Configuration.Credentials {
		if !validKey.MatchString(k) {
			continue
		}
		props[k] = property{Type: "string", Title: k, Description: d, Secret: isSecret(k), ServerPath: isServerPath(k), Group: "credentials"}
	}
	// Additional fields are mostly tuning knobs, but a few (session tokens,
	// shared secrets, TOTP seeds) are secondary credentials, so they run
	// through the same classifier as Credentials.
	for k, d := range t.Configuration.Additional {
		if !validKey.MatchString(k) {
			continue
		}
		props[k] = property{Type: "string", Title: k, Description: d, Secret: isSecret(k), ServerPath: isServerPath(k), Group: "additional"}
	}
	for k, d := range extraCredentialFields[t.Code] {
		props[k] = property{Type: "string", Title: k, Description: d, Secret: isSecret(k), ServerPath: isServerPath(k), Group: "credentials"}
	}
	for k, p := range props {
		if m := aliasRe.FindStringSubmatch(p.Description); m != nil {
			p.AliasOf = m[1]
			props[k] = p
		}
	}
	s := schema{Schema: "https://json-schema.org/draft/2020-12/schema", Title: t.Name, Type: "object",
		AdditionalProperties: false, Properties: props}
	if reason, ok := unsupportedProviders[t.Code]; ok {
		s.Unsupported, s.UnsupportedReason = true, reason
	} else {
		methods, err := deriveAuthMethods(pkgDir, t, props)
		if err != nil {
			return providerFile{}, err
		}
		if len(methods) == 0 {
			return providerFile{}, fmt.Errorf("%s: no auth methods derived from NewDNSProvider and no authOverrides entry", t.Code)
		}
		s.AuthMethods = methods
	}
	return providerFile{Code: t.Code, Name: t.Name, URL: t.URL, Aliases: t.Aliases, Schema: s}, nil
}

func renderDocs(files []providerFile) []byte {
	var b bytes.Buffer
	b.WriteString("# DNS providers\n\n")
	b.WriteString("Generated by `tools/gen-lego-schemas` from lego's provider metadata. Do not edit by hand.\n\n")
	b.WriteString("Fields marked secret are write-only: the API never returns them, and a PUT with `__unchanged__` keeps the stored value. Fields in the additional group are optional tuning knobs.\n\n")
	b.WriteString("The lego `exec` provider (runs an arbitrary program on the server) and `manual` provider (reads stdin) are not offered here; use verification rule method `manual-dns` instead.\n\n")
	b.WriteString("A field marked `serverPath: true` (usually a name ending `_FILE` or `_PATH`, plus a handful of fields overridden individually where the name doesn't follow that convention) names a path on lego's own host filesystem; the API rejects a value for these with a 422. Most providers with such a field also have an inline field carrying the same material (used instead, written to a private server-side temp file for the provider to read and removed once it has); a provider whose *only* input is that file, with no inline field added for it yet, is marked `unsupported: true` below.\n\n")
	b.WriteString("## File-backed credentials\n\n")
	b.WriteString("transip and hyperone each read their credential from a file on lego's own host filesystem instead of an environment variable's value: `gotransip.NewClient` opens and reads `TRANSIP_PRIVATE_KEY_PATH` (transip), and `internal.LoadPassportFile` reads `HYPERONE_PASSPORT_LOCATION` (hyperone), both eagerly during provider construction. certforge instead accepts the material inline (`TRANSIP_PRIVATE_KEY`, `HYPERONE_PASSPORT`, both secret, listed below under each provider), and writes it to a private, 0600 file inside a fresh 0700 temp directory just before construction, pointing the provider's own path env var at that file; the temp directory is removed as soon as construction returns, whether it succeeded or not. The path env vars themselves are never accepted directly — like any other `serverPath: true` field, a value for one is rejected with a 422.\n\n")
	var unsupported []providerFile
	for _, f := range files {
		if f.Schema.Unsupported {
			unsupported = append(unsupported, f)
		}
	}
	if len(unsupported) > 0 {
		b.WriteString("### Not yet supported\n\n")
		for _, f := range unsupported {
			fmt.Fprintf(&b, "- **%s** (`%s`): %s\n", f.Name, f.Code, f.Schema.UnsupportedReason)
		}
		b.WriteString("\n")
	}
	for _, f := range files {
		fmt.Fprintf(&b, "## %s\n\nCode: `%s`", f.Name, f.Code)
		if len(f.Aliases) > 0 {
			fmt.Fprintf(&b, " (aliases: `%s`)", strings.Join(f.Aliases, "`, `"))
		}
		if f.URL != "" {
			fmt.Fprintf(&b, ". Website: <%s>", f.URL)
		}
		b.WriteString("\n\n")
		if f.Schema.Unsupported {
			fmt.Fprintf(&b, "**Not supported yet:** %s\n\n", f.Schema.UnsupportedReason)
		}
		if len(f.Schema.AuthMethods) > 0 {
			var ms []string
			for _, m := range f.Schema.AuthMethods {
				fs := "no fields"
				if len(m.Fields) > 0 {
					fs = "`" + strings.Join(m.Fields, "`, `") + "`"
				}
				ms = append(ms, fmt.Sprintf("**%s** (%s)", m.Label, fs))
			}
			fmt.Fprintf(&b, "Auth methods (one is required): %s.\n\n", strings.Join(ms, "; "))
		}
		b.WriteString("| Field | Group | Secret | Description |\n|---|---|---|---|\n")
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
			if p.AliasOf != "" {
				desc = fmt.Sprintf("Alias of `%s`", p.AliasOf)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", k, p.Group, secret, desc)
		}
		b.WriteString("\n")
	}
	return b.Bytes()
}
