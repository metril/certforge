package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx"
)

// TypeRouterOS is the MikroTik RouterOS deploy target type: files go up over
// SCP (RouterOS has no POSIX shell), then are imported and bound over REST.
const TypeRouterOS = "routeros"

var roCertNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

// RouterOS 7.x REST details. Items marked VERIFY come from the documentation
// and have not been confirmed against a live router; adjust them here.
const (
	roCerts       = "/rest/certificate"        // GET list; entries carry .id, name, fingerprint, private-key
	roCertImport  = "/rest/certificate/import" // VERIFY: body {"file-name","passphrase"}
	roCertSet     = "/rest/certificate/set"
	roCertRemove  = "/rest/certificate/remove" // VERIFY: id key may need to be "numbers"
	roFileRemove  = "/rest/file/remove"        // VERIFY: removing by file name via "numbers"
	roIPService   = "/rest/ip/service"
	roIPSvcSet    = "/rest/ip/service/set"
	roSSTPSet     = "/rest/interface/sstp-server/server/set" // VERIFY
	roOVPNSet     = "/rest/interface/ovpn-server/server/set" // VERIFY
	roCertIDKey   = ".id"                                    // VERIFY for remove
	roFileIDKey   = "numbers"                                // VERIFY
	roFingerprint = "fingerprint"                            // VERIFY: sha256 hex; colons and case are ignored
	roErrCap      = 200
	roMaxBody     = 1 << 20
)

// RouterOSConfig is a RouterOS target's config; Password is the secret.
type RouterOSConfig struct {
	URL            string   `json:"url"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	SSHPort        int      `json:"sshPort,omitempty"`
	HostKey        string   `json:"hostKey"`
	CertName       string   `json:"certName,omitempty"`
	Services       []string `json:"services"`
	CAPEM          string   `json:"caPem,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
}

const routerOSSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "MikroTik RouterOS",
  "description": "Uploads a certificate and key to RouterOS 7.x over SCP, imports them through the REST API and binds them to services. Runs on the server.",
  "credentialKinds": ["password"],
  "type": "object",
  "additionalProperties": false,
  "required": ["url", "username", "password", "hostKey"],
  "properties": {
    "url": {"type": "string", "format": "uri", "title": "REST URL", "description": "https URL of the router, e.g. https://router.example.net. The REST API is served by www-ssl."},
    "username": {"type": "string", "title": "Username", "description": "RouterOS user allowed to use SSH, REST and manage certificates."},
    "password": {"type": "string", "secret": true, "title": "Password", "description": "Used for both REST and SSH."},
    "sshPort": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 22, "title": "SSH port"},
    "hostKey": {"type": "string", "title": "SSH host key", "description": "The router's SSH public key, e.g. from ssh-keyscan -t ed25519."},
    "certName": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,40}$", "default": "certforge", "title": "Certificate name prefix", "description": "Certificates are named <prefix>-<fingerprint>; older ones with this prefix are removed."},
    "services": {"type": "array", "uniqueItems": true, "items": {"type": "string", "enum": ["www-ssl", "api-ssl", "sstp", "ovpn"]}, "default": ["www-ssl", "api-ssl"], "title": "Services", "description": "Where to bind the certificate."},
    "caPem": {"type": "string", "title": "CA certificate", "description": "PEM certificate(s) to trust for the router's REST TLS certificate, in addition to the system roots."},
    "timeoutSeconds": {"type": "integer", "minimum": 10, "maximum": 300, "default": 90, "title": "Timeout (seconds)"}
  }
}`

// RouterOS is the RouterOS server-run deploy target. Implements targets.Target.
type RouterOS struct{}

// Type implements targets.Target.
func (RouterOS) Type() string { return TypeRouterOS }

// Name implements targets.Target.
func (RouterOS) Name() string { return "MikroTik RouterOS" }

// Schema implements targets.Target.
func (RouterOS) Schema() json.RawMessage { return json.RawMessage(routerOSSchema) }

// RunsOn implements targets.Target: always Server.
func (RouterOS) RunsOn() targets.Mode { return targets.Server }

// KeyPolicy implements targets.Target: always needs the key.
func (RouterOS) KeyPolicy() targets.KeyPolicy { return targets.Always }

// Parse implements targets.Target.
func (t RouterOS) Parse(raw json.RawMessage) (targets.Config, error) {
	var c RouterOSConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return targets.Config{}, &delivery.FieldError{Field: "config", Msg: err.Error()}
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return targets.Config{}, &delivery.FieldError{Field: "config.url", Msg: "must be an https URL without credentials, query or fragment"}
	}
	c.URL = strings.TrimRight(c.URL, "/")
	if c.Username == "" {
		return targets.Config{}, &delivery.FieldError{Field: "config.username", Msg: "required"}
	}
	if c.Password == "" {
		return targets.Config{}, &delivery.FieldError{Field: "config.password", Msg: "required"}
	}
	if c.SSHPort == 0 {
		c.SSHPort = 22
	}
	if c.SSHPort < 1 || c.SSHPort > 65535 {
		return targets.Config{}, &delivery.FieldError{Field: "config.sshPort", Msg: "must be between 1 and 65535"}
	}
	if _, err := sshx.ParseHostKey(c.HostKey); err != nil {
		return targets.Config{}, &delivery.FieldError{Field: "config.hostKey", Msg: "must be a valid SSH public key (e.g. from ssh-keyscan -t ed25519)"}
	}
	if c.CertName == "" {
		c.CertName = "certforge"
	}
	if !roCertNameRe.MatchString(c.CertName) {
		return targets.Config{}, &delivery.FieldError{Field: "config.certName", Msg: "must match ^[A-Za-z0-9_-]{1,40}$"}
	}
	if c.Services == nil {
		c.Services = []string{"www-ssl", "api-ssl"}
	}
	seen := map[string]bool{}
	for _, s := range c.Services {
		switch s {
		case "www-ssl", "api-ssl", "sstp", "ovpn":
		default:
			return targets.Config{}, &delivery.FieldError{Field: "config.services", Msg: "must be www-ssl, api-ssl, sstp or ovpn"}
		}
		if seen[s] {
			return targets.Config{}, &delivery.FieldError{Field: "config.services", Msg: "duplicate " + s}
		}
		seen[s] = true
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 90
	}
	if c.TimeoutSeconds < 10 || c.TimeoutSeconds > 300 {
		return targets.Config{}, &delivery.FieldError{Field: "config.timeoutSeconds", Msg: "must be between 10 and 300"}
	}
	canon, err := json.Marshal(c)
	if err != nil {
		return targets.Config{}, err
	}
	pub, secrets, err := targets.Split(t.Schema(), canon)
	if err != nil {
		return targets.Config{}, err
	}
	ssh := "ssh://" + net.JoinHostPort(u.Hostname(), strconv.Itoa(c.SSHPort))
	return targets.Config{Public: pub, Secrets: secrets, NeedsKey: true, URLs: []string{c.URL, ssh}}, nil
}

type roCert struct {
	ID, Name, FP string
	HasKey       bool
}

func roNormFP(s string) string { return strings.ToLower(strings.ReplaceAll(s, ":", "")) }

// Deploy implements targets.Target.
func (RouterOS) Deploy(ctx context.Context, req targets.Request) (targets.Result, error) {
	var cfg RouterOSConfig
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return targets.Result{}, err
	}
	secrets := map[string]string{"password": cfg.Password}
	fail := func(err error) (targets.Result, error) {
		return targets.Result{}, errors.New("deploy: routeros: " + targets.Redact(err, secrets, 500))
	}
	if req.Material == nil {
		return targets.Result{}, errors.New("deploy: routeros: no certificate material")
	}
	mat, err := delivery.TargetMaterial(*req.Material)
	if err != nil {
		return targets.Result{}, err
	}
	if _, err := sshx.ParseHostKey(cfg.HostKey); err != nil {
		return fail(err)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Hostname() == "" {
		return fail(errors.New("invalid url"))
	}
	if cfg.CertName == "" {
		cfg.CertName = "certforge"
	}
	if cfg.Services == nil {
		cfg.Services = []string{"www-ssl", "api-ssl"}
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if cfg.TimeoutSeconds == 0 {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sum := sha256.Sum256(req.Material.LeafDER)
	fp := hex.EncodeToString(sum[:])
	fp8 := fp[:8]
	newName := cfg.CertName + "-" + fp8
	files := []string{"cf-" + fp8 + ".crt", "cf-" + fp8 + ".key"}

	client, err := req.HTTP.New(httpx.Options{CAPEM: cfg.CAPEM, Timeout: timeout, MaxBody: roMaxBody})
	if err != nil {
		return fail(err)
	}
	base := strings.TrimRight(cfg.URL, "/")
	callCtx := func(ctx context.Context, method, path string, body any) ([]byte, error) {
		full := base + path
		if err := httpx.CheckURL(full, req.HTTP.AllowLoopback); err != nil {
			return nil, err
		}
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		hr, err := http.NewRequestWithContext(ctx, method, full, rd)
		if err != nil {
			return nil, err
		}
		hr.SetBasicAuth(cfg.Username, cfg.Password)
		hr.Header.Set("Accept", "application/json")
		if body != nil {
			hr.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.HTTPClient().Do(hr)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, roMaxBody))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			snippet := b
			if len(snippet) > roErrCap {
				snippet = snippet[:roErrCap]
			}
			return nil, fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return ' '
				}
				return r
			}, string(snippet)))
		}
		return b, nil
	}
	call := func(method, path string, body any) ([]byte, error) {
		return callCtx(ctx, method, path, body)
	}
	list := func() ([]roCert, error) {
		b, err := call(http.MethodGet, roCerts, nil)
		if err != nil {
			return nil, err
		}
		var raw []map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, fmt.Errorf("decoding certificate list: %w", err)
		}
		var out []roCert
		for _, m := range raw {
			c := roCert{}
			c.ID, _ = m[".id"].(string)
			c.Name, _ = m["name"].(string)
			if s, _ := m[roFingerprint].(string); s != "" {
				c.FP = roNormFP(s)
			}
			switch v := m["private-key"].(type) {
			case string:
				c.HasKey = v == "true"
			case bool:
				c.HasKey = v
			}
			if c.ID != "" {
				out = append(out, c)
			}
		}
		return out, nil
	}
	find := func(all []roCert) *roCert {
		for i := range all {
			if all[i].FP == fp {
				return &all[i]
			}
		}
		return nil
	}

	all, err := list()
	if err != nil {
		return fail(err)
	}
	cur := find(all)
	verb := "unchanged"
	var warns []string
	if cur == nil {
		verb = "imported"
		cl, err := sshx.Dial(ctx, sshx.Opts{Host: u.Hostname(), Port: cfg.SSHPort, User: cfg.Username, Password: cfg.Password,
			HostKey: cfg.HostKey, AllowLoopback: req.HTTP.AllowLoopback, Timeout: timeout})
		if err != nil {
			return fail(err)
		}
		defer func() { _ = cl.Close() }()
		uploaded := true
		cleaned := false
		removeFiles := func() {
			rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer rcancel()
			for _, f := range files {
				if _, err := callCtx(rctx, http.MethodPost, roFileRemove, map[string]string{roFileIDKey: f}); err != nil {
					warns = append(warns, "remove file "+f+": "+err.Error())
				}
			}
		}
		defer func() {
			if uploaded && !cleaned {
				removeFiles()
			}
		}()
		if err := cl.WriteFileSCP(ctx, files[0], mat.Fullchain, os.FileMode(0o644)); err != nil {
			return fail(fmt.Errorf("upload %s: %w", files[0], err))
		}
		if err := cl.WriteFileSCP(ctx, files[1], mat.Key, os.FileMode(0o600)); err != nil {
			return fail(fmt.Errorf("upload %s: %w", files[1], err))
		}
		for _, f := range files {
			if _, err := call(http.MethodPost, roCertImport, map[string]string{"file-name": f, "passphrase": ""}); err != nil {
				return fail(fmt.Errorf("import %s: %w", f, err))
			}
		}
		if all, err = list(); err != nil {
			return fail(err)
		}
		if cur = find(all); cur == nil {
			return fail(errors.New("imported certificate not found by fingerprint"))
		}
		if !cur.HasKey {
			return fail(errors.New("imported certificate has no private key"))
		}
		cleaned = true
		removeFiles()
	} else if !cur.HasKey {
		return fail(errors.New("existing certificate has no private key"))
	}
	if cur.Name != newName {
		if _, err := call(http.MethodPost, roCertSet, map[string]string{".id": cur.ID, "name": newName}); err != nil {
			return fail(fmt.Errorf("rename certificate: %w", err))
		}
	}

	var svcs []struct {
		ID   string `json:".id"`
		Name string `json:"name"`
	}
	for _, s := range cfg.Services {
		if s != "www-ssl" && s != "api-ssl" || svcs != nil {
			continue
		}
		b, err := call(http.MethodGet, roIPService, nil)
		if err != nil {
			return fail(err)
		}
		if err := json.Unmarshal(b, &svcs); err != nil {
			return fail(fmt.Errorf("decoding service list: %w", err))
		}
	}
	for _, s := range cfg.Services {
		var err error
		switch s {
		case "www-ssl", "api-ssl":
			id := ""
			for _, v := range svcs {
				if v.Name == s {
					id = v.ID
				}
			}
			if id == "" {
				return fail(fmt.Errorf("service %s not found", s))
			}
			_, err = call(http.MethodPost, roIPSvcSet, map[string]string{".id": id, "certificate": newName})
		case "sstp":
			_, err = call(http.MethodPost, roSSTPSet, map[string]string{"certificate": newName})
		case "ovpn":
			_, err = call(http.MethodPost, roOVPNSet, map[string]string{"certificate": newName})
		}
		if err != nil {
			return fail(fmt.Errorf("bind %s: %w", s, err))
		}
	}

	oldRe := regexp.MustCompile("^" + regexp.QuoteMeta(cfg.CertName) + "-[0-9a-f]{8}$")
	removed := 0
	for _, c := range all {
		if c.ID == cur.ID || !oldRe.MatchString(c.Name) {
			continue
		}
		if _, err := call(http.MethodPost, roCertRemove, map[string]string{roCertIDKey: c.ID}); err != nil {
			warns = append(warns, "remove "+c.Name+": "+err.Error())
			continue
		}
		removed++
	}
	bound := "none"
	if len(cfg.Services) > 0 {
		bound = strings.Join(cfg.Services, ", ")
	}
	detail := fmt.Sprintf("certificate %s %s; bound: %s; %d old removed", newName, verb, bound, removed)
	if len(warns) > 0 {
		detail += "; warnings: " + targets.Redact(errors.New(strings.Join(warns, "; ")), secrets, 400)
	}
	return targets.Result{Detail: detail}, nil
}
