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
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/targets"
)

// TypeAuthentik is the authentik deploy target type: a server-run target
// that pushes a certificate and key into Authentik's certificate-keypair
// store.
const TypeAuthentik = "authentik"

var authentikNameRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{0,120}$`)

const (
	authentikKeypairs = "/api/v3/crypto/certificatekeypairs/"
	authentikErrCap   = 200
)

// AuthentikConfig is an authentik target's config; Token is the secret.
type AuthentikConfig struct {
	URL            string `json:"url"`
	Token          string `json:"token"`
	Name           string `json:"name,omitempty"`
	CAPEM          string `json:"caPem,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
}

const authentikSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Authentik",
  "description": "Pushes a certificate and its private key into Authentik's certificate-keypair store. Runs on the server.",
  "credentialKinds": ["token"],
  "type": "object",
  "additionalProperties": false,
  "required": ["url", "token"],
  "properties": {
    "url": {"type": "string", "format": "uri", "title": "URL", "description": "https URL of the Authentik instance."},
    "token": {"type": "string", "secret": true, "title": "API token", "description": "Authentik API token allowed to view, add and change certificate-key pairs."},
    "name": {"type": "string", "pattern": "^[A-Za-z0-9 ._-]{0,120}$", "default": "", "title": "Keypair name", "description": "Name of the keypair in Authentik. Empty uses the certificate's name."},
    "caPem": {"type": "string", "format": "pem-bundle", "title": "CA certificate", "description": "PEM certificate(s) to trust for Authentik's TLS certificate, in addition to the system roots."},
    "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 120, "default": 30, "title": "Timeout (seconds)"}
  }
}`

// Authentik is the "authentik" server-run deploy target. Implements
// targets.Target.
type Authentik struct{}

// Type implements targets.Target.
func (Authentik) Type() string { return TypeAuthentik }

// Name implements targets.Target.
func (Authentik) Name() string { return "Authentik" }

// Schema implements targets.Target.
func (Authentik) Schema() json.RawMessage { return json.RawMessage(authentikSchema) }

// RunsOn implements targets.Target: always Server.
func (Authentik) RunsOn() targets.Mode { return targets.Server }

// KeyPolicy implements targets.Target: always needs the key.
func (Authentik) KeyPolicy() targets.KeyPolicy { return targets.Always }

// Parse implements targets.Target.
func (t Authentik) Parse(raw json.RawMessage) (targets.Config, error) {
	var c AuthentikConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return targets.Config{}, &delivery.FieldError{Field: "config", Msg: err.Error()}
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return targets.Config{}, &delivery.FieldError{Field: "config.url", Msg: "must be an https URL without credentials, query or fragment"}
	}
	c.URL = strings.TrimRight(c.URL, "/")
	if c.Token == "" {
		return targets.Config{}, &delivery.FieldError{Field: "config.token", Msg: "required"}
	}
	if !authentikNameRe.MatchString(c.Name) {
		return targets.Config{}, &delivery.FieldError{Field: "config.name", Msg: "must match ^[A-Za-z0-9 ._-]{0,120}$"}
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 30
	}
	if c.TimeoutSeconds < 5 || c.TimeoutSeconds > 120 {
		return targets.Config{}, &delivery.FieldError{Field: "config.timeoutSeconds", Msg: "must be between 5 and 120"}
	}
	if ca, err := httpx.NormalizeCABundle(c.CAPEM); err != nil {
		return targets.Config{}, &delivery.FieldError{Field: "config.caPem", Msg: err.Error()}
	} else {
		c.CAPEM = ca
	}
	canon, err := json.Marshal(c)
	if err != nil {
		return targets.Config{}, err
	}
	pub, secrets, err := targets.Split(t.Schema(), canon)
	if err != nil {
		return targets.Config{}, err
	}
	return targets.Config{Public: pub, Secrets: secrets, NeedsKey: true, URLs: []string{c.URL}}, nil
}

type akKeypair struct {
	PK          string `json:"pk"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint_sha256"`
}

// Deploy implements targets.Target: updates the keypair named cfg.Name (or
// the certificate's name) in place, or creates it.
func (Authentik) Deploy(ctx context.Context, req targets.Request) (targets.Result, error) {
	var cfg AuthentikConfig
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return targets.Result{}, err
	}
	secrets := map[string]string{"token": cfg.Token}
	fail := func(err error) (targets.Result, error) {
		return targets.Result{}, errors.New("deploy: authentik: " + targets.Redact(err, secrets, 500))
	}
	if req.Material == nil {
		return targets.Result{}, errors.New("deploy: authentik: no certificate material")
	}
	mat, err := delivery.TargetMaterial(*req.Material)
	if err != nil {
		return targets.Result{}, err
	}
	name := cfg.Name
	if name == "" {
		name = req.CertName
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if cfg.TimeoutSeconds == 0 {
		timeout = 30 * time.Second
	}
	client, err := req.HTTP.New(httpx.Options{CAPEM: cfg.CAPEM, Timeout: timeout, MaxBody: 1 << 20})
	if err != nil {
		return fail(err)
	}
	base := strings.TrimRight(cfg.URL, "/")
	call := func(method, u string, body any) ([]byte, error) {
		if err := httpx.CheckURL(u, req.HTTP.AllowLoopback); err != nil {
			return nil, err
		}
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		hr, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return nil, err
		}
		hr.Header.Set("Authorization", "Bearer "+cfg.Token)
		hr.Header.Set("Accept", "application/json")
		if body != nil {
			hr.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.HTTPClient().Do(hr)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			snippet := b
			if len(snippet) > authentikErrCap {
				snippet = snippet[:authentikErrCap]
			}
			return nil, fmt.Errorf("%s: status %d: %s", method, resp.StatusCode, strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return ' '
				}
				return r
			}, string(snippet)))
		}
		return b, nil
	}

	b, err := call(http.MethodGet, base+authentikKeypairs+"?"+url.Values{"name": {name}, "page_size": {"2"}}.Encode(), nil)
	if err != nil {
		return fail(err)
	}
	var list struct {
		Results []akKeypair `json:"results"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return fail(fmt.Errorf("decoding keypair list: %w", err))
	}
	var match []akKeypair
	for _, k := range list.Results {
		if k.Name == name {
			match = append(match, k)
		}
	}
	if len(match) > 1 {
		return fail(fmt.Errorf("%d keypairs are named %q; remove the duplicates in Authentik", len(match), name))
	}
	body := map[string]string{"name": name, "certificate_data": string(mat.Fullchain), "key_data": string(mat.Key)}
	if len(match) == 1 {
		k := match[0]
		sum := sha256.Sum256(req.Material.LeafDER)
		if k.Fingerprint != "" && strings.EqualFold(strings.ReplaceAll(k.Fingerprint, ":", ""), hex.EncodeToString(sum[:])) {
			return targets.Result{Detail: "unchanged"}, nil
		}
		if _, err := call(http.MethodPatch, base+authentikKeypairs+url.PathEscape(k.PK)+"/", body); err != nil {
			return fail(err)
		}
		return targets.Result{Detail: fmt.Sprintf("keypair %s updated", k.PK)}, nil
	}
	b, err = call(http.MethodPost, base+authentikKeypairs, body)
	if err != nil {
		return fail(err)
	}
	var created akKeypair
	if err := json.Unmarshal(b, &created); err != nil || created.PK == "" {
		return fail(errors.New("create response has no pk"))
	}
	return targets.Result{Detail: fmt.Sprintf("keypair %s created", created.PK)}, nil
}
