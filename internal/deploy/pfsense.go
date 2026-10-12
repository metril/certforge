package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/targets"
)

// TypePfSense is the pfSense Plus deploy target type: a server-run target
// that pushes a certificate into pfSense via Netgate's REST API.
const TypePfSense = "pfsense"

var pfNameRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{0,64}$`)

// Paths relative to the configured URL (the Nexus API base, e.g. .../api).
// System paths are served under /device/pfsense/{id}/api when Nexus manages
// the firewall. Keep every path here.
const (
	pfLogin   = "/login"
	pfDevices = "/mim/devices"
	pfCerts   = "/system/certificates"
	pfAdmin   = "/system/advanced/admin"
	pfErrCap  = 200
	pfMaxBody = 1 << 20
)

// PfSenseConfig is a pfsense target's config; Password is the secret.
type PfSenseConfig struct {
	URL            string `json:"url"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Device         string `json:"device,omitempty"`
	CertName       string `json:"certName,omitempty"`
	SetWebGuiCert  bool   `json:"setWebGuiCert,omitempty"`
	CAPEM          string `json:"caPem,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
}

const pfSenseSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "pfSense Plus",
  "description": "Pushes a certificate and its private key into pfSense Plus (25.03+) through the Netgate Nexus REST API, updating an existing certificate entry in place. Runs on the server.",
  "credentialKinds": ["password"],
  "type": "object",
  "additionalProperties": false,
  "required": ["url", "username", "password"],
  "properties": {
    "url": {"type": "string", "format": "uri", "title": "API URL", "description": "https URL of the Nexus API, e.g. https://fw.example.net:8443/api."},
    "username": {"type": "string", "title": "Username", "description": "pfSense user allowed to manage certificates."},
    "password": {"type": "string", "secret": true, "title": "Password"},
    "device": {"type": "string", "default": "", "title": "Device", "description": "Name, alias or ID of the firewall in Nexus. Empty uses the only managed device."},
    "certName": {"type": "string", "pattern": "^[A-Za-z0-9 ._-]{0,64}$", "default": "", "title": "Certificate name", "description": "Description of the certificate in pfSense. Empty uses the certificate's name."},
    "setWebGuiCert": {"type": "boolean", "default": false, "title": "Use for the WebGUI", "description": "Also select this certificate for the pfSense web interface."},
    "caPem": {"type": "string", "format": "pem-bundle", "title": "CA certificate", "description": "PEM certificate(s) to trust for pfSense's TLS certificate, in addition to the system roots."},
    "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 120, "default": 30, "title": "Timeout (seconds)"}
  }
}`

// PfSense is the "pfsense" server-run deploy target. Implements targets.Target.
type PfSense struct{}

// Type implements targets.Target.
func (PfSense) Type() string { return TypePfSense }

// Name implements targets.Target.
func (PfSense) Name() string { return "pfSense Plus" }

// Schema implements targets.Target.
func (PfSense) Schema() json.RawMessage { return json.RawMessage(pfSenseSchema) }

// RunsOn implements targets.Target: always Server.
func (PfSense) RunsOn() targets.Mode { return targets.Server }

// KeyPolicy implements targets.Target: always needs the key.
func (PfSense) KeyPolicy() targets.KeyPolicy { return targets.Always }

// Parse implements targets.Target.
func (t PfSense) Parse(raw json.RawMessage) (targets.Config, error) {
	var c PfSenseConfig
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
	if c.Username == "" {
		return targets.Config{}, &delivery.FieldError{Field: "config.username", Msg: "required"}
	}
	if c.Password == "" {
		return targets.Config{}, &delivery.FieldError{Field: "config.password", Msg: "required"}
	}
	if !pfNameRe.MatchString(c.CertName) {
		return targets.Config{}, &delivery.FieldError{Field: "config.certName", Msg: "must match ^[A-Za-z0-9 ._-]{0,64}$"}
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 30
	}
	if c.TimeoutSeconds < 5 || c.TimeoutSeconds > 120 {
		return targets.Config{}, &delivery.FieldError{Field: "config.timeoutSeconds", Msg: "must be between 5 and 120"}
	}
	ca, err := httpx.NormalizeCABundle(c.CAPEM)
	if err != nil {
		return targets.Config{}, &delivery.FieldError{Field: "config.caPem", Msg: err.Error()}
	}
	c.CAPEM = ca
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

// pfEntry is one certificate found in the list response.
type pfEntry struct {
	Refid, Label string
	Same         bool // exposes a PEM or fingerprint equal to ours
}

// pfScan walks the list response tolerantly: every JSON object holding a
// string "refid" is an entry. This is the only place that knows the shape.
func pfScan(v any, leafDER []byte, out *[]pfEntry) {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			pfScan(e, leafDER, out)
		}
	case map[string]any:
		if ref, ok := x["refid"].(string); ok && ref != "" {
			label, _ := x["descr"].(string)
			if label == "" {
				label, _ = x["name"].(string)
			}
			*out = append(*out, pfEntry{Refid: ref, Label: label, Same: pfSame(x, leafDER)})
			return
		}
		for _, e := range x {
			pfScan(e, leafDER, out)
		}
	}
}

func pfSame(x map[string]any, leafDER []byte) bool {
	sum := sha256.Sum256(leafDER)
	fp := hex.EncodeToString(sum[:])
	b64 := base64.StdEncoding.EncodeToString(leafDER)
	if info, ok := x["info"].(map[string]any); ok {
		if f, _ := info["cert_fingerprint"].(string); f != "" && strings.EqualFold(strings.ReplaceAll(f, ":", ""), fp) {
			return true
		}
	}
	for k, v := range x {
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		lk := strings.ToLower(k)
		if strings.Contains(lk, "fingerprint") {
			if strings.EqualFold(strings.ReplaceAll(s, ":", ""), fp) {
				return true
			}
			continue
		}
		if lk != "crt" && lk != "cert" && lk != "certificate" {
			continue
		}
		if d, err := base64.StdEncoding.DecodeString(s); err == nil {
			s = string(d) // pfSense stores PEM base64-encoded
		}
		if strings.Contains(strings.Join(strings.Fields(s), ""), b64) {
			return true
		}
	}
	return false
}

// Deploy implements targets.Target: login, find or create the certificate,
// optionally select it for the WebGUI.
func (PfSense) Deploy(ctx context.Context, req targets.Request) (targets.Result, error) {
	var cfg PfSenseConfig
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return targets.Result{}, err
	}
	secrets := map[string]string{"password": cfg.Password}
	fail := func(err error) (targets.Result, error) {
		return targets.Result{}, errors.New("deploy: pfsense: " + targets.Redact(err, secrets, 500))
	}
	if req.Material == nil {
		return targets.Result{}, errors.New("deploy: pfsense: no certificate material")
	}
	mat, err := delivery.TargetMaterial(*req.Material)
	if err != nil {
		return targets.Result{}, err
	}
	name := cfg.CertName
	if name == "" {
		name = req.CertName
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if cfg.TimeoutSeconds == 0 {
		timeout = 30 * time.Second
	}
	client, err := req.HTTP.New(httpx.Options{CAPEM: cfg.CAPEM, Timeout: timeout, MaxBody: pfMaxBody})
	if err != nil {
		return fail(err)
	}
	if client.HTTPClient().Jar == nil { // login sets a refresh cookie
		jar, _ := cookiejar.New(nil)
		client.HTTPClient().Jar = jar
	}
	base := strings.TrimRight(cfg.URL, "/")
	token := ""
	call := func(method, path string, body any) ([]byte, error) {
		u := base + path
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
		if token != "" {
			hr.Header.Set("Authorization", "Bearer "+token)
		}
		hr.Header.Set("Accept", "application/json")
		if body != nil {
			hr.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.HTTPClient().Do(hr)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, pfMaxBody))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			snippet := b
			if len(snippet) > pfErrCap {
				snippet = snippet[:pfErrCap]
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

	b, err := call(http.MethodPost, pfLogin, map[string]string{
		"username": base64.StdEncoding.EncodeToString([]byte(cfg.Username)),
		"password": base64.StdEncoding.EncodeToString([]byte(cfg.Password))})
	if err != nil {
		return fail(err)
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &login); err != nil || login.Token == "" {
		return fail(errors.New("login response has no token"))
	}
	token = login.Token
	secrets["token"] = token

	b, err = call(http.MethodGet, pfDevices, nil)
	if err != nil {
		return fail(err)
	}
	prefix, err := pfPickDevice(b, cfg.Device)
	if err != nil {
		return fail(err)
	}
	certs, admin := prefix+pfCerts, prefix+pfAdmin

	b, err = call(http.MethodGet, certs, nil)
	if err != nil {
		return fail(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return fail(fmt.Errorf("decoding certificate list: %w", err))
	}
	var all, match []pfEntry
	pfScan(doc, req.Material.LeafDER, &all)
	for _, e := range all {
		if e.Label == name {
			match = append(match, e)
		}
	}
	if len(match) > 1 {
		return fail(fmt.Errorf("%d certificates are named %q; remove the duplicates in pfSense", len(match), name))
	}
	body := map[string]any{"name": name, "descr": name, "method_existing_pem": map[string]string{
		"cert": string(mat.Fullchain), "private_key": string(mat.Key)}}
	var refid, verb string
	if len(match) == 1 {
		refid = match[0].Refid
		verb = "updated"
		if match[0].Same {
			verb = "unchanged"
		} else if _, err := call(http.MethodPost, certs+"/"+url.PathEscape(refid), body); err != nil {
			return fail(err)
		}
	} else {
		b, err = call(http.MethodPut, certs, body)
		if err != nil {
			return fail(err)
		}
		var cdoc any
		_ = json.Unmarshal(b, &cdoc)
		var made []pfEntry
		pfScan(cdoc, req.Material.LeafDER, &made)
		var created pfEntry
		if len(made) > 0 {
			created = made[0]
		}
		if created.Refid == "" {
			return fail(errors.New("create response has no refid"))
		}
		refid, verb = created.Refid, "created"
	}
	detail := fmt.Sprintf("certificate %s %s", refid, verb)

	if cfg.SetWebGuiCert {
		b, err := call(http.MethodGet, admin, nil)
		if err != nil {
			return fail(err)
		}
		var obj map[string]any
		if err := json.Unmarshal(b, &obj); err != nil {
			return fail(fmt.Errorf("decoding webgui settings: %w", err))
		}
		// SystemAdvAdminSetting is {"admin": {..., "ssl_certref": "..."}}.
		adm, ok := obj["admin"].(map[string]any)
		if !ok {
			return fail(errors.New("webgui settings have no admin object"))
		}
		if cur, _ := adm["ssl_certref"].(string); cur != refid {
			adm["ssl_certref"] = refid
			if _, err := call(http.MethodPost, admin, obj); err != nil {
				return fail(err)
			}
			detail += ", webgui cert set"
		}
	}
	return targets.Result{Detail: detail}, nil
}

// pfPickDevice resolves the Nexus device to manage from a GET /mim/devices
// body and returns the path prefix for its system endpoints.
func pfPickDevice(body []byte, want string) (string, error) {
	var doc struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
			Name     string `json:"name"`
			Alias    string `json:"alias"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("decoding device list: %w", err)
	}
	if len(doc.Devices) == 0 {
		// Unverified: assume the firewall serving the API manages itself and
		// exposes the system endpoints directly under the base URL.
		return "", nil
	}
	prefix := func(id string) string { return "/device/pfsense/" + url.PathEscape(id) + "/api" }
	if want == "" {
		if len(doc.Devices) == 1 {
			return prefix(doc.Devices[0].DeviceID), nil
		}
		var names []string
		for _, d := range doc.Devices {
			names = append(names, d.Name)
		}
		return "", fmt.Errorf("the Nexus controller manages %d devices (%s); set Device to one of them", len(names), strings.Join(names, ", "))
	}
	for _, d := range doc.Devices {
		if strings.EqualFold(d.Name, want) || strings.EqualFold(d.Alias, want) || strings.EqualFold(d.DeviceID, want) {
			return prefix(d.DeviceID), nil
		}
	}
	return "", fmt.Errorf("no Nexus device matches %q", want)
}
