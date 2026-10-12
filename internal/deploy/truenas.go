package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/targets"
)

// TypeTrueNAS is the TrueNAS SCALE deploy target type: a server-run target
// that imports a certificate over the JSON-RPC WebSocket API.
const TypeTrueNAS = "truenas"

var truenasPrefixRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

const truenasErrCap = 200

// TrueNASConfig is a truenas target's config; APIKey is the secret.
type TrueNASConfig struct {
	URL            string `json:"url"`
	Username       string `json:"username,omitempty"`
	APIKey         string `json:"apiKey"`
	CertPrefix     string `json:"certPrefix,omitempty"`
	SetUICert      *bool  `json:"setUiCert,omitempty"`
	CAPEM          string `json:"caPem,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
}

const truenasSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TrueNAS SCALE",
  "description": "Imports a certificate into TrueNAS SCALE 25.10+ over its API and optionally makes it the web UI certificate. Runs on the server.",
  "credentialKinds": ["apiKey"],
  "type": "object",
  "additionalProperties": false,
  "required": ["url", "apiKey"],
  "properties": {
    "url": {"type": "string", "format": "uri", "title": "URL", "description": "https URL of the TrueNAS web UI."},
    "username": {"type": "string", "default": "root", "title": "Username", "description": "User the API key belongs to."},
    "apiKey": {"type": "string", "secret": true, "title": "API key", "description": "TrueNAS API key allowed to manage certificates and system settings."},
    "certPrefix": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,40}$", "default": "certforge", "title": "Certificate name prefix", "description": "Imported certificates are named <prefix>-<fingerprint>; older ones with this prefix are removed."},
    "setUiCert": {"type": "boolean", "default": true, "title": "Use as web UI certificate", "description": "Make the imported certificate the UI certificate and restart the UI."},
    "caPem": {"type": "string", "format": "pem-bundle", "title": "CA certificate", "description": "PEM certificate(s) to trust for TrueNAS's TLS certificate, in addition to the system roots."},
    "timeoutSeconds": {"type": "integer", "minimum": 10, "maximum": 300, "default": 120, "title": "Timeout (seconds)"}
  }
}`

// TrueNAS is the "truenas" server-run deploy target. Implements
// targets.Target.
type TrueNAS struct{}

// Type implements targets.Target.
func (TrueNAS) Type() string { return TypeTrueNAS }

// Name implements targets.Target.
func (TrueNAS) Name() string { return "TrueNAS SCALE" }

// Schema implements targets.Target.
func (TrueNAS) Schema() json.RawMessage { return json.RawMessage(truenasSchema) }

// RunsOn implements targets.Target: always Server.
func (TrueNAS) RunsOn() targets.Mode { return targets.Server }

// KeyPolicy implements targets.Target: always needs the key.
func (TrueNAS) KeyPolicy() targets.KeyPolicy { return targets.Always }

// Parse implements targets.Target.
func (t TrueNAS) Parse(raw json.RawMessage) (targets.Config, error) {
	var c TrueNASConfig
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
		c.Username = "root"
	}
	if c.APIKey == "" {
		return targets.Config{}, &delivery.FieldError{Field: "config.apiKey", Msg: "required"}
	}
	if c.CertPrefix == "" {
		c.CertPrefix = "certforge"
	}
	if !truenasPrefixRe.MatchString(c.CertPrefix) {
		return targets.Config{}, &delivery.FieldError{Field: "config.certPrefix", Msg: "must match ^[A-Za-z0-9_-]{1,40}$"}
	}
	if c.SetUICert == nil {
		on := true
		c.SetUICert = &on
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 120
	}
	if c.TimeoutSeconds < 10 || c.TimeoutSeconds > 300 {
		return targets.Config{}, &delivery.FieldError{Field: "config.timeoutSeconds", Msg: "must be between 10 and 300"}
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

type tnCert struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
}

// leafMatches reports whether the PEM chain's first certificate is der.
func leafMatches(chainPEM string, der []byte) bool {
	blk, _ := pem.Decode([]byte(chainPEM))
	return blk != nil && blk.Type == "CERTIFICATE" && bytes.Equal(blk.Bytes, der)
}

// Deploy implements targets.Target.
func (TrueNAS) Deploy(ctx context.Context, req targets.Request) (targets.Result, error) {
	var cfg TrueNASConfig
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return targets.Result{}, err
	}
	secrets := map[string]string{"apiKey": cfg.APIKey}
	fail := func(err error) (targets.Result, error) {
		return targets.Result{}, errors.New("deploy: truenas: " + oneLine(targets.Redact(err, secrets, 500), 500))
	}
	if req.Material == nil {
		return targets.Result{}, errors.New("deploy: truenas: no certificate material")
	}
	mat, err := delivery.TargetMaterial(*req.Material)
	if err != nil {
		return targets.Result{}, err
	}
	username, prefix, setUI := cfg.Username, cfg.CertPrefix, cfg.SetUICert == nil || *cfg.SetUICert
	if username == "" {
		username = "root"
	}
	if prefix == "" {
		prefix = "certforge"
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if cfg.TimeoutSeconds == 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	wsURL, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil || wsURL.Scheme != "https" {
		return fail(errors.New("url must be https"))
	}
	wsURL.Scheme = "wss"
	wsURL.Path = truenasEndpoint
	opts, err := req.HTTP.WebSocket(httpx.Options{CAPEM: cfg.CAPEM, Timeout: timeout, MaxBody: 1 << 20})
	if err != nil {
		return fail(err)
	}
	conn, err := tnDial(ctx, wsURL.String(), opts)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = conn.CloseNow() }()
	rc := newRPCClient(conn)

	if err := tnLogin(ctx, rc, username, cfg.APIKey); err != nil {
		return fail(err)
	}

	sum := sha256.Sum256(req.Material.LeafDER)
	name := prefix + "-" + hex.EncodeToString(sum[:])[:8]

	raw, err := rc.call(ctx, "certificate.query", []any{[]any{[]any{"name", "^", prefix}}})
	if err != nil {
		return fail(fmt.Errorf("listing certificates: %w", err))
	}
	var existing []tnCert
	if err := json.Unmarshal(raw, &existing); err != nil {
		return fail(fmt.Errorf("decoding certificate list: %w", err))
	}
	ours := regexp.MustCompile("^" + regexp.QuoteMeta(prefix) + "-[0-9a-f]{8}$")
	kept := existing[:0]
	for _, e := range existing {
		if ours.MatchString(e.Name) {
			kept = append(kept, e)
		}
	}
	existing = kept
	id, imported := 0, false
	for _, e := range existing {
		if e.Name == name || leafMatches(e.Certificate, req.Material.LeafDER) {
			id = e.ID
			break
		}
	}
	if id == 0 {
		res, err := tnJob(ctx, rc, "certificate.create", []any{map[string]any{
			"name": name, "create_type": truenasCreateType,
			"certificate": string(mat.Fullchain), "privatekey": string(mat.Key),
		}})
		if err != nil {
			return fail(fmt.Errorf("importing certificate: %w", err))
		}
		var ce tnCert
		if err := json.Unmarshal(res, &ce); err != nil || ce.ID == 0 {
			return fail(errors.New("import result has no certificate id"))
		}
		id, imported = ce.ID, true
	}

	detail := fmt.Sprintf("certificate %d unchanged", id)
	if imported {
		detail = fmt.Sprintf("certificate %d imported", id)
	}
	if setUI {
		raw, err := rc.call(ctx, "system.general.config", []any{})
		if err != nil {
			return fail(fmt.Errorf("reading general config: %w", err))
		}
		var gc struct {
			UICertificate json.RawMessage `json:"ui_certificate"`
		}
		if err := json.Unmarshal(raw, &gc); err != nil {
			return fail(fmt.Errorf("decoding general config: %w", err))
		}
		if tnCertID(gc.UICertificate) != id {
			if _, err := rc.call(ctx, "system.general.update", []any{map[string]any{"ui_certificate": id}}); err != nil {
				return fail(fmt.Errorf("setting ui certificate: %w", err))
			}
			if err := rc.callAllowClose(ctx, truenasMethodRestartUI, truenasUIRestartParams); err != nil {
				return fail(fmt.Errorf("restarting ui: %w", err))
			}
			detail += ", ui cert set"
			// The UI restart may drop the socket, so stale cleanup
			// needs a fresh connection.
			_ = conn.CloseNow()
			conn = nil
			for i := 0; i < 5 && conn == nil; i++ {
				if i > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(2 * time.Second):
					}
				}
				conn, _ = tnDial(ctx, wsURL.String(), opts)
			}
			if conn == nil {
				return targets.Result{Detail: detail + " (cleanup skipped: reconnect failed)"}, nil
			}
			defer func() { _ = conn.CloseNow() }()
			rc = newRPCClient(conn)
			if err := tnLogin(ctx, rc, username, cfg.APIKey); err != nil {
				return targets.Result{Detail: detail + " (cleanup skipped: login failed)"}, nil
			}
		}
	}

	removed, warns := 0, []string{}
	for _, e := range existing {
		if e.ID == id {
			continue
		}
		if _, err := tnJob(ctx, rc, "certificate.delete", []any{e.ID, false}); err != nil {
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "in use") && !strings.Contains(msg, "used by") {
				warns = append(warns, fmt.Sprintf("could not remove %s: %s", e.Name, oneLine(targets.Redact(err, secrets, truenasErrCap), truenasErrCap)))
			}
			continue
		}
		removed++
	}
	if removed > 0 {
		detail += fmt.Sprintf(", %d old removed", removed)
	}
	if len(warns) > 0 {
		detail += " (warning: " + strings.Join(warns, "; ") + ")"
	}
	return targets.Result{Detail: detail}, nil
}

// tnCertID reads ui_certificate, which is an object with an id, a bare id or null.
func tnCertID(raw json.RawMessage) int {
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var o struct {
		ID int `json:"id"`
	}
	_ = json.Unmarshal(raw, &o)
	return o.ID
}

func tnLogin(ctx context.Context, rc *rpcClient, username, key string) error {
	raw, err := rc.call(ctx, truenasMethodLoginEx, []any{map[string]any{
		"mechanism": truenasLoginMechanism, "username": username, "api_key": key,
	}})
	if err == nil {
		var r struct {
			ResponseType string `json:"response_type"`
		}
		if json.Unmarshal(raw, &r) == nil && r.ResponseType == "SUCCESS" {
			return nil
		}
		return errors.New("login failed: API key rejected")
	}
	if !isMethodNotFound(err) {
		return fmt.Errorf("login failed: %w", err)
	}
	raw, err = rc.call(ctx, truenasMethodLoginKey, []any{key})
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if string(bytes.TrimSpace(raw)) != "true" {
		return errors.New("login failed: API key rejected")
	}
	return nil
}

// tnJob calls a job-returning method and waits for its result.
func tnJob(ctx context.Context, rc *rpcClient, method string, params any) (json.RawMessage, error) {
	raw, err := rc.call(ctx, method, params)
	if err != nil {
		return nil, err
	}
	var jobID int
	if err := json.Unmarshal(raw, &jobID); err != nil {
		return nil, fmt.Errorf("%s: no job id in response", method)
	}
	res, err := rc.call(ctx, truenasMethodJobWait, []any{jobID})
	if err == nil || !isMethodNotFound(err) {
		return res, err
	}
	for {
		raw, err := rc.call(ctx, "core.get_jobs", []any{[]any{[]any{"id", "=", jobID}}})
		if err != nil {
			return nil, err
		}
		var jobs []struct {
			State     string          `json:"state"`
			Result    json.RawMessage `json:"result"`
			Error     string          `json:"error"`
			Exception string          `json:"exception"`
		}
		if err := json.Unmarshal(raw, &jobs); err != nil || len(jobs) != 1 {
			return nil, errors.New("job status unavailable")
		}
		switch jobs[0].State {
		case "SUCCESS":
			return jobs[0].Result, nil
		case "FAILED", "ABORTED":
			msg := jobs[0].Error
			if msg == "" {
				msg = jobs[0].Exception
			}
			return nil, fmt.Errorf("job %d %s: %s", jobID, strings.ToLower(jobs[0].State), oneLine(msg, truenasErrCap))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func tnDial(ctx context.Context, u string, opts *websocket.DialOptions) (*websocket.Conn, error) {
	conn, resp, err := websocket.Dial(ctx, u, opts)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	return conn, err
}
