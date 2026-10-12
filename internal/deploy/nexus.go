package deploy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"

	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/targets"
)

const (
	pfShell  = "/diag/cmd/shell"
	pfPHP    = "/diag/cmd/php"
	pfMarker = "CFJSON:"
)

var pfRefidRe = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// nexusClient talks to one pfSense firewall through the Netgate Nexus API.
type nexusClient struct {
	client        *httpx.Client
	base, token   string
	prefix        string
	allowLoopback bool
}

// newNexusClient builds the HTTP client, logs in and resolves the device.
func newNexusClient(ctx context.Context, f targets.HTTPFactory, cfg PfSenseConfig) (*nexusClient, error) {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if cfg.TimeoutSeconds == 0 {
		timeout = 30 * time.Second
	}
	client, err := f.New(httpx.Options{CAPEM: cfg.CAPEM, Timeout: timeout, MaxBody: pfMaxBody})
	if err != nil {
		return nil, err
	}
	if client.HTTPClient().Jar == nil { // login sets a refresh cookie
		jar, _ := cookiejar.New(nil)
		client.HTTPClient().Jar = jar
	}
	n := &nexusClient{client: client, base: strings.TrimRight(cfg.URL, "/"), allowLoopback: f.AllowLoopback}
	b, err := n.call(ctx, http.MethodPost, pfLogin, map[string]string{
		"username": base64.StdEncoding.EncodeToString([]byte(cfg.Username)),
		"password": base64.StdEncoding.EncodeToString([]byte(cfg.Password))})
	if err != nil {
		return nil, err
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &login); err != nil || login.Token == "" {
		return nil, errors.New("login response has no token")
	}
	n.token = login.Token
	b, err = n.call(ctx, http.MethodGet, pfDevices, nil)
	if err != nil {
		return nil, err
	}
	if n.prefix, err = pfPickDevice(b, cfg.Device); err != nil {
		return nil, err
	}
	return n, nil
}

// secrets adds the session token (when set) to base and returns it, for
// redacting errors.
func (n *nexusClient) secrets(base map[string]string) map[string]string {
	if n != nil && n.token != "" {
		base["token"] = n.token
	}
	return base
}

// call issues one request; path is relative to the configured base URL.
func (n *nexusClient) call(ctx context.Context, method, path string, body any) ([]byte, error) {
	u := n.base + path
	if err := httpx.CheckURL(u, n.allowLoopback); err != nil {
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
	if n.token != "" {
		hr.Header.Set("Authorization", "Bearer "+n.token)
	}
	hr.Header.Set("Accept", "application/json")
	if body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	resp, err := n.client.HTTPClient().Do(hr)
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

// sys calls a device system endpoint (device prefix applied).
func (n *nexusClient) sys(ctx context.Context, method, path string, body any) ([]byte, error) {
	return n.call(ctx, method, n.prefix+path, body)
}

// diag posts a base64-encoded command to a /diag/cmd endpoint and returns the
// "response" text.
func (n *nexusClient) diag(ctx context.Context, path, cmd string, timeout int) (string, error) {
	body := map[string]any{"cmd": base64.StdEncoding.EncodeToString([]byte(cmd))}
	if timeout > 0 {
		body["timeout"] = timeout
	}
	b, err := n.sys(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", err
	}
	var out struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("decoding %s response: %w", path, err)
	}
	return out.Response, nil
}

// Shell runs a shell command on the firewall and returns its output.
func (n *nexusClient) Shell(ctx context.Context, cmd string, timeoutSeconds int) (string, error) {
	return n.diag(ctx, pfShell, cmd, timeoutSeconds)
}

// PHP runs PHP code (without an opening tag) on the firewall.
func (n *nexusClient) PHP(ctx context.Context, code string) (string, error) {
	return n.diag(ctx, pfPHP, code, 0)
}

// pfService is one entry of cert_get_all_services()['services'].
type pfService struct {
	Name   string         `json:"name"`
	Extras map[string]any `json:"extras"`
}

// pfServices mirrors the array cert_get_all_services() returns.
type pfServices struct {
	WebGUI   bool
	Services []pfService
	Packages []string
}

// UnmarshalJSON tolerates PHP's habit of encoding empty arrays as [] and
// non-sequential arrays as objects.
func (s *pfServices) UnmarshalJSON(b []byte) error {
	*s = pfServices{}
	var raw struct {
		WebGUI   any             `json:"webgui"`
		Services json.RawMessage `json:"services"`
		Packages json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil // an empty PHP array encodes as []
	}
	switch v := raw.WebGUI.(type) {
	case nil:
	case bool:
		s.WebGUI = v
	default:
		s.WebGUI = v != "" && v != float64(0)
	}
	s.Services = decodeList[pfService](raw.Services)
	s.Packages = decodeList[string](raw.Packages)
	return nil
}

func decodeList[T any](b json.RawMessage) []T {
	var arr []T
	if json.Unmarshal(b, &arr) == nil {
		return arr
	}
	var m map[string]T
	if json.Unmarshal(b, &m) == nil {
		out := make([]T, 0, len(m))
		for _, v := range m {
			out = append(out, v)
		}
		return out
	}
	return nil
}

func pfStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprint(int64(x))
	}
	return ""
}

// Labels returns human labels for the services, WebGUI first.
func (s pfServices) Labels() []string {
	out := []string{}
	for _, k := range s.Keyed() {
		out = append(out, k.Label)
	}
	return out
}

// phpMarked runs code and returns the output that holds pfMarker. The response
// may itself be base64, and some firmware only runs code that starts with an
// opening tag, so it retries once with one.
func (n *nexusClient) phpMarked(ctx context.Context, code string) (string, error) {
	var raw string
	for _, c := range []string{code, "<?php\n" + code} {
		out, err := n.PHP(ctx, c)
		if err != nil {
			return "", err
		}
		if strings.Contains(out, pfMarker) {
			return out, nil
		}
		if d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out)); err == nil && strings.Contains(string(d), pfMarker) {
			return string(d), nil
		}
		raw = out
	}
	if len(raw) > 300 {
		raw = raw[:300]
	}
	raw = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, raw)
	if n.token != "" {
		raw = strings.ReplaceAll(raw, n.token, "***")
	}
	return "", fmt.Errorf("unexpected output from the PHP command: %q", raw)
}

func (n *nexusClient) certServices(ctx context.Context, refid string, restart bool) (pfServices, error) {
	var none pfServices
	if !pfRefidRe.MatchString(refid) {
		return none, fmt.Errorf("invalid certificate id %q", refid)
	}
	code := `require_once("certs.inc"); $s = cert_get_all_services("` + refid + `"); `
	if restart {
		code += `cert_restart_services($s); `
	}
	code += `echo "` + pfMarker + `" . json_encode($s);`
	out, err := n.phpMarked(ctx, code)
	if err != nil {
		return none, err
	}
	i := strings.LastIndex(out, pfMarker)
	line := out[i+len(pfMarker):]
	if j := strings.IndexAny(line, "\r\n"); j >= 0 {
		line = line[:j]
	}
	var s pfServices
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &s); err != nil {
		return none, fmt.Errorf("decoding service list: %w", err)
	}
	return s, nil
}

// CertServices lists the services that use the certificate.
func (n *nexusClient) CertServices(ctx context.Context, refid string) (pfServices, error) {
	return n.certServices(ctx, refid, false)
}

// RestartCertServices restarts the services that use the certificate and
// returns what it restarted.
func (n *nexusClient) RestartCertServices(ctx context.Context, refid string) (pfServices, error) {
	return n.certServices(ctx, refid, true)
}

// findCert lists the firewall's certificates: all of them, and those whose
// label is name.
func (n *nexusClient) findCert(ctx context.Context, name string, leafDER []byte) (all, match []pfEntry, err error) {
	b, err := n.sys(ctx, http.MethodGet, pfCerts, nil)
	if err != nil {
		return nil, nil, err
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, fmt.Errorf("decoding certificate list: %w", err)
	}
	pfScan(doc, leafDER, &all)
	for _, e := range all {
		if e.Label == name {
			match = append(match, e)
		}
	}
	return all, match, nil
}

// PfSenseUsage reports which pfSense services use the certificate stored
// under the name Deploy would use (cfg.CertName, else certName), without
// deploying. refid is "" when the firewall has no such certificate. cfgJSON
// is the target's resolved config (secrets included).
func PfSenseUsage(ctx context.Context, f targets.HTTPFactory, cfgJSON json.RawMessage, certName string) (string, []PfSenseService, error) {
	var cfg PfSenseConfig
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		return "", nil, err
	}
	secrets := map[string]string{"password": cfg.Password}
	n, err := newNexusClient(ctx, f, cfg)
	if err != nil {
		return "", nil, errors.New("pfsense: " + targets.Redact(err, secrets, 500))
	}
	wrap := func(err error) error {
		return errors.New("pfsense: " + targets.Redact(err, n.secrets(secrets), 500))
	}
	name := cfg.CertName
	if name == "" {
		name = certName
	}
	_, match, err := n.findCert(ctx, name, nil)
	if err != nil {
		return "", nil, wrap(err)
	}
	switch len(match) {
	case 0:
		return "", nil, nil
	case 1:
	default:
		return "", nil, fmt.Errorf("pfsense: %d certificates are named %q; remove the duplicates in pfSense", len(match), name)
	}
	s, err := n.CertServices(ctx, match[0].Refid)
	if err != nil {
		return "", nil, wrap(err)
	}
	return match[0].Refid, s.Keyed(), nil
}
