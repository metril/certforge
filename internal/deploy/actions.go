package deploy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/actions"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx"
)

// Notifier sends an action step's notification; internal/notify implements
// it (this package must not import internal/notify).
type Notifier interface {
	SendDeploy(ctx context.Context, orgID, channelID uuid.UUID, n DeployNotice) error
}

// DeployNotice is what a notify action says about a grant's deploy.
type DeployNotice struct {
	GrantID                                  uuid.UUID
	CertName, TargetName, Fingerprint, Phase string
}

// stepAction is an expanded action with the columns the dispatcher adds.
type stepAction struct {
	actions.ActionRef
	Name   string
	Sealed []byte // the action's sealed secret_cfg
}

// stepResult is what an action reports for its run record.
type stepResult struct {
	argv           []string
	stdout, stderr string
	exit           int
	redact         map[string]string
}

const (
	defaultActionTimeout = 60 * time.Second
	maxHTTPActionBody    = 8192
)

// hookRecorder stores a server run against one grant and its target.
type hookRecorder struct {
	d      *Dispatcher
	grant  uuid.UUID
	target uuid.UUID
	action *uuid.UUID // the action step the run belongs to, when it is one
}

// RecordHook implements targets.HookRecorder. A failed write is only logged,
// and runs even when the deploy's own context has expired.
func (r hookRecorder) RecordHook(ctx context.Context, h targets.HookRun) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	g, t := r.grant, r.target
	err := r.d.Q.InsertServerHookRun(ctx, sqlcgen.InsertServerHookRunParams{GrantID: &g, HookID: r.action, DeployTargetID: &t, Phase: h.Phase,
		Argv: h.Argv, ExitCode: int32(h.ExitCode), DurationMs: h.Duration.Milliseconds(), Stdout: h.Stdout, Stderr: h.Stderr})
	if err != nil {
		r.d.log().Error("deploy: hook run not recorded", "grant", r.grant, "err", err)
	}
}

// resolvedTarget is a deploy target with its secrets and credential opened.
type resolvedTarget struct {
	cfg    json.RawMessage // resolved config, secrets included
	redact map[string]string
}

// loadTarget opens the org's deploy target id, which must be one of types.
// Errors name the target kind (label) and carry no secrets.
func (d *Dispatcher) loadTarget(ctx context.Context, orgID, id uuid.UUID, types []string, label string) (resolvedTarget, error) {
	var rt resolvedTarget
	t, err := d.Q.GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: id, OrgID: orgID})
	if err != nil {
		return rt, errors.New(label + " target not found")
	}
	if !slices.Contains(types, t.Type) {
		return rt, errors.New("target is not a " + label + " target")
	}
	secrets, err := d.openTargetSecrets(ctx, t.SecretCfg)
	if err != nil {
		return rt, errors.New(label + " target secrets unavailable")
	}
	var cred *targets.Credential
	rt.redact = secrets
	if t.CredentialID != nil {
		dc, err := d.Q.GetDeployCredential(ctx, sqlcgen.GetDeployCredentialParams{ID: *t.CredentialID, OrgID: orgID})
		if err != nil {
			return rt, errors.New(label + " target credential not found")
		}
		if cred, err = targets.OpenCredential(ctx, d.Box.Open, &dc.Kind, dc.Public, dc.SecretCfg); err != nil {
			return rt, errors.New(label + " target credential unavailable")
		}
		rt.redact = make(map[string]string, len(secrets)+len(cred.Secrets))
		for k, v := range secrets {
			rt.redact[k] = v
		}
		for k, v := range cred.Secrets {
			rt.redact["credential:"+k] = v
		}
	}
	if rt.cfg, err = targets.Resolve(t.Config, secrets, cred); err != nil {
		return rt, errors.New(label + " target config invalid")
	}
	return rt, nil
}

// PfSenseUsage reports which pfSense services use the certificate named
// certName on the org's pfsense target id (see the package-level PfSenseUsage).
func (d *Dispatcher) PfSenseUsage(ctx context.Context, orgID, id uuid.UUID, certName string) (string, []PfSenseService, error) {
	rt, err := d.loadTarget(ctx, orgID, id, []string{TypePfSense}, "pfsense")
	if err != nil {
		return "", nil, err
	}
	if d.HTTP == nil {
		return "", nil, errors.New("pfsense: outbound HTTP is not configured")
	}
	return PfSenseUsage(ctx, d.HTTP(ctx), rt.cfg, certName)
}

// runAction runs one action step against the grant and records it. The
// returned error is already redacted of the target's and the action's secrets.
func (d *Dispatcher) runAction(ctx context.Context, row sqlcgen.ServerDeployGrantRow, a stepAction, req targets.Request) error {
	timeout := time.Duration(a.TimeoutSeconds) * time.Second
	if a.TimeoutSeconds <= 0 {
		timeout = defaultActionTimeout
	}
	if a.Kind == "wait" {
		var c struct {
			Seconds int `json:"seconds"`
		}
		_ = json.Unmarshal(a.Config, &c)
		timeout = time.Duration(c.Seconds)*time.Second + 5*time.Second
	}
	id := a.ID
	rec := hookRecorder{d: d, grant: row.ID, action: &id}
	if row.DeployTargetID != nil {
		rec.target = *row.DeployTargetID
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	res := stepResult{exit: -1, argv: []string{a.Kind}}
	err := d.execAction(ctx, row, a, req, timeout, &res)
	run := targets.HookRun{Phase: a.Phase, Argv: res.argv, ExitCode: res.exit, Duration: time.Since(start),
		Stdout: capRun([]byte(res.stdout)), Stderr: capRun([]byte(res.stderr))}
	if err == nil {
		rec.RecordHook(ctx, run)
		return nil
	}
	msg := targets.Redact(err, res.redact, 500)
	if run.Stderr == "" {
		run.Stderr = capRun([]byte(msg))
	}
	rec.RecordHook(ctx, run)
	return errors.New(msg)
}

func (d *Dispatcher) execAction(ctx context.Context, row sqlcgen.ServerDeployGrantRow, a stepAction, req targets.Request, timeout time.Duration, res *stepResult) error {
	var c struct {
		TargetID  string                  `json:"targetId"`
		Command   string                  `json:"command"`
		Mode      string                  `json:"mode"`
		Services  []string                `json:"services"`
		Seconds   int                     `json:"seconds"`
		Method    string                  `json:"method"`
		URL       string                  `json:"url"`
		Headers   map[string]string       `json:"headers"`
		Body      string                  `json:"body"`
		Expected  *struct{ Min, Max int } `json:"expectedStatus"`
		ChannelID string                  `json:"channelId"`
		Host      string                  `json:"host"`
		Port      *int                    `json:"port"`
		SNI       string                  `json:"sni"`
	}
	if err := json.Unmarshal(a.Config, &c); err != nil {
		return errors.New("action config invalid")
	}
	target := func(types []string, label string) (resolvedTarget, error) {
		id, err := uuid.Parse(c.TargetID)
		if err != nil {
			return resolvedTarget{}, errors.New("action config invalid")
		}
		rt, err := d.loadTarget(ctx, row.OrgID, id, types, label)
		res.redact = rt.redact
		return rt, err
	}
	secs := int(timeout.Seconds())
	switch a.Kind {
	case "ssh":
		rt, err := target([]string{TypeSSH, TypePiKVM}, "ssh")
		if err != nil {
			return err
		}
		var cfg SSHConfig
		if err := json.Unmarshal(rt.cfg, &cfg); err != nil {
			return errors.New("ssh target config invalid")
		}
		res.argv = []string{"ssh", cfg.Host, c.Command}
		cl, err := sshx.Dial(ctx, sshx.Opts{Host: cfg.Host, Port: cfg.Port, User: cfg.Username, Password: cfg.Password,
			PrivateKeyPEM: cfg.PrivateKey, PrivateKeyPassphrase: cfg.PrivateKeyPassphrase, HostKey: cfg.HostKey, AllowLoopback: req.HTTP.AllowLoopback, Timeout: timeout})
		if err != nil {
			return err
		}
		defer func() { _ = cl.Close() }()
		stdout, stderr, code, err := cl.Run(ctx, c.Command)
		if err != nil {
			return err
		}
		res.exit, res.stdout, res.stderr = code, string(stdout), string(stderr)
		if code != 0 {
			return fmt.Errorf("exit %d: %s", code, sshSnippet(stderr))
		}
	case "pfsense_shell":
		rt, err := target([]string{TypePfSense}, "pfsense")
		if err != nil {
			return err
		}
		var cfg PfSenseConfig
		if err := json.Unmarshal(rt.cfg, &cfg); err != nil {
			return errors.New("pfsense target config invalid")
		}
		res.argv = []string{"pfsense", pfHost(cfg.URL), c.Command}
		cfg.TimeoutSeconds = pfPostActionHTTPTimeout(cfg.TimeoutSeconds, secs)
		n, err := newNexusClient(ctx, req.HTTP, cfg)
		if err != nil {
			return err
		}
		res.redact = n.secrets(rt.redact)
		out, err := n.Shell(ctx, c.Command, secs)
		if err != nil {
			return err
		}
		// The API reports no exit status: an accepted command counts as done.
		res.exit, res.stdout = 0, out
	case "pfsense_restart":
		rt, err := target([]string{TypePfSense}, "pfsense")
		if err != nil {
			return err
		}
		var cfg PfSenseConfig
		if err := json.Unmarshal(rt.cfg, &cfg); err != nil {
			return errors.New("pfsense target config invalid")
		}
		mode := c.Mode
		if mode == "" {
			mode = PfRestartAll
		}
		res.argv = []string{"pfsense_restart", pfHost(cfg.URL), mode}
		if mode == PfRestartNone {
			res.exit, res.stdout = 0, "no services restarted (mode none)"
			return nil
		}
		refid, _, err := PfSenseUsage(ctx, req.HTTP, rt.cfg, req.CertName)
		if err != nil {
			return err
		}
		if refid == "" {
			return errors.New("the certificate is not on the firewall")
		}
		cfg.TimeoutSeconds = pfPostActionHTTPTimeout(cfg.TimeoutSeconds, secs)
		n, err := newNexusClient(ctx, req.HTTP, cfg)
		if err != nil {
			return err
		}
		res.redact = n.secrets(rt.redact)
		var s pfServices
		var skipped []string
		if mode == PfRestartSelected {
			s, skipped, err = n.restartSelected(ctx, refid, c.Services)
		} else {
			s, err = n.RestartCertServices(ctx, refid)
		}
		if err != nil {
			return err
		}
		res.exit = 0
		if labels := s.Labels(); len(labels) > 0 {
			res.stdout = "restarted: " + strings.Join(labels, ", ")
		} else {
			res.stdout = "no services use the certificate"
		}
		res.stdout += pfSkippedNote(skipped)
	case "truenas_restart":
		rt, err := target([]string{TypeTrueNAS}, "truenas")
		if err != nil {
			return err
		}
		var cfg TrueNASConfig
		if err := json.Unmarshal(rt.cfg, &cfg); err != nil {
			return errors.New("truenas target config invalid")
		}
		wsURL, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
		if err != nil || wsURL.Scheme != "https" {
			return errors.New("url must be https")
		}
		res.argv = []string{"truenas_restart", wsURL.Host}
		wsURL.Scheme, wsURL.Path = "wss", truenasEndpoint
		opts, err := req.HTTP.WebSocket(httpx.Options{CAPEM: cfg.CAPEM, Timeout: timeout, MaxBody: 1 << 20})
		if err != nil {
			return err
		}
		conn, err := tnDial(ctx, wsURL.String(), opts)
		if err != nil {
			return err
		}
		defer func() { _ = conn.CloseNow() }()
		rc := newRPCClient(conn)
		username := cfg.Username
		if username == "" {
			username = "root"
		}
		if err := tnLogin(ctx, rc, username, cfg.APIKey); err != nil {
			return err
		}
		if err := rc.callAllowClose(ctx, truenasMethodRestartUI, truenasUIRestartParams); err != nil {
			return fmt.Errorf("restarting ui: %w", err)
		}
		res.exit, res.stdout = 0, "web UI restarted"
	case "routeros_restart":
		rt, err := target([]string{TypeRouterOS}, "routeros")
		if err != nil {
			return err
		}
		var cfg RouterOSConfig
		if err := json.Unmarshal(rt.cfg, &cfg); err != nil {
			return errors.New("routeros target config invalid")
		}
		if req.Material == nil {
			return errors.New("no certificate material")
		}
		if cfg.CertName == "" {
			cfg.CertName = "certforge"
		}
		if cfg.Services == nil {
			cfg.Services = []string{"www-ssl", "api-ssl"}
		}
		res.argv = []string{"routeros_restart", pfHost(cfg.URL)}
		client, err := req.HTTP.New(httpx.Options{CAPEM: cfg.CAPEM, Timeout: timeout, MaxBody: roMaxBody})
		if err != nil {
			return err
		}
		callCtx := roCaller(client, cfg, req.HTTP.AllowLoopback)
		name := cfg.CertName + "-" + req.Fingerprint[:8]
		if err := roBindServices(cfg.Services, name, func(method, path string, body any) ([]byte, error) {
			return callCtx(ctx, method, path, body)
		}); err != nil {
			return err
		}
		res.exit, res.stdout = 0, "services bound to "+name
	case "http":
		return d.execHTTP(ctx, a, req, timeout, res, c.Method, c.URL, c.Headers, c.Body, c.Expected)
	case "notify":
		if d.Notify == nil {
			return errors.New("notifications are not configured")
		}
		id, err := uuid.Parse(c.ChannelID)
		if err != nil {
			return errors.New("action config invalid")
		}
		res.argv = []string{"notify", c.ChannelID}
		if err := d.Notify.SendDeploy(ctx, row.OrgID, id, DeployNotice{GrantID: row.ID, CertName: row.CertificateName,
			TargetName: row.TargetName, Fingerprint: req.Fingerprint, Phase: a.Phase}); err != nil {
			return err
		}
		res.exit, res.stdout = 0, "notification sent"
	case "verify_tls":
		port := "443"
		if c.Port != nil {
			port = strconv.Itoa(*c.Port)
		}
		res.argv = []string{"verify_tls", c.Host + ":" + port}
		chain, _, err := httpx.Peek(ctx, c.Host, port, c.SNI, req.HTTP.AllowLoopback)
		if err != nil {
			return err
		}
		if got := agentproto.CertFingerprint(chain[0].Raw); got != req.Fingerprint {
			return fmt.Errorf("the server presents certificate %s, not the deployed %s", shortFP(got), shortFP(req.Fingerprint))
		}
		res.exit, res.stdout = 0, "serves the deployed certificate "+shortFP(req.Fingerprint)
	case "wait":
		res.argv = []string{"wait", strconv.Itoa(c.Seconds) + "s"}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(c.Seconds) * time.Second):
		}
		res.exit = 0
	default:
		return fmt.Errorf("action kind %q cannot run on the server", a.Kind)
	}
	return nil
}

func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}

// pfHost is the host part of a target's URL, or the URL itself.
func pfHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// execHTTP sends the http action's request through the SSRF-safe client.
func (d *Dispatcher) execHTTP(ctx context.Context, a stepAction, req targets.Request, timeout time.Duration, res *stepResult,
	method, rawURL string, headers map[string]string, body string, expected *struct{ Min, Max int }) error {
	secrets, err := d.openTargetSecrets(ctx, a.Sealed)
	if err != nil {
		return errors.New("action secrets unavailable")
	}
	var secretHeaders map[string]string
	if raw := secrets["secretHeaders"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &secretHeaders); err != nil {
			return errors.New("action secrets unavailable")
		}
	}
	res.redact = map[string]string{}
	for k, v := range secretHeaders {
		res.redact["header:"+k] = v
	}
	// The query string can carry a token: record only scheme, host and path.
	if u, err := url.Parse(rawURL); err == nil {
		res.argv = []string{"http", method, u.Scheme + "://" + u.Host + u.Path}
	}
	if err := httpx.CheckURL(rawURL, req.HTTP.AllowLoopback); err != nil {
		return err
	}
	client, err := req.HTTP.New(httpx.Options{Timeout: timeout, MaxBody: maxHTTPActionBody})
	if err != nil {
		return err
	}
	var notAfter string
	if c, err := x509.ParseCertificate(leafDER(req)); err == nil {
		notAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}
	body = actions.ExpandTemplate(body, actions.Vars{CertName: req.CertName, CertFingerprint: req.Fingerprint,
		CertNotAfter: notAfter, GrantID: req.GrantID})
	var rd io.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	}
	hr, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return errors.New("invalid request")
	}
	for k, v := range headers {
		hr.Header.Set(k, v)
	}
	for k, v := range secretHeaders {
		hr.Header.Set(k, v)
	}
	resp, err := client.HTTPClient().Do(hr)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPActionBody))
	res.exit, res.stdout = resp.StatusCode, targets.Redact(errors.New(string(b)), res.redact, maxHTTPActionBody)
	lo, hi := 200, 299
	if expected != nil {
		lo, hi = expected.Min, expected.Max
	}
	if resp.StatusCode < lo || resp.StatusCode > hi {
		return fmt.Errorf("status %d, expected %d to %d: %s", resp.StatusCode, lo, hi, sshSnippet([]byte(res.stdout)))
	}
	return nil
}

func leafDER(req targets.Request) []byte {
	if req.Material == nil {
		return nil
	}
	return req.Material.LeafDER
}

// pfPostActionHTTPTimeout is the HTTP timeout (seconds) for a pfSense shell
// action: the command may run as long as the action allows, which can exceed
// the target's own timeout, plus slack for the request itself.
func pfPostActionHTTPTimeout(cfgSecs, paSecs int) int {
	if cfgSecs == 0 {
		cfgSecs = 30
	}
	return max(cfgSecs, paSecs) + 10
}
