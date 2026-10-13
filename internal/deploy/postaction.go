package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx"
)

// Post action kinds.
const (
	PostActionSSH     = "ssh"
	PostActionPfSense = "pfsense"
)

// PostAction is a server grant's optional follow-up, run after a successful
// deploy: one command over SSH on the host of an existing ssh deploy target
// (kind "ssh"), or one shell command on a pfSense firewall through the Nexus
// API of an existing pfsense deploy target (kind "pfsense").
type PostAction struct {
	Kind           string    `json:"kind"`
	TargetID       uuid.UUID `json:"targetId"`
	Command        string    `json:"command"`
	TimeoutSeconds int       `json:"timeoutSeconds,omitempty"`
}

// UnmarshalJSON reads rows stored before kinds existed: no kind means ssh,
// and sshTargetId is the old name of targetId.
func (p *PostAction) UnmarshalJSON(b []byte) error {
	type plain PostAction
	aux := struct {
		plain
		SSHTargetID uuid.UUID `json:"sshTargetId"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*p = PostAction(aux.plain)
	if p.Kind == "" {
		p.Kind = PostActionSSH
	}
	if p.TargetID == uuid.Nil {
		p.TargetID = aux.SSHTargetID
	}
	return nil
}

// TargetType is the deploy target type this kind runs against.
func (p *PostAction) TargetType() string {
	if p.Kind == PostActionPfSense {
		return TypePfSense
	}
	return "ssh"
}

// MaxPostActionCommand bounds PostAction.Command.
const MaxPostActionCommand = 512

// ParsePostAction decodes a stored post_action; empty, null or {} is nil.
func ParsePostAction(raw []byte) (*PostAction, error) {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return nil, nil
	}
	var p PostAction
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the fields that do not need the database.
func (p *PostAction) Validate() error {
	p.Command = strings.TrimSpace(p.Command)
	if p.Kind == "" {
		p.Kind = PostActionSSH
	}
	switch {
	case p.Kind != PostActionSSH && p.Kind != PostActionPfSense:
		return errors.New("kind must be ssh or pfsense")
	case p.TargetID == uuid.Nil:
		return errors.New("targetId is required")
	case p.Command == "":
		return errors.New("command is required")
	case len(p.Command) > MaxPostActionCommand:
		return fmt.Errorf("command is longer than %d characters", MaxPostActionCommand)
	case p.TimeoutSeconds == 0:
		p.TimeoutSeconds = 60
	case p.TimeoutSeconds < 5 || p.TimeoutSeconds > 300:
		return errors.New("timeoutSeconds must be 5 to 300")
	}
	return nil
}

// hookRecorder stores a server run against one grant and its target.
type hookRecorder struct {
	d      *Dispatcher
	grant  uuid.UUID
	target uuid.UUID
}

// RecordHook implements targets.HookRecorder. A failed write is only logged,
// and runs even when the deploy's own context has expired.
func (r hookRecorder) RecordHook(ctx context.Context, h targets.HookRun) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	g, t := r.grant, r.target
	err := r.d.Q.InsertServerHookRun(ctx, sqlcgen.InsertServerHookRunParams{GrantID: &g, DeployTargetID: &t, Phase: h.Phase,
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

// loadTarget opens the org's deploy target id, which must be of type typ.
// Errors name the target kind (label) and carry no secrets.
func (d *Dispatcher) loadTarget(ctx context.Context, orgID, id uuid.UUID, typ, label string) (resolvedTarget, error) {
	var rt resolvedTarget
	t, err := d.Q.GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: id, OrgID: orgID})
	if err != nil {
		return rt, errors.New(label + " target not found")
	}
	if t.Type != typ {
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
	rt, err := d.loadTarget(ctx, orgID, id, TypePfSense, "pfsense")
	if err != nil {
		return "", nil, err
	}
	if d.HTTP == nil {
		return "", nil, errors.New("pfsense: outbound HTTP is not configured")
	}
	return PfSenseUsage(ctx, d.HTTP(ctx), rt.cfg, certName)
}

// runPostAction runs pa over the referenced target and records it. The
// returned error is already redacted of the target's secrets.
func (d *Dispatcher) runPostAction(ctx context.Context, row sqlcgen.ServerDeployGrantRow, pa *PostAction, hf targets.HTTPFactory) error {
	label := pa.TargetType()
	rt, err := d.loadTarget(ctx, row.OrgID, pa.TargetID, label, label)
	if err != nil {
		return errors.New("post action: " + err.Error())
	}
	timeout := time.Duration(pa.TimeoutSeconds) * time.Second
	if pa.TimeoutSeconds == 0 {
		timeout = 60 * time.Second
	}
	rec := hookRecorder{d: d, grant: row.ID, target: *row.DeployTargetID}
	run := targets.HookRun{Phase: "post_deploy", ExitCode: -1}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	redact := rt.redact
	fail := func(err error) error {
		msg := targets.Redact(err, redact, 500)
		run.Duration, run.Stderr = time.Since(start), capRun([]byte(msg))
		rec.RecordHook(ctx, run)
		return errors.New("post action: " + msg)
	}
	if pa.Kind == PostActionPfSense {
		var cfg PfSenseConfig
		if err := json.Unmarshal(rt.cfg, &cfg); err != nil {
			return errors.New("post action: pfsense target config invalid")
		}
		host := cfg.URL
		if u, err := url.Parse(cfg.URL); err == nil && u.Host != "" {
			host = u.Host
		}
		run.Argv = []string{"pfsense", host, pa.Command}
		cfg.TimeoutSeconds = pfPostActionHTTPTimeout(cfg.TimeoutSeconds, pa.TimeoutSeconds)
		n, err := newNexusClient(ctx, hf, cfg)
		if err != nil {
			return fail(err)
		}
		redact = n.secrets(redact)
		out, err := n.Shell(ctx, pa.Command, pa.TimeoutSeconds)
		if err != nil {
			return fail(err)
		}
		// The API reports no exit status: an accepted command counts as done.
		run.ExitCode, run.Duration = 0, time.Since(start)
		run.Stdout = capRun([]byte(targets.Redact(errors.New(out), redact, 8192)))
		rec.RecordHook(ctx, run)
		return nil
	}
	var cfg SSHConfig
	if err := json.Unmarshal(rt.cfg, &cfg); err != nil {
		return errors.New("post action: ssh target config invalid")
	}
	run.Argv = []string{"ssh", cfg.Host, pa.Command}
	cl, err := sshx.Dial(ctx, sshx.Opts{Host: cfg.Host, Port: cfg.Port, User: cfg.Username, Password: cfg.Password,
		PrivateKeyPEM: cfg.PrivateKey, PrivateKeyPassphrase: cfg.PrivateKeyPassphrase, HostKey: cfg.HostKey, AllowLoopback: hf.AllowLoopback, Timeout: timeout})
	if err != nil {
		return fail(err)
	}
	defer func() { _ = cl.Close() }()
	stdout, stderr, code, err := cl.Run(ctx, pa.Command)
	if err != nil {
		return fail(err)
	}
	run.ExitCode, run.Duration, run.Stdout, run.Stderr = code, time.Since(start), capRun(stdout), capRun(stderr)
	rec.RecordHook(ctx, run)
	if code != 0 {
		return fmt.Errorf("post action: exit %d: %s", code, sshSnippet(stderr))
	}
	return nil
}

// pfPostActionHTTPTimeout is the HTTP timeout (seconds) for a pfSense post
// action: the command may run as long as the post action allows, which can
// exceed the target's own timeout, plus slack for the request itself.
func pfPostActionHTTPTimeout(cfgSecs, paSecs int) int {
	if cfgSecs == 0 {
		cfgSecs = 30
	}
	return max(cfgSecs, paSecs) + 10
}
