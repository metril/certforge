package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx"
)

// PostAction is a server grant's optional follow-up: one command run over SSH
// on the host of an existing ssh deploy target, after a successful deploy.
type PostAction struct {
	SSHTargetID    uuid.UUID `json:"sshTargetId"`
	Command        string    `json:"command"`
	TimeoutSeconds int       `json:"timeoutSeconds,omitempty"`
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
	switch {
	case p.SSHTargetID == uuid.Nil:
		return errors.New("sshTargetId is required")
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

// runPostAction runs pa over the referenced ssh target and records it. The
// returned error is already redacted of the ssh target's secrets.
func (d *Dispatcher) runPostAction(ctx context.Context, row sqlcgen.ServerDeployGrantRow, pa *PostAction, allowLoopback bool) error {
	t, err := d.Q.GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: pa.SSHTargetID, OrgID: row.OrgID})
	if err != nil {
		return errors.New("post action: ssh target not found")
	}
	if t.Type != "ssh" {
		return errors.New("post action: target is not an ssh target")
	}
	secrets, err := d.openTargetSecrets(ctx, t.SecretCfg)
	if err != nil {
		return errors.New("post action: ssh target secrets unavailable")
	}
	raw, err := targets.Merge(t.Config, secrets)
	if err != nil {
		return errors.New("post action: ssh target config invalid")
	}
	var cfg SSHConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return errors.New("post action: ssh target config invalid")
	}
	timeout := time.Duration(pa.TimeoutSeconds) * time.Second
	if pa.TimeoutSeconds == 0 {
		timeout = 60 * time.Second
	}
	rec := hookRecorder{d: d, grant: row.ID, target: *row.DeployTargetID}
	run := targets.HookRun{Phase: "post_deploy", Argv: []string{"ssh", cfg.Host, pa.Command}, ExitCode: -1}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	fail := func(err error) error {
		msg := targets.Redact(err, secrets, 500)
		run.Duration, run.Stderr = time.Since(start), capRun([]byte(msg))
		rec.RecordHook(ctx, run)
		return errors.New("post action: " + msg)
	}
	cl, err := sshx.Dial(ctx, sshx.Opts{Host: cfg.Host, Port: cfg.Port, User: cfg.Username, Password: cfg.Password,
		PrivateKeyPEM: cfg.PrivateKey, HostKey: cfg.HostKey, AllowLoopback: allowLoopback, Timeout: timeout})
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
