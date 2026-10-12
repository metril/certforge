package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx"
)

// TypeSSH is the ssh deploy target type: a server-run target that writes
// certificate files to a remote host over SSH and runs optional pre/post
// commands (for example PiKVM, which has no certificate API).
const TypeSSH = "ssh"

const sshErrCap = 200

var (
	sshContentRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	sshModeRe    = regexp.MustCompile(`^0[0-7]{3}$`)
)

// sshCanon are the content names rendered from the certificate material.
var sshCanon = map[string]bool{"fullchain": true, "cert": true, "chain": true, "key": true, "bundle": true}

// SSHFile is one file the ssh target writes.
type SSHFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode,omitempty"`
}

// SSHConfig is an ssh target's config; Password and PrivateKey are secret.
type SSHConfig struct {
	Host           string    `json:"host"`
	Port           int       `json:"port,omitempty"`
	Username       string    `json:"username"`
	Password       string    `json:"password,omitempty"`
	PrivateKey     string    `json:"privateKey,omitempty"`
	HostKey        string    `json:"hostKey"`
	Files          []SSHFile `json:"files"`
	PreCommand     string    `json:"preCommand,omitempty"`
	PostCommand    string    `json:"postCommand,omitempty"`
	TimeoutSeconds int       `json:"timeoutSeconds,omitempty"`
}

const sshSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "SSH (files + commands)",
  "description": "Writes certificate files to a remote host over SSH and runs optional commands before and after. Runs on the server.",
  "type": "object",
  "additionalProperties": false,
  "required": ["host", "username", "hostKey", "files"],
  "properties": {
    "host": {"type": "string", "title": "Host", "description": "Hostname or IP address of the SSH server."},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 22, "title": "Port"},
    "username": {"type": "string", "title": "Username"},
    "password": {"type": "string", "secret": true, "title": "Password", "description": "Password login. Provide a password, a private key, or both."},
    "privateKey": {"type": "string", "secret": true, "maxLength": 8192, "title": "Private key", "description": "PEM private key (not passphrase-protected)."},
    "hostKey": {"type": "string", "maxLength": 2048, "title": "Host key", "description": "Pinned server key: a known_hosts line or '<type> <base64>'. Get it with: ssh-keyscan -t ed25519 <host>"},
    "files": {
      "type": "array", "minItems": 1, "maxItems": 16, "title": "Files",
      "items": {
        "type": "object", "additionalProperties": false, "required": ["path", "content"],
        "properties": {
          "path": {"type": "string", "title": "Remote path", "description": "Absolute path on the host."},
          "content": {"type": "string", "title": "Content", "description": "fullchain, cert, chain, key, bundle (fullchain + key), or the name of a layout file.", "pattern": "^[A-Za-z0-9._-]+$"},
          "mode": {"type": "string", "pattern": "^0[0-7]{3}$", "default": "0644", "title": "Mode"}
        }
      }
    },
    "preCommand": {"type": "string", "maxLength": 512, "title": "Command before writing", "description": "Run first; a non-zero exit aborts the deploy."},
    "postCommand": {"type": "string", "maxLength": 512, "title": "Command after writing", "description": "Always run when set, even if a write failed."},
    "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 300, "default": 60, "title": "Timeout (seconds)"}
  }
}`

// SSH is the "ssh" server-run deploy target. Implements targets.Target.
type SSH struct{}

// Type implements targets.Target.
func (SSH) Type() string { return TypeSSH }

// Name implements targets.Target.
func (SSH) Name() string { return "SSH (files + commands)" }

// Schema implements targets.Target.
func (SSH) Schema() json.RawMessage { return json.RawMessage(sshSchema) }

// RunsOn implements targets.Target: always Server.
func (SSH) RunsOn() targets.Mode { return targets.Server }

// KeyPolicy implements targets.Target: the key is needed only when a file
// asks for it.
func (SSH) KeyPolicy() targets.KeyPolicy { return targets.Optional }

// Parse implements targets.Target. NeedsKey is true when a file's content is
// key or bundle, or names a layout file (whose Secret flag is unknown until
// deploy, so it is treated as secret).
func (t SSH) Parse(raw json.RawMessage) (targets.Config, error) {
	var c SSHConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return targets.Config{}, &delivery.FieldError{Field: "config", Msg: err.Error()}
	}
	bad := func(field, msg string) (targets.Config, error) {
		return targets.Config{}, &delivery.FieldError{Field: "config." + field, Msg: msg}
	}
	if c.Host == "" || strings.ContainsAny(c.Host, "/@ \t") {
		return bad("host", "required: a hostname or IP address")
	}
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Port < 1 || c.Port > 65535 {
		return bad("port", "must be between 1 and 65535")
	}
	if c.Username == "" {
		return bad("username", "required")
	}
	if c.Password == "" && c.PrivateKey == "" {
		return bad("password", "a password or a private key is required")
	}
	if _, err := sshx.ParseHostKey(c.HostKey); err != nil {
		return bad("hostKey", "must be a known_hosts line or '<type> <base64>' public key")
	}
	if len(c.Files) < 1 || len(c.Files) > 16 {
		return bad("files", "must hold 1 to 16 files")
	}
	needsKey := false
	for i := range c.Files {
		f := &c.Files[i]
		if !strings.HasPrefix(f.Path, "/") || strings.ContainsAny(f.Path, "\x00\n") {
			return bad(fmt.Sprintf("files[%d].path", i), "must be an absolute path")
		}
		if !sshContentRe.MatchString(f.Content) {
			return bad(fmt.Sprintf("files[%d].content", i), "must match ^[A-Za-z0-9._-]+$")
		}
		if f.Mode == "" {
			f.Mode = "0644"
		}
		if !sshModeRe.MatchString(f.Mode) {
			return bad(fmt.Sprintf("files[%d].mode", i), "must match ^0[0-7]{3}$")
		}
		if f.Content == "key" || f.Content == "bundle" || !sshCanon[f.Content] {
			needsKey = true
		}
	}
	if len(c.PreCommand) > 512 || len(c.PostCommand) > 512 {
		return bad("preCommand", "commands are limited to 512 characters")
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 60
	}
	if c.TimeoutSeconds < 5 || c.TimeoutSeconds > 300 {
		return bad("timeoutSeconds", "must be between 5 and 300")
	}
	canon, err := json.Marshal(c)
	if err != nil {
		return targets.Config{}, err
	}
	pub, secrets, err := targets.Split(t.Schema(), canon)
	if err != nil {
		return targets.Config{}, err
	}
	u := "ssh://" + net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	return targets.Config{Public: pub, Secrets: secrets, NeedsKey: needsKey, URLs: []string{u}}, nil
}

// sshContent resolves one file's bytes from the material or layout files.
func sshContent(name string, m *render.Material, files []render.File) ([]byte, error) {
	if !sshCanon[name] {
		for _, f := range files {
			if f.Name == name {
				return f.Data, nil
			}
		}
		return nil, fmt.Errorf("content %q is not a certificate part or a layout file of this grant", name)
	}
	if m == nil {
		return nil, errors.New("no certificate material")
	}
	parts := map[string][]string{
		"fullchain": {"fullchain"}, "cert": {"cert"}, "chain": {"chain"}, "key": {"key"}, "bundle": {"fullchain", "key"},
	}[name]
	for _, p := range parts {
		if p == "key" && len(m.PrivateKeyPKCS8) == 0 {
			return nil, errors.New("private key is not available to this target")
		}
	}
	out, err := render.PEM{}.Render(*m, render.OutputOpts{Parts: parts})
	if err != nil {
		return nil, err
	}
	var b []byte
	for _, f := range out {
		b = append(b, f.Data...)
	}
	return b, nil
}

// capRun bounds recorded command output to 8 KiB.
func capRun(b []byte) string {
	if len(b) > 8192 {
		b = b[:8192]
	}
	return strings.ToValidUTF8(strings.ReplaceAll(string(b), "\x00", ""), "")
}

func sshSnippet(b []byte) string {
	if len(b) > sshErrCap {
		b = b[:sshErrCap]
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, string(b)))
}

// Deploy implements targets.Target: preCommand, each file in order, then
// postCommand (always, once connected); the first error is returned.
func (SSH) Deploy(ctx context.Context, req targets.Request) (targets.Result, error) {
	var cfg SSHConfig
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return targets.Result{}, err
	}
	secrets := map[string]string{"password": cfg.Password, "privateKey": cfg.PrivateKey}
	fail := func(err error) (targets.Result, error) {
		return targets.Result{}, errors.New("deploy: ssh: " + targets.Redact(err, secrets, 500))
	}
	// Resolve every file before connecting, so a bad name runs nothing.
	data := make([][]byte, len(cfg.Files))
	for i, f := range cfg.Files {
		b, err := sshContent(f.Content, req.Material, req.Files)
		if err != nil {
			return fail(fmt.Errorf("file %s: %w", f.Path, err))
		}
		data[i] = b
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if cfg.TimeoutSeconds == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cl, err := sshx.Dial(ctx, sshx.Opts{Host: cfg.Host, Port: cfg.Port, User: cfg.Username, Password: cfg.Password,
		PrivateKeyPEM: cfg.PrivateKey, HostKey: cfg.HostKey, AllowLoopback: req.HTTP.AllowLoopback, Timeout: timeout})
	if err != nil {
		return fail(err)
	}
	defer func() { _ = cl.Close() }()

	record := func(ctx context.Context, phase, cmd string, start time.Time, stdout, stderr []byte, code int, err error) {
		if req.Recorder == nil {
			return
		}
		r := targets.HookRun{Phase: phase, Argv: []string{"ssh", cfg.Host, cmd}, ExitCode: code, Duration: time.Since(start),
			Stdout: capRun(stdout), Stderr: capRun(stderr)}
		if err != nil {
			r.ExitCode = -1
			r.Stderr = capRun([]byte(targets.Redact(err, secrets, 500)))
		}
		req.Recorder.RecordHook(ctx, r)
	}
	run := func(label, cmd string) error {
		start := time.Now()
		stdout, stderr, code, err := cl.Run(ctx, cmd)
		record(ctx, "pre_deploy", cmd, start, stdout, stderr, code, err)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if code != 0 {
			return fmt.Errorf("%s: exit %d: %s", label, code, sshSnippet(stderr))
		}
		return nil
	}
	if cfg.PreCommand != "" {
		if err := run("preCommand", cfg.PreCommand); err != nil {
			return fail(err)
		}
	}
	var first error
	written := 0
	for i, f := range cfg.Files {
		mode := os.FileMode(0o644)
		if n, err := strconv.ParseUint(f.Mode, 8, 32); err == nil {
			mode = os.FileMode(n)
		}
		if err := cl.WriteFile(ctx, f.Path, data[i], mode); err != nil {
			first = fmt.Errorf("write %s: %w", f.Path, err)
			break
		}
		written++
	}
	post := ""
	if cfg.PostCommand != "" {
		post = "; post: ok"
		// A fresh context: ctx may be what expired, and the post command
		// restores state (for example a read-only root filesystem).
		pctx, pcancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		pstart := time.Now()
		stdout, stderr, code, perr := cl.Run(pctx, cfg.PostCommand)
		record(pctx, "post_deploy", cfg.PostCommand, pstart, stdout, stderr, code, perr)
		pcancel()
		switch {
		case perr != nil:
			perr = fmt.Errorf("postCommand: %w", perr)
		case code != 0:
			perr = fmt.Errorf("postCommand: exit %d: %s", code, sshSnippet(stderr))
		}
		if perr != nil {
			post = "; post: failed"
			if first == nil {
				first = perr
			}
		}
	}
	if first != nil {
		return fail(first)
	}
	return targets.Result{Detail: fmt.Sprintf("%d files written%s", written, post)}, nil
}
