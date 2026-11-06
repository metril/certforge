package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx"
)

// TypeGLKVM is the glkvm deploy target type: a server-run target that writes
// the GL.iNet Comet KVM's nginx certificate and key over SSH. A glkvm_restart action restarts it.
const TypeGLKVM = "glkvm"

const glkvmSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "GL.iNet Comet KVM",
  "description": "Writes the KVM web server's certificate and key over SSH. The root filesystem needs no remount. A glkvm_restart action restarts nginx. Log in as root. Runs on the server.",
  "credentialKinds": ["ssh", "password"],
  "type": "object",
  "additionalProperties": false,
  "required": ["host", "username", "hostKey"],
  "properties": {
    "host": {"type": "string", "title": "Host", "description": "Hostname or IP address of the Comet."},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 22, "title": "Port"},
    "username": {"type": "string", "default": "root", "title": "Username", "description": "Must be root."},
    "password": {"type": "string", "secret": true, "title": "Password", "description": "Password login. Provide a password, a private key, or both."},
    "privateKey": {"type": "string", "format": "private-key", "secret": true, "maxLength": 8192, "title": "Private key", "description": "PEM private key (OpenSSH, PKCS#1 or PKCS#8)."},
    "privateKeyPassphrase": {"type": "string", "secret": true, "maxLength": 1024, "title": "Key passphrase", "description": "Passphrase of the private key, when it is protected."},
    "hostKey": {"type": "string", "format": "ssh-host-key", "maxLength": 2048, "title": "Host key", "description": "Pinned server key: a known_hosts line or '<type> <base64>'. Fetch it from the host below, or run ssh-keyscan -t ed25519 <host>."},
    "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 300, "default": 60, "title": "Timeout (seconds)"}
  }
}`

// GLKVMConfig is a glkvm target's config; Password, PrivateKey and
// PrivateKeyPassphrase are secret.
type GLKVMConfig struct {
	Host                 string `json:"host"`
	Port                 int    `json:"port,omitempty"`
	Username             string `json:"username"`
	Password             string `json:"password,omitempty"`
	PrivateKey           string `json:"privateKey,omitempty"`
	PrivateKeyPassphrase string `json:"privateKeyPassphrase,omitempty"`
	HostKey              string `json:"hostKey"`
	TimeoutSeconds       int    `json:"timeoutSeconds,omitempty"`
}

// GLKVM is the "glkvm" server-run deploy target. Implements targets.Target.
type GLKVM struct{}

// Type implements targets.Target.
func (GLKVM) Type() string { return TypeGLKVM }

// Name implements targets.Target.
func (GLKVM) Name() string { return "GL.iNet Comet KVM" }

// Schema implements targets.Target.
func (GLKVM) Schema() json.RawMessage { return json.RawMessage(glkvmSchema) }

// RunsOn implements targets.Target: always Server.
func (GLKVM) RunsOn() targets.Mode { return targets.Server }

// KeyPolicy implements targets.Target: the private key is always written.
func (GLKVM) KeyPolicy() targets.KeyPolicy { return targets.Always }

// Parse implements targets.Target.
func (t GLKVM) Parse(raw json.RawMessage) (targets.Config, error) {
	var c GLKVMConfig
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
		c.Username = "root"
	}
	if c.Password == "" && c.PrivateKey == "" {
		return bad("password", "a password or a private key is required")
	}
	if fe := checkSSHKey(c.PrivateKey, c.PrivateKeyPassphrase); fe != nil {
		return targets.Config{}, fe
	}
	if _, err := sshx.ParseHostKey(c.HostKey); err != nil {
		return bad("hostKey", "must be a known_hosts line or '<type> <base64>' public key")
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
	return targets.Config{Public: pub, Secrets: secrets, NeedsKey: true, URLs: []string{u}}, nil
}

// Deploy implements targets.Target: write the certificate and key. The
// filesystem is already writable, so there is no remount. It does not restart
// anything; the glkvm_restart action does.
func (GLKVM) Deploy(ctx context.Context, req targets.Request) (targets.Result, error) {
	var c GLKVMConfig
	if err := json.Unmarshal(req.Config, &c); err != nil {
		return targets.Result{}, err
	}
	cfg := SSHConfig{
		Host: c.Host, Port: c.Port, Username: c.Username, Password: c.Password,
		PrivateKey: c.PrivateKey, PrivateKeyPassphrase: c.PrivateKeyPassphrase,
		HostKey: c.HostKey, TimeoutSeconds: c.TimeoutSeconds,
		Files: []SSHFile{
			{Path: "/etc/kvmd/user/ssl/server.crt", Content: "fullchain", Mode: "0644"},
			{Path: "/etc/kvmd/user/ssl/server.key", Content: "key", Mode: "0600"},
		},
	}
	return sshDeploy(ctx, req, cfg, "glkvm")
}
