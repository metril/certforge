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

// TypePiKVM is the pikvm deploy target type: a server-run target that writes
// kvmd's nginx certificate and key over SSH. A pikvm_restart action restarts it.
const TypePiKVM = "pikvm"

const pikvmSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "PiKVM / GL.iNet Comet",
  "description": "Writes kvmd's nginx certificate and key over SSH. The writes are wrapped in rw/ro (root filesystem read-write, then read-only). A pikvm_restart action restarts kvmd-nginx. Log in as root. Runs on the server.",
  "credentialKinds": ["ssh", "password"],
  "type": "object",
  "additionalProperties": false,
  "required": ["host", "username", "hostKey"],
  "properties": {
    "host": {"type": "string", "title": "Host", "description": "Hostname or IP address of the PiKVM."},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 22, "title": "Port"},
    "username": {"type": "string", "default": "root", "title": "Username", "description": "Must be root."},
    "password": {"type": "string", "secret": true, "title": "Password", "description": "Password login. Provide a password, a private key, or both."},
    "privateKey": {"type": "string", "format": "private-key", "secret": true, "maxLength": 8192, "title": "Private key", "description": "PEM private key (OpenSSH, PKCS#1 or PKCS#8)."},
    "privateKeyPassphrase": {"type": "string", "secret": true, "maxLength": 1024, "title": "Key passphrase", "description": "Passphrase of the private key, when it is protected."},
    "hostKey": {"type": "string", "format": "ssh-host-key", "maxLength": 2048, "title": "Host key", "description": "Pinned server key: a known_hosts line or '<type> <base64>'. Fetch it from the host below, or run ssh-keyscan -t ed25519 <host>."},
    "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 300, "default": 60, "title": "Timeout (seconds)"}
  }
}`

// PiKVMConfig is a pikvm target's config; Password, PrivateKey and
// PrivateKeyPassphrase are secret.
type PiKVMConfig struct {
	Host                 string `json:"host"`
	Port                 int    `json:"port,omitempty"`
	Username             string `json:"username"`
	Password             string `json:"password,omitempty"`
	PrivateKey           string `json:"privateKey,omitempty"`
	PrivateKeyPassphrase string `json:"privateKeyPassphrase,omitempty"`
	HostKey              string `json:"hostKey"`
	TimeoutSeconds       int    `json:"timeoutSeconds,omitempty"`
}

// PiKVM is the "pikvm" server-run deploy target. Implements targets.Target.
type PiKVM struct{}

// Type implements targets.Target.
func (PiKVM) Type() string { return TypePiKVM }

// Name implements targets.Target.
func (PiKVM) Name() string { return "PiKVM / GL.iNet Comet" }

// Schema implements targets.Target.
func (PiKVM) Schema() json.RawMessage { return json.RawMessage(pikvmSchema) }

// RunsOn implements targets.Target: always Server.
func (PiKVM) RunsOn() targets.Mode { return targets.Server }

// KeyPolicy implements targets.Target: the private key is always written.
func (PiKVM) KeyPolicy() targets.KeyPolicy { return targets.Always }

// Parse implements targets.Target.
func (t PiKVM) Parse(raw json.RawMessage) (targets.Config, error) {
	var c PiKVMConfig
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

// Deploy implements targets.Target: remount rw, write the certificate and
// key, then remount ro (always, once connected). It does not restart
// anything; the pikvm_restart action does.
func (PiKVM) Deploy(ctx context.Context, req targets.Request) (targets.Result, error) {
	var c PiKVMConfig
	if err := json.Unmarshal(req.Config, &c); err != nil {
		return targets.Result{}, err
	}
	cfg := SSHConfig{
		Host: c.Host, Port: c.Port, Username: c.Username, Password: c.Password,
		PrivateKey: c.PrivateKey, PrivateKeyPassphrase: c.PrivateKeyPassphrase,
		HostKey: c.HostKey, TimeoutSeconds: c.TimeoutSeconds,
		Files: []SSHFile{
			{Path: "/etc/kvmd/nginx/ssl/server.crt", Content: "fullchain", Mode: "0644"},
			{Path: "/etc/kvmd/nginx/ssl/server.key", Content: "key", Mode: "0600"},
		},
		PreCommand:  "rw",
		PostCommand: "ro",
	}
	return sshDeploy(ctx, req, cfg, "pikvm")
}
