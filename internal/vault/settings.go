// Package vault talks to HashiCorp Vault (or OpenBao): the "vault" global
// settings section, a client for Transit, KV and PKI, and the provider that
// turns those settings into a live client for the Transit KEK and private
// CAs backed by Vault's PKI secrets engine.
package vault

import (
	_ "embed"
	"encoding/json"
	"errors"

	"github.com/metril/certforge/internal/settings"
)

// SectionName is the global settings section holding Vault connection
// details (Shared contract, Settings row).
const SectionName = "vault"

//go:embed vault.schema.json
var settingsSchema []byte

// settingsDefault leaves Vault unconfigured: no address, so
// authMethod/timeoutSeconds are never checked against anything.
const settingsDefault = `{}`

// Settings is the "vault" section: address, authentication and TLS/timeout
// config used to reach Vault or OpenBao.
type Settings struct {
	Address        string `json:"address"`
	Namespace      string `json:"namespace"`
	AuthMethod     string `json:"authMethod"`
	Token          string `json:"token"`
	RoleID         string `json:"roleId"`
	SecretID       string `json:"secretId"`
	CAPem          string `json:"caPem"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

// RegisterSettings adds the vault section and its extra checks.
func RegisterSettings(r *settings.Registry) error {
	if err := r.Register(SectionName, json.RawMessage(settingsSchema), json.RawMessage(settingsDefault)); err != nil {
		return err
	}
	return r.AddCheck(SectionName, checkSettings)
}

// checkSettings enforces the auth-method pairing the schema alone cannot
// express: token requires authMethod token, and roleId/secretId require
// authMethod approle (Shared contract, Settings row). It runs on raw JSON
// before secret fields are split out for storage, so token/roleId/secretId
// are still present here.
func checkSettings(raw json.RawMessage) error {
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	method := s.AuthMethod
	if method == "" {
		method = "token"
	}
	if s.Token != "" && method != "token" {
		return errors.New("token requires authMethod token")
	}
	if (s.RoleID != "" || s.SecretID != "") && method != "approle" {
		return errors.New("roleId and secretId require authMethod approle")
	}
	return nil
}
