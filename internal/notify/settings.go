// Package notify delivers CertForge events (certificate issuance and
// renewal failure, expiry, deployment problems, client and agent health,
// external monitor state changes, and backup outcomes) to configured
// notification channels: webhook, email, Discord, ntfy and Home Assistant
// (Shared contracts, Channel/Event operations rows). This file adds the
// "smtp" and "notifications" global settings sections (Shared contract,
// Settings row); the event model, emitter, delivery worker and the
// notifiers themselves land in later Phase 6A tasks.
package notify

import (
	_ "embed"
	"encoding/json"
	"errors"

	"github.com/metril/certforge/internal/settings"
)

// SMTPSectionName is the global settings section holding the SMTP server
// CertForge uses to deliver email notification channels (Shared contract).
const SMTPSectionName = "smtp"

//go:embed smtp.schema.json
var smtpSchema []byte

// smtpSettingsDefault leaves SMTP unconfigured (no host, so from/username
// are never checked against anything) beyond the schema's own defaults.
const smtpSettingsDefault = `{"port":587,"security":"starttls","timeoutSeconds":10}`

// SMTPSettings is the "smtp" section: the server CertForge authenticates to
// and sends mail through for email notification channels.
type SMTPSettings struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	From           string `json:"from"`
	Security       string `json:"security"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

// SectionName is the global settings section holding notification behaviour
// shared across every channel (Shared contract).
const SectionName = "notifications"

//go:embed notifications.schema.json
var notificationsSchema []byte

const notificationsSettingsDefault = `{"allowLoopbackUrls":false,"expiryWarningDays":7,"failureThreshold":3}`

// Settings is the "notifications" section.
type Settings struct {
	AllowLoopbackURLs bool `json:"allowLoopbackUrls"`
	ExpiryWarningDays int  `json:"expiryWarningDays"`
	FailureThreshold  int  `json:"failureThreshold"`
}

// RegisterSettings adds the "smtp" and "notifications" sections and the
// smtp section's extra checks.
func RegisterSettings(r *settings.Registry) error {
	if err := r.Register(SMTPSectionName, json.RawMessage(smtpSchema), json.RawMessage(smtpSettingsDefault)); err != nil {
		return err
	}
	if err := r.AddCheck(SMTPSectionName, checkSMTPSettings); err != nil {
		return err
	}
	if err := r.AddUpdateCheck(SMTPSectionName, checkSMTPReentry); err != nil {
		return err
	}
	return r.Register(SectionName, json.RawMessage(notificationsSchema), json.RawMessage(notificationsSettingsDefault))
}

// checkSMTPSettings enforces the auth/security pairing the schema alone
// cannot express: a username requires a connection secured by TLS, so
// credentials are never sent over a plaintext session (Shared contract,
// Settings row).
func checkSMTPSettings(raw json.RawMessage) error {
	var s SMTPSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	security := s.Security
	if security == "" {
		security = "starttls"
	}
	if s.Username != "" && security == "none" {
		return errors.New("authentication requires TLS")
	}
	return nil
}

// checkSMTPReentry enforces the re-entry rule (Shared contract, Settings
// row; pre-flight ruling; same pattern as vault.checkReentry): changing host
// or port must re-send the password, since a stored password may no longer
// be valid — or may leak — against a different server. stored is nil on the
// section's first save, which is always allowed.
func checkSMTPReentry(stored, next json.RawMessage) error {
	if stored == nil {
		return nil
	}
	var prev, cur SMTPSettings
	if err := json.Unmarshal(stored, &prev); err != nil {
		return err
	}
	if err := json.Unmarshal(next, &cur); err != nil {
		return err
	}
	if prev.Host == cur.Host && prev.Port == cur.Port {
		return nil
	}
	if cur.Password == "" || cur.Password == settings.Unchanged {
		return errors.New("re-enter the password")
	}
	return nil
}
