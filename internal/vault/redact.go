package vault

import (
	"errors"
	"regexp"
	"strings"
)

// secretPattern catches Vault's own well-known secret-bearing JSON fields
// even when the exact value redactValue looks for is not the one that
// leaked (for example a different token echoed back inside a nested error
// body).
var secretPattern = regexp.MustCompile(`(?i)"(x-vault-token|client_token|secret_id|token)"\s*:\s*"[^"]*"`)

// Redact scrubs c's current token and, for AppRoleAuth, its secretId from
// err's message, so a caller can log or return err without leaking either.
// Every exported Client method runs its error through Redact before
// returning it (Contract: "X-Vault-Token and any secretId must be redacted
// in every error string and never logged").
func (c *Client) Redact(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	redacted := redactValue(msg, c.getToken())
	if a, ok := c.auth.(AppRoleAuth); ok {
		redacted = redactValue(redacted, a.SecretID)
	}
	redacted = secretPattern.ReplaceAllString(redacted, `"$1":"[redacted]"`)
	if redacted == msg {
		return err
	}
	return errors.New(redacted)
}

func redactValue(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[redacted]")
}
