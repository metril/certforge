package vault

import (
	"encoding/json"
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
//
// An *APIError is redacted into a new *APIError with the same Status and
// redacted Errors, not a bare string: callers use errors.As to branch on
// Status (T8/T10/T13), and that must keep working whether or not a secret
// was actually found in the message. Any other error is wrapped in a
// redactedError, which keeps Unwrap so errors.Is/As still see the original
// error's type (e.g. context.Canceled) while Error() only ever returns the
// scrubbed text.
func (c *Client) Redact(err error) error {
	if err == nil {
		return nil
	}

	var apiErr *APIError
	if errors.As(err, &apiErr) {
		errs := make([]string, len(apiErr.Errors))
		changed := false
		for i, e := range apiErr.Errors {
			errs[i] = c.redactString(e)
			changed = changed || errs[i] != e
		}
		if !changed {
			return err
		}
		return &APIError{Status: apiErr.Status, Errors: errs}
	}

	msg := err.Error()
	redacted := c.redactString(msg)
	if redacted == msg {
		return err
	}
	return &redactedError{msg: redacted, cause: err}
}

func (c *Client) redactString(s string) string {
	redacted := redactValue(s, c.getToken())
	if a, ok := c.auth.(AppRoleAuth); ok {
		redacted = redactValue(redacted, a.SecretID)
	}
	return secretPattern.ReplaceAllString(redacted, `"$1":"[redacted]"`)
}

func redactValue(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[redacted]")
}

// redactedError wraps a non-APIError error whose message contained a
// secret: Error() returns the already-scrubbed text, while Unwrap keeps
// errors.Is/As working against the original error's type.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// scrubRaw removes every string value raw holds (its top-level properties,
// whatever they are — token, secretId, roleId, caPem, ...) from msg, on top
// of whatever Client.Redact already caught. Provider.Test uses it so a
// candidate "vault" section value's own secrets never survive into the
// testVaultSettings response even when raw's token/secretId came from a
// caller-supplied value the Client itself never held as c.token/c.auth
// (Contract: "scrubbed of every secret value in raw").
func scrubRaw(msg string, raw json.RawMessage) string {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return msg
	}
	for _, v := range doc {
		var str string
		if err := json.Unmarshal(v, &str); err != nil || str == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, str, "[redacted]")
	}
	return msg
}
