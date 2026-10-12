package adcs

import (
	"errors"
	"fmt"
	"strings"
)

// ErrAuth means the enrollment service rejected the credentials (HTTP
// 401/403 or an authentication SOAP fault).
var ErrAuth = errors.New("adcs: authentication failed")

// AuthError is the typed form of ErrAuth: Detail is what the server said
// (an HTTP status or a SOAP fault such as "FailedAuthentication: ...") and
// Hint is set when the username looks like it is in the wrong format. It
// never contains the password.
type AuthError struct {
	Detail, Hint string
}

// Error implements error.
func (e *AuthError) Error() string { return e.Message("adcs: authentication failed") }

// Unwrap makes errors.Is(err, ErrAuth) hold.
func (e *AuthError) Unwrap() error { return ErrAuth }

// Message is lead followed by the detail and hint in parentheses.
func (e *AuthError) Message(lead string) string {
	parts := make([]string, 0, 2)
	if e.Detail != "" {
		parts = append(parts, e.Detail)
	}
	if e.Hint != "" {
		parts = append(parts, e.Hint)
	}
	if len(parts) == 0 {
		return lead
	}
	return lead + " (" + strings.Join(parts, "; ") + ")"
}

// UsernameHint is the hint for a username with neither a domain prefix nor
// a UPN suffix, or "" when its format is fine.
func UsernameHint(username string) string {
	if strings.ContainsAny(username, `\@`) {
		return ""
	}
	return `use DOMAIN\user or user@domain`
}

// ErrTemplateUnknown means the enrollment policy does not publish the
// configured certificate template.
var ErrTemplateUnknown = errors.New("adcs: template not found in enrollment policy")

// ErrPending means the CA took the request under submission (the template
// requires CA-manager approval). Approve RequestID in AD CS, then renew.
type ErrPending struct {
	// RequestID is the CA's request id for the pending request.
	RequestID string
}

// Error implements error.
func (e ErrPending) Error() string {
	return fmt.Sprintf("request %s is pending CA manager approval", e.RequestID)
}

// ErrDenied means the CA refused the request.
type ErrDenied struct {
	// Disposition is the CA's disposition message.
	Disposition string
}

// Error implements error.
func (e ErrDenied) Error() string {
	return e.Disposition
}

// ErrKeyTooSmall means the requested key is below the template's minimum
// key length; it is reported before any enrollment request is sent.
var ErrKeyTooSmall = errors.New("adcs: key below template minimum size")

// keyTooSmallError carries the user-facing message and matches ErrKeyTooSmall.
type keyTooSmallError struct{ msg string }

func (e keyTooSmallError) Error() string { return e.msg }
func (e keyTooSmallError) Unwrap() error { return ErrKeyTooSmall }
