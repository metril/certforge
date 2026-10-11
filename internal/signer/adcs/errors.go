package adcs

import (
	"errors"
	"fmt"
)

// ErrAuth means the enrollment service rejected the credentials (HTTP
// 401/403 or an authentication SOAP fault).
var ErrAuth = errors.New("adcs: authentication failed")

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
	return fmt.Sprintf("adcs: request %s is pending approval", e.RequestID)
}

// ErrDenied means the CA refused the request.
type ErrDenied struct {
	// Disposition is the CA's disposition message.
	Disposition string
}

// Error implements error.
func (e ErrDenied) Error() string {
	return "adcs: request denied: " + e.Disposition
}
