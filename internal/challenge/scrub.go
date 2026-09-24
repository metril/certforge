package challenge

import (
	"net/url"
	"strings"
)

// redacted replaces a scrubbed config value in an error message.
const redacted = "[redacted]"

// Scrub returns an error whose Error() text has every non-empty value in
// cfg replaced with "[redacted]", both as written and url.QueryEscape'd (a
// REST provider commonly reports a failure by echoing the request URL,
// which query-encodes the value). A live DNS provider error can otherwise
// leak a write-only secret back out through an attempt's last_error, an
// audit log, or an API response — none of which are secret-protected the
// way a stored credential's own GET/list/update responses are.
//
// The original error is preserved via Unwrap, so errors.Is/errors.As
// against known sentinels still works; only the displayed message changes.
// Scrub(nil, cfg) returns nil, and an error whose message needed no
// scrubbing is returned unchanged.
func Scrub(err error, cfg map[string]string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	scrubbed := scrubString(msg, cfg)
	if scrubbed == msg {
		return err
	}
	return &scrubbedError{msg: scrubbed, cause: err}
}

// scrubString replaces every non-empty cfg value (raw and
// url.QueryEscape'd) in s with "[redacted]".
func scrubString(s string, cfg map[string]string) string {
	for _, v := range cfg {
		if v == "" {
			continue
		}
		s = strings.ReplaceAll(s, v, redacted)
		if esc := url.QueryEscape(v); esc != v {
			s = strings.ReplaceAll(s, esc, redacted)
		}
	}
	return s
}

// scrubbedError carries a scrubbed display message over an unscrubbed
// cause; errors.Is/errors.As still see the cause via Unwrap.
type scrubbedError struct {
	msg   string
	cause error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.cause }
