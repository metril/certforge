package notify

import "regexp"

// urlPattern matches an absolute URL (scheme://...) up to the next
// whitespace, quote or closing bracket — the shape *url.Error's own
// Error() embeds (`Put "https://host:8200/v1/...": ...`), which
// vault.Redact leaves untouched (it only scrubs a known token/secretId
// value, never the address itself).
var urlPattern = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>)]+`)

// dialAddrPattern matches net.Dialer's own "dial tcp host:port" error
// shape, which a *url.Error's wrapped cause often carries even after its
// own URL has been redacted (e.g. "dial tcp 10.0.0.5:8200: connect:
// connection refused").
var dialAddrPattern = regexp.MustCompile(`\bdial (tcp4|tcp6|tcp|udp4|udp6|udp) [^\s:]+:\d+`)

// redactURLs strips any embedded absolute URL or dial address from s
// (R10; batch-3 review finding 3): a server-run deploy target's stored
// last_error is a plain string a scan reads back long after the failing
// call returned, with no secret value in hand to match against (unlike
// vault.Redact, which scrubs a token/secretId it still holds) — the target
// address itself, not a credential, is what must never reach an event's
// details.
func redactURLs(s string) string {
	s = urlPattern.ReplaceAllString(s, "<redacted-url>")
	s = dialAddrPattern.ReplaceAllString(s, "dial $1 <redacted-host>")
	return s
}
