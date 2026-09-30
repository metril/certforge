package targets

import (
	"encoding/base64"
	"unicode/utf8"

	"github.com/metril/certforge/internal/notify/httpx"
)

// Redact returns err's message with every non-empty value of secrets — and
// each one's base64.StdEncoding form, in case the target ever base64-encodes
// a secret into a header or body it later echoes back — replaced with
// "[redacted]" (httpx.Redact itself already covers each value's
// url.QueryEscape and url.PathEscape forms), cut to at most max bytes on a
// UTF-8 boundary. Used wherever a target's own error could echo a secret
// back before it is stored or logged: server_deployments.last_error, a
// deploy.failed payload, an agent report (Global Constraints, Secrets row).
func Redact(err error, secrets map[string]string, max int) string {
	if err == nil {
		return ""
	}
	args := make([]string, 0, len(secrets)*2)
	for _, v := range secrets {
		if v == "" {
			continue
		}
		args = append(args, v, base64.StdEncoding.EncodeToString([]byte(v)))
	}
	return cutUTF8(httpx.Redact(err.Error(), args...), max)
}

// cutUTF8 truncates s to at most max bytes, trimming back further if the
// cut landed inside a multi-byte rune.
func cutUTF8(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	s = s[:max]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
