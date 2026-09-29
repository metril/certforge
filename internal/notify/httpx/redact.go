package httpx

import (
	"net/url"
	"strings"
)

// Redact replaces every non-empty secret in s — along with its
// url.QueryEscape and url.PathEscape forms, so a secret embedded in a
// query string or a URL path is still caught — with "[redacted]". Callers
// (notify.DeliverWorker) pass every secret value a channel config or the
// smtp/prometheus settings ever hold, so a delivery error can never leak
// one into notification_deliveries.last_error or a log line (global
// constraints, Secrets row).
func Redact(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, "[redacted]")
		if esc := url.QueryEscape(secret); esc != secret {
			s = strings.ReplaceAll(s, esc, "[redacted]")
		}
		if esc := url.PathEscape(secret); esc != secret {
			s = strings.ReplaceAll(s, esc, "[redacted]")
		}
	}
	return s
}
