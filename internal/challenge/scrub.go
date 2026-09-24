package challenge

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// redacted replaces a scrubbed config value in an error message.
const redacted = "[redacted]"

// minNonSecretScrubLen is the shortest non-secret value Scrub will redact.
// A short generic value (a propagation-seconds "2", a TTL "60") is common
// enough as an ordinary substring of unrelated message text that redacting
// it unconditionally does more harm (mangled, misleading error text) than
// good; a field the provider schema marks secret: true is always redacted
// regardless of length, since leaking any amount of it is the failure mode
// this exists to prevent.
const minNonSecretScrubLen = 4

// Scrub returns an error whose Error() text has every value in cfg that is
// worth redacting (see buildScrubList) replaced with "[redacted]", in each
// of four forms: as written, url.QueryEscape'd, url.PathEscape'd, and as it
// would appear inside a JSON string (strconv.Quote's escaping, without the
// surrounding quotes, so a message that echoes a backslash-escaped value
// still matches). A live DNS provider error can otherwise leak a
// write-only secret back out through an attempt's last_error, an audit
// log, or an API response — none of which are secret-protected the way a
// stored credential's own GET/list/update responses are.
//
// Values are applied longest first (ties broken by field name), not in cfg's
// (random) map order: replacing a short value first can land inside a
// longer value that contains it as a substring, splitting it into
// fragments that no longer match when Scrub gets to the longer value —
// found in practice as a short field's value (for example a
// single-digit polling interval) fragmenting an unrelated secret that
// happened to contain the same digit.
//
// The original error is preserved via Unwrap, so errors.Is/errors.As
// against known sentinels still works; only the displayed message changes.
// Scrub(nil, code, cfg) returns nil, and an error whose message needed no
// scrubbing is returned unchanged.
func Scrub(err error, code string, cfg map[string]string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	scrubbed := msg
	for _, sv := range buildScrubList(code, cfg) {
		scrubbed = replaceAllForms(scrubbed, sv.value)
	}
	if scrubbed == msg {
		return err
	}
	return &scrubbedError{msg: scrubbed, cause: err}
}

// scrubValue is one cfg entry worth redacting.
type scrubValue struct {
	key, value string
}

// buildScrubList returns cfg's values worth redacting, longest first (ties
// broken by key), for a deterministic replacement order regardless of Go's
// randomized map iteration order. Every field the provider schema (code)
// marks secret: true is included regardless of length; any other field is
// included only when its value is at least minNonSecretScrubLen
// characters. An unknown code or empty value is skipped rather than
// erroring: Scrub is a best-effort defense applied to arbitrary error
// text, not a validating parse.
func buildScrubList(code string, cfg map[string]string) []scrubValue {
	e, _ := lookupEntry(code)
	list := make([]scrubValue, 0, len(cfg))
	for k, v := range cfg {
		if v == "" {
			continue
		}
		secret := e != nil && e.secret[k]
		if !secret && len(v) < minNonSecretScrubLen {
			continue
		}
		list = append(list, scrubValue{key: k, value: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if len(list[i].value) != len(list[j].value) {
			return len(list[i].value) > len(list[j].value)
		}
		return list[i].key < list[j].key
	})
	return list
}

// replaceAllForms replaces every occurrence of v in s, and of its
// url.QueryEscape, url.PathEscape, and JSON-string-escaped forms, with
// "[redacted]".
func replaceAllForms(s, v string) string {
	s = strings.ReplaceAll(s, v, redacted)
	if esc := url.QueryEscape(v); esc != v {
		s = strings.ReplaceAll(s, esc, redacted)
	}
	if esc := url.PathEscape(v); esc != v {
		s = strings.ReplaceAll(s, esc, redacted)
	}
	if esc := jsonEscaped(v); esc != v {
		s = strings.ReplaceAll(s, esc, redacted)
	}
	return s
}

// jsonEscaped returns v as it would appear between the quotes of a JSON
// string: strconv.Quote produces the same backslash escaping JSON uses for
// the characters that need it (", \, control characters), so stripping its
// surrounding quotes gives the JSON-string-inner form without a second
// escaping implementation to keep in sync.
func jsonEscaped(v string) string {
	q := strconv.Quote(v)
	return q[1 : len(q)-1]
}

// scrubbedError carries a scrubbed display message over an unscrubbed
// cause; errors.Is/errors.As still see the cause via Unwrap.
type scrubbedError struct {
	msg   string
	cause error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.cause }
