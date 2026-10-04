package challenge

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

type matchKind int

const (
	matchAll      matchKind = iota // "*"
	matchWildcard                  // "*.example.com"
	matchZone                      // "example.com"
)

// Matcher is a parsed VerificationRule.match pattern. The web UI mirrors
// these semantics (plan 1C matchRule); keep the two in step.
//
//   - "*" matches every name.
//   - "*.zone" matches names exactly one label below zone, and the wildcard
//     name "*.zone" itself (the names a "*.zone" certificate covers).
//   - "zone" matches zone, every name below it, and wildcards below it.
type Matcher struct {
	kind matchKind
	zone string
	raw  string
}

// ParseMatch parses "*", "*.zone" or "zone".
func ParseMatch(s string) (Matcher, error) {
	raw := s
	s = normalize(s)
	switch {
	case s == "":
		return Matcher{}, fmt.Errorf("empty match pattern")
	case s == "*":
		return Matcher{kind: matchAll, raw: raw}, nil
	case strings.HasPrefix(s, "*."):
		z := s[2:]
		if err := validZone(z); err != nil {
			return Matcher{}, fmt.Errorf("invalid match %q: %w", raw, err)
		}
		return Matcher{kind: matchWildcard, zone: z, raw: raw}, nil
	default:
		if err := validZone(s); err != nil {
			return Matcher{}, fmt.Errorf("invalid match %q: %w", raw, err)
		}
		return Matcher{kind: matchZone, zone: s, raw: raw}, nil
	}
}

func validZone(z string) error {
	if z == "" {
		return fmt.Errorf("missing zone")
	}
	for _, label := range strings.Split(z, ".") {
		if label == "" {
			return fmt.Errorf("empty label")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return fmt.Errorf("'*' is only allowed as the leftmost label, and names use letters, digits, '-' and '_'")
			}
		}
	}
	return nil
}

// String returns the pattern as written.
func (m Matcher) String() string { return m.raw }

// Matches reports whether certificate name (possibly "*.x") matches.
func (m Matcher) Matches(name string) bool {
	name = normalize(name)
	switch m.kind {
	case matchAll:
		return true
	case matchWildcard:
		if strings.HasPrefix(name, "*.") {
			return name == "*."+m.zone
		}
		rest, ok := strings.CutSuffix(name, "."+m.zone)
		return ok && rest != "" && !strings.Contains(rest, ".")
	default:
		base := strings.TrimPrefix(name, "*.")
		return base == m.zone || strings.HasSuffix(base, "."+m.zone)
	}
}

// normalize lowercases, strips a trailing dot, and converts a Unicode
// (U-label) name or zone to its ASCII (A-label/"xn--...") form via IDNA, so
// a U-label certificate name compares equal to the ASCII form a match
// pattern is written in. Input IDNA rejects ("*", a malformed label, ...)
// falls through unconverted; validZone reports the real error for patterns,
// and an unconverted name simply fails to match, as before.
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || s == "*" {
		return s
	}
	zone, wildcard := s, false
	if strings.HasPrefix(s, "*.") {
		zone, wildcard = s[2:], true
	}
	ascii, err := idna.Lookup.ToASCII(zone)
	if err != nil {
		return s
	}
	if wildcard {
		return "*." + ascii
	}
	return ascii
}
