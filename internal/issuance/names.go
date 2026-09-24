package issuance

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeNames validates and de-duplicates certificate names. The common
// name comes first. Wildcards are allowed only as the whole leftmost label.
func NormalizeNames(commonName string, sans []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range append([]string{commonName}, sans...) {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if n == "" {
			continue
		}
		if err := validName(n); err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one name is required")
	}
	if len(out) > 100 {
		return nil, fmt.Errorf("at most 100 names per certificate")
	}
	return out, nil
}

func validName(n string) error {
	if net.ParseIP(n) != nil {
		return nil
	}
	base := strings.TrimPrefix(n, "*.")
	if strings.Contains(base, "*") {
		return fmt.Errorf("%q: '*' is only allowed as the whole leftmost label", n)
	}
	if len(base) > 253 || !strings.Contains(base, ".") {
		return fmt.Errorf("%q is not a fully qualified domain name", n)
	}
	for _, label := range strings.Split(base, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q has an invalid label %q", n, label)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("%q has an invalid character %q", n, c)
			}
		}
	}
	return nil
}
