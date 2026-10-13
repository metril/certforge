package actions

import "strings"

// Vars are the values the template placeholders expand to.
type Vars struct {
	CertName, CertFingerprint, CertNotAfter, GrantID string
}

// ExpandTemplate replaces exactly {{cert.name}}, {{cert.fingerprint}},
// {{cert.notAfter}} and {{grant.id}} in s; any other text, including other
// {{...}} placeholders, is left as is. Replaced values are not rescanned.
func ExpandTemplate(s string, v Vars) string {
	return strings.NewReplacer(
		"{{cert.name}}", v.CertName,
		"{{cert.fingerprint}}", v.CertFingerprint,
		"{{cert.notAfter}}", v.CertNotAfter,
		"{{grant.id}}", v.GrantID,
	).Replace(s)
}
