package challenge

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Method is a verification method. Phase 1 supports dns-01 and manual-dns.
type Method string

const (
	MethodDNS01     Method = "dns-01"
	MethodManualDNS Method = "manual-dns"
)

// RuleSpec is the stored and API form of a verification rule.
type RuleSpec struct {
	Match              string     `json:"match"`
	Method             Method     `json:"method"`
	DNSCredentialID    *uuid.UUID `json:"dnsCredentialId,omitempty"`
	PropagationSeconds *int       `json:"propagationSeconds,omitempty"`
	Resolvers          []string   `json:"resolvers,omitempty"`
	CNAMEAliasZone     string     `json:"cnameAliasZone,omitempty"`
}

// Validate checks a rule in isolation (credential ownership is checked by
// the store).
func (r RuleSpec) Validate() error {
	if _, err := ParseMatch(r.Match); err != nil {
		return err
	}
	switch r.Method {
	case MethodDNS01:
		if r.DNSCredentialID == nil {
			return fmt.Errorf("rule %q: dns-01 needs dnsCredentialId", r.Match)
		}
	case MethodManualDNS:
		if r.DNSCredentialID != nil {
			return fmt.Errorf("rule %q: manual-dns takes no dnsCredentialId", r.Match)
		}
	default:
		return fmt.Errorf("rule %q: method %q is not supported (dns-01, manual-dns)", r.Match, r.Method)
	}
	if r.PropagationSeconds != nil && (*r.PropagationSeconds < 0 || *r.PropagationSeconds > 3600) {
		return fmt.Errorf("rule %q: propagationSeconds must be 0..3600", r.Match)
	}
	if strings.Contains(r.CNAMEAliasZone, "*") {
		return fmt.Errorf("rule %q: cnameAliasZone must be a zone name", r.Match)
	}
	return nil
}
