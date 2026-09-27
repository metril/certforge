package challenge

import (
	"fmt"
	"path"
	"strings"

	"github.com/google/uuid"
)

// Method is a verification method.
type Method string

const (
	MethodDNS01     Method = "dns-01"
	MethodManualDNS Method = "manual-dns"
	MethodHTTP01    Method = "http-01"
	MethodTLSALPN01 Method = "tls-alpn-01"
)

// Type returns the challenge type m uses (manual-dns counts as dns-01: same
// TXT-record mechanism, just operator-confirmed).
func (m Method) Type() Type {
	switch m {
	case MethodHTTP01:
		return HTTP01
	case MethodTLSALPN01:
		return TLSALPN01
	case MethodManualDNS:
		return ManualDNS
	default:
		return DNS01
	}
}

// Via selects who serves an http-01 challenge.
type Via string

const (
	ViaServer Via = "server"
	ViaAgent  Via = "agent"
)

// RuleSpec is the stored and API form of a verification rule.
type RuleSpec struct {
	Match              string     `json:"match"`
	Method             Method     `json:"method"`
	DNSCredentialID    *uuid.UUID `json:"dnsCredentialId,omitempty"`
	PropagationSeconds *int       `json:"propagationSeconds,omitempty"`
	Resolvers          []string   `json:"resolvers,omitempty"`
	CNAMEAliasZone     string     `json:"cnameAliasZone,omitempty"`
	Via                Via        `json:"via,omitempty"`
	ClientID           *uuid.UUID `json:"clientId,omitempty"`
	Webroot            string     `json:"webroot,omitempty"`
}

// EffectiveVia is r.Via, defaulting to ViaServer when unset (http-01 only;
// meaningless for the other methods).
func (r RuleSpec) EffectiveVia() Via {
	if r.Via == "" {
		return ViaServer
	}
	return r.Via
}

// Validate checks a rule in isolation (credential and client ownership are
// checked by the store).
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
	case MethodHTTP01:
		if err := r.forbidDNSOnlyFields(); err != nil {
			return err
		}
		switch r.EffectiveVia() {
		case ViaServer:
			if r.ClientID != nil {
				return fmt.Errorf("rule %q: http-01 via server takes no clientId", r.Match)
			}
			if r.Webroot != "" {
				return fmt.Errorf("rule %q: http-01 via server takes no webroot", r.Match)
			}
		case ViaAgent:
			if r.ClientID == nil {
				return fmt.Errorf("rule %q: http-01 via agent needs clientId", r.Match)
			}
			if r.Webroot != "" {
				if err := cleanWebroot(r.Webroot); err != nil {
					return fmt.Errorf("rule %q: webroot %w", r.Match, err)
				}
			}
		default:
			return fmt.Errorf("rule %q: via must be server or agent", r.Match)
		}
	case MethodTLSALPN01:
		if err := r.forbidDNSOnlyFields(); err != nil {
			return err
		}
		if r.ClientID == nil {
			return fmt.Errorf("rule %q: tls-alpn-01 needs clientId", r.Match)
		}
		if r.Webroot != "" {
			return fmt.Errorf("rule %q: tls-alpn-01 takes no webroot", r.Match)
		}
		if r.Via != "" && r.Via != ViaAgent {
			return fmt.Errorf("rule %q: tls-alpn-01 via must be agent", r.Match)
		}
	default:
		return fmt.Errorf("rule %q: method %q is not supported (dns-01, manual-dns, http-01, tls-alpn-01)", r.Match, r.Method)
	}
	if r.PropagationSeconds != nil && (*r.PropagationSeconds < 0 || *r.PropagationSeconds > 3600) {
		return fmt.Errorf("rule %q: propagationSeconds must be 0..3600", r.Match)
	}
	if strings.Contains(r.CNAMEAliasZone, "*") {
		return fmt.Errorf("rule %q: cnameAliasZone must be a zone name", r.Match)
	}
	return nil
}

// forbidDNSOnlyFields rejects the dns-01-only fields on a rule whose method
// is http-01 or tls-alpn-01.
func (r RuleSpec) forbidDNSOnlyFields() error {
	if r.DNSCredentialID != nil || r.PropagationSeconds != nil || len(r.Resolvers) > 0 || r.CNAMEAliasZone != "" {
		return fmt.Errorf("rule %q: %s takes no dnsCredentialId, propagationSeconds, resolvers or cnameAliasZone", r.Match, r.Method)
	}
	return nil
}

// cleanWebroot accepts only absolute, already-clean paths below / with no
// trailing slash or NUL. Reimplemented here (not internal/delivery.CleanPath)
// because this package must not import internal/delivery.
func cleanWebroot(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("must be an absolute path")
	}
	if p == "/" || strings.ContainsRune(p, 0) || path.Clean(p) != p {
		return fmt.Errorf("must be a clean file path without . or .. segments or a trailing slash")
	}
	return nil
}
