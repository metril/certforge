package issuance

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
)

// TestValidateWildcardMethodRejectsHTTP01: a certificate whose own rules
// route a wildcard SAN to http-01 is rejected at create/update time (before
// the store's own DB-backed checks), not only once an issuance attempt
// later builds the real Router (challenge.Router.Validate).
func TestValidateWildcardMethodRejectsHTTP01(t *testing.T) {
	in := CertInput{
		CommonName: "example.com",
		SANs:       []string{"*.example.com"},
		Rules:      []challenge.RuleSpec{{Match: "*.example.com", Method: challenge.MethodHTTP01}},
	}
	err := validateWildcardMethods(in)
	if err == nil {
		t.Fatal("want error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "verificationRules" {
		t.Fatalf("err = %v, want a verificationRules ValidationError", err)
	}
	if !strings.Contains(err.Error(), "*.example.com") {
		t.Fatalf("err = %v, want it to name the wildcard SAN", err)
	}
}

// TestValidateWildcardMethodAllowsDNS01: the same shape, but the wildcard
// name is (correctly) routed to dns-01.
func TestValidateWildcardMethodAllowsDNS01(t *testing.T) {
	id := uuid.New()
	in := CertInput{
		CommonName: "example.com",
		SANs:       []string{"*.example.com"},
		Rules:      []challenge.RuleSpec{{Match: "*.example.com", Method: challenge.MethodDNS01, DNSCredentialID: &id}},
	}
	if err := validateWildcardMethods(in); err != nil {
		t.Fatalf("err = %v", err)
	}
}

// TestValidateWildcardMethodSkipsUnmatchedWildcard: a wildcard SAN that no
// cert-level rule (own or cert-level override) matches is not flagged here
// — it may still be covered by an org/global catch-all rule, which is only
// known at issuance time (worker.buildRouter builds the real Router there).
func TestValidateWildcardMethodSkipsUnmatchedWildcard(t *testing.T) {
	in := CertInput{
		CommonName: "example.com",
		SANs:       []string{"*.example.com"},
		Rules:      []challenge.RuleSpec{{Match: "other.example.net", Method: challenge.MethodHTTP01}},
	}
	if err := validateWildcardMethods(in); err != nil {
		t.Fatalf("err = %v, want nil (deferred to issuance time)", err)
	}
}

// TestValidateWildcardMethodChecksOverrideRules: a cert-level override
// catch-all counts too (worker.buildRouter appends eff.VerificationRules
// after the cert's own rules the same way).
func TestValidateWildcardMethodChecksOverrideRules(t *testing.T) {
	catchAll := []challenge.RuleSpec{{Match: "*", Method: challenge.MethodTLSALPN01, ClientID: func() *uuid.UUID { id := uuid.New(); return &id }()}}
	in := CertInput{
		CommonName: "example.com",
		SANs:       []string{"*.example.com"},
		Overrides:  Defaults{VerificationRules: &catchAll},
	}
	err := validateWildcardMethods(in)
	if err == nil {
		t.Fatal("want error")
	}
}

// TestValidateWildcardMethodAcceptsOrderedRules (fix round 1, controller
// ruling + Important finding 3): an apex rule using http-01 listed first, a
// wildcard rule using dns-01 listed second — the same shape and order
// task-6-brief.md's TestRouterMixedApexWildcard uses at the Router level.
// The apex rule's zone matcher also matches the wildcard name (matchZone
// matches wildcards below its zone), but per the controller ruling a
// wildcard name skips an http-01/tls-alpn-01 match and tries the next rule,
// so this must be accepted (no error), matching what Router.Validate would
// conclude for the same rule list.
func TestValidateWildcardMethodAcceptsOrderedRules(t *testing.T) {
	id := uuid.New()
	in := CertInput{
		CommonName: "example.com",
		SANs:       []string{"*.example.com"},
		Rules: []challenge.RuleSpec{
			{Match: "example.com", Method: challenge.MethodHTTP01},
			{Match: "*.example.com", Method: challenge.MethodDNS01, DNSCredentialID: &id},
		},
	}
	if err := validateWildcardMethods(in); err != nil {
		t.Fatalf("err = %v, want nil (the wildcard rule after the apex http-01 rule resolves it)", err)
	}
}
