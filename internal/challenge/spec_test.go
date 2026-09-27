package challenge

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestRuleSpecValidateMethods covers RuleSpec.Validate for all four methods
// (task-6-brief.md "Rules"): dns-01 and manual-dns behave as before;
// http-01 (via server/agent, webroot) and tls-alpn-01 (agent-only) are new.
func TestRuleSpecValidateMethods(t *testing.T) {
	id := uuid.New()
	secs := 7200
	cases := []struct {
		name string
		r    RuleSpec
		ok   bool
	}{
		{"dns-01 with credential", RuleSpec{Match: "example.com", Method: MethodDNS01, DNSCredentialID: &id}, true},
		{"dns-01 without credential", RuleSpec{Match: "example.com", Method: MethodDNS01}, false},
		{"manual-dns catch-all", RuleSpec{Match: "*", Method: MethodManualDNS}, true},
		{"manual-dns with credential", RuleSpec{Match: "*", Method: MethodManualDNS, DNSCredentialID: &id}, false},
		{"manual-dns with propagationSeconds", RuleSpec{Match: "*", Method: MethodManualDNS, PropagationSeconds: &secs}, false},
		{"bad match pattern", RuleSpec{Match: "a.*.b", Method: MethodManualDNS}, false},
		{"unsupported method", RuleSpec{Match: "example.com", Method: "carrier-pigeon"}, false},

		{"http-01 default via server", RuleSpec{Match: "example.com", Method: MethodHTTP01}, true},
		{"http-01 via server explicit", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaServer}, true},
		{"http-01 via server forbids clientId", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaServer, ClientID: &id}, false},
		{"http-01 via server forbids webroot", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaServer, Webroot: "/var/www"}, false},
		{"http-01 via agent needs clientId", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaAgent}, false},
		{"http-01 via agent with clientId", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaAgent, ClientID: &id}, true},
		{"http-01 via agent with absolute webroot", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaAgent, ClientID: &id, Webroot: "/var/www/html"}, true},
		{"http-01 via agent with relative webroot", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaAgent, ClientID: &id, Webroot: "var/www"}, false},
		{"http-01 via agent with unclean webroot", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaAgent, ClientID: &id, Webroot: "/var/www/../html"}, false},
		{"http-01 via agent with trailing slash webroot", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: ViaAgent, ClientID: &id, Webroot: "/var/www/"}, false},
		{"http-01 bad via", RuleSpec{Match: "example.com", Method: MethodHTTP01, Via: "carrier-pigeon"}, false},
		{"http-01 forbids dnsCredentialId", RuleSpec{Match: "example.com", Method: MethodHTTP01, DNSCredentialID: &id}, false},
		{"http-01 forbids propagationSeconds", RuleSpec{Match: "example.com", Method: MethodHTTP01, PropagationSeconds: &secs}, false},
		{"http-01 forbids resolvers", RuleSpec{Match: "example.com", Method: MethodHTTP01, Resolvers: []string{"1.1.1.1"}}, false},
		{"http-01 forbids cnameAliasZone", RuleSpec{Match: "example.com", Method: MethodHTTP01, CNAMEAliasZone: "alias.example.net"}, false},

		{"tls-alpn-01 needs clientId", RuleSpec{Match: "example.com", Method: MethodTLSALPN01}, false},
		{"tls-alpn-01 with clientId", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id}, true},
		{"tls-alpn-01 via absent", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id, Via: ""}, true},
		{"tls-alpn-01 via agent", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id, Via: ViaAgent}, true},
		{"tls-alpn-01 via server", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id, Via: ViaServer}, true},
		{"tls-alpn-01 forbids webroot", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id, Webroot: "/var/www"}, false},
		{"tls-alpn-01 forbids dnsCredentialId", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id, DNSCredentialID: &id}, false},
		{"tls-alpn-01 forbids propagationSeconds", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id, PropagationSeconds: &secs}, false},
		{"tls-alpn-01 forbids resolvers", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id, Resolvers: []string{"1.1.1.1"}}, false},
		{"tls-alpn-01 forbids cnameAliasZone", RuleSpec{Match: "example.com", Method: MethodTLSALPN01, ClientID: &id, CNAMEAliasZone: "alias.example.net"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.r.Validate()
			if (err == nil) != c.ok {
				t.Errorf("%+v: err = %v", c.r, err)
			}
		})
	}
}

// TestRuleSpecValidateMethodErrorListsAll checks the unsupported-method
// error names every supported method, so an operator sees the full set
// rather than just the two Phase 1 ones.
func TestRuleSpecValidateMethodErrorListsAll(t *testing.T) {
	err := RuleSpec{Match: "example.com", Method: "nope"}.Validate()
	if err == nil {
		t.Fatal("want error")
	}
	for _, m := range []string{"dns-01", "manual-dns", "http-01", "tls-alpn-01"} {
		if !strings.Contains(err.Error(), m) {
			t.Errorf("error %q missing method %q", err.Error(), m)
		}
	}
}
