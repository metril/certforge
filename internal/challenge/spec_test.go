package challenge

import (
	"testing"

	"github.com/google/uuid"
)

func TestRuleSpecValidate(t *testing.T) {
	id := uuid.New()
	secs := 7200
	cases := []struct {
		r  RuleSpec
		ok bool
	}{
		{RuleSpec{Match: "example.com", Method: MethodDNS01, DNSCredentialID: &id}, true},
		{RuleSpec{Match: "*", Method: MethodManualDNS}, true},
		{RuleSpec{Match: "example.com", Method: MethodDNS01}, false},
		{RuleSpec{Match: "*", Method: MethodManualDNS, DNSCredentialID: &id}, false},
		{RuleSpec{Match: "example.com", Method: "http-01"}, false},
		{RuleSpec{Match: "a.*.b", Method: MethodManualDNS}, false},
		{RuleSpec{Match: "*", Method: MethodManualDNS, PropagationSeconds: &secs}, false},
	}
	for _, c := range cases {
		if err := c.r.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: err = %v", c.r, err)
		}
	}
}
