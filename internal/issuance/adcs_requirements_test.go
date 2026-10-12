package issuance

import (
	"testing"

	"github.com/metril/certforge/internal/signer/adcs"
)

func TestADCSRequirements(t *testing.T) {
	good := adcs.Template{Name: "T", CanEnroll: true, SubjectFlags: 1, KeyAlgorithm: "ECDSA_P384"}
	cases := []struct {
		name     string
		mod      func(*adcs.Template)
		key      string
		blocking bool
	}{
		{"enroll", func(t *adcs.Template) { t.CanEnroll = false }, "enroll", true},
		{"approval", func(t *adcs.Template) { t.EnrollmentFlags = adcs.FlagPendAllRequests }, "approval", true},
		{"signatures", func(t *adcs.Template) { t.RASignatures = 1 }, "signatures", true},
		{"subject", func(t *adcs.Template) { t.SubjectFlags = 0 }, "subject", true},
		{"serverAuth", func(t *adcs.Template) { t.EKUs = []string{"1.3.6.1.5.5.7.3.2"} }, "serverAuth", false},
		{"keyAlgorithm", func(t *adcs.Template) { t.KeyAlgorithm = "RSA" }, "keyAlgorithm", false},
	}
	for _, r := range adcsRequirements(&good) {
		if !r.OK {
			t.Errorf("good template fails %s", r.Key)
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tpl := good
			c.mod(&tpl)
			var found bool
			for _, r := range adcsRequirements(&tpl) {
				if r.Key == c.key {
					found = true
					if r.OK || r.Blocking != c.blocking || r.Fix == "" || r.Label == "" {
						t.Errorf("requirement = %+v", r)
					}
				} else if r.Key != "keyAlgorithm" && !r.OK {
					t.Errorf("unexpected failure %s", r.Key)
				}
			}
			if !found {
				t.Fatalf("requirement %s missing", c.key)
			}
			_, err := usableADCSTemplate(&adcs.PolicyResult{Templates: []adcs.Template{tpl}}, "T")
			if c.blocking != (err != nil) {
				t.Errorf("usable err = %v, blocking = %v", err, c.blocking)
			}
		})
	}
}
