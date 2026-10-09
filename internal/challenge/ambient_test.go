package challenge

import (
	"errors"
	"testing"
)

func TestCheckNoAmbient(t *testing.T) {
	cases := []struct {
		name   string
		code   string
		public map[string]string
		secret map[string]string
		bad    bool
	}{
		{"route53 ambient", "route53", map[string]string{}, map[string]string{}, true},
		{"route53 keys", "route53", map[string]string{}, map[string]string{"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b"}, false},
		{"route53 keys + assume role", "route53", map[string]string{"AWS_ASSUME_ROLE_ARN": "arn:aws:iam::1:role/x"}, map[string]string{"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b"}, true},
		{"route53 keys + profile", "route53", map[string]string{"AWS_PROFILE": "p"}, map[string]string{"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b"}, true},
		{"cloudflare token", "cloudflare", map[string]string{}, map[string]string{"CF_DNS_API_TOKEN": "t"}, false},
	}
	for _, c := range cases {
		err := CheckNoAmbient(c.code, c.public, c.secret)
		if c.bad != errors.Is(err, ErrAmbientCredentials) {
			t.Errorf("%s: err=%v want bad=%v", c.name, err, c.bad)
		}
	}
}
