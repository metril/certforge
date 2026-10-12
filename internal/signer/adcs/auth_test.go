package adcs

import (
	"errors"
	"testing"
)

func TestAuthErrorMessage(t *testing.T) {
	const lead = "authentication failed"
	fault := &Fault{Subcode: "a:FailedAuthentication", Reason: "At least one security token in the message could not be validated."}
	cases := []struct {
		name string
		err  *AuthError
		want string
	}{
		{"with hint", &AuthError{Detail: fault.text(), Hint: UsernameHint("svc")},
			`authentication failed (FailedAuthentication: At least one security token in the message could not be validated.; use DOMAIN\user or user@domain)`},
		{"without hint", &AuthError{Detail: "http 401", Hint: UsernameHint(`CORP\svc`)}, "authentication failed (http 401)"},
	}
	for _, tc := range cases {
		if got := tc.err.Message(lead); got != tc.want {
			t.Errorf("%s: %q", tc.name, got)
		}
		if !errors.Is(tc.err, ErrAuth) {
			t.Errorf("%s: not ErrAuth", tc.name)
		}
	}
	if UsernameHint("svc@corp.test") != "" || UsernameHint("svc") == "" {
		t.Error("hint rule")
	}
}
