package authn

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metril/certforge/internal/settings"
)

func TestClientIP(t *testing.T) {
	trusted := AuthSettings{TrustedProxies: []string{"10.0.0.0/8", "fd00::/8"}}
	trusted.normalize()
	cases := []struct {
		name, remote string
		xff          []string
		st           AuthSettings
		want         string
	}{
		{"no proxies ignores xff", "203.0.113.5:1234", []string{"1.2.3.4"}, AuthSettings{}, "203.0.113.5"},
		{"untrusted remote ignores xff", "203.0.113.5:1234", []string{"10.0.0.1"}, trusted, "203.0.113.5"},
		{"one trusted hop", "10.0.0.2:1", []string{"198.51.100.7"}, trusted, "198.51.100.7"},
		{"skips trusted hops", "10.0.0.2:1", []string{"198.51.100.7, 10.0.0.9"}, trusted, "198.51.100.7"},
		{"spoofed leftmost ignored", "10.0.0.2:1", []string{"1.1.1.1, 198.51.100.7"}, trusted, "198.51.100.7"},
		{"split headers", "10.0.0.2:1", []string{"198.51.100.7", "10.0.0.9"}, trusted, "198.51.100.7"},
		{"garbage hop stops walk", "10.0.0.2:1", []string{"garbage"}, trusted, "10.0.0.2"},
		{"all trusted gives leftmost", "10.0.0.2:1", []string{"10.0.0.3"}, trusted, "10.0.0.3"},
		{"no xff", "10.0.0.2:1", nil, trusted, "10.0.0.2"},
		{"ipv4-mapped remote", "[::ffff:10.0.0.2]:1", []string{"198.51.100.7"}, trusted, "198.51.100.7"},
		{"ipv6 proxy", "[fd00::1]:1", []string{"2001:db8::7"}, trusted, "2001:db8::7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := tc.st.ClientIP(r); got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthSettingsCheck(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.Section(SettingsSection)
	if keys := sec.SecretKeys(); len(keys) != 1 || keys[0] != "clientSecret" {
		t.Fatalf("secret keys %v", keys)
	}
	for _, bad := range []string{
		`{"enabled":true}`,
		`{"enabled":true,"issuer":"https://idp.test","clientId":"c","scopes":["profile"]}`,
		`{"trustedProxies":["10.0.0.0/33"]}`,
		`{"trustedProxies":["proxy.local"]}`,
		`{"sessionTtlHours":0}`,
	} {
		if err := sec.Validate([]byte(bad)); !errors.Is(err, settings.ErrInvalid) {
			t.Fatalf("%s accepted: %v", bad, err)
		}
	}
	ok := `{"enabled":true,"issuer":"https://idp.test","clientId":"c","clientSecret":"s","scopes":["openid","email"],"trustedProxies":["10.0.0.1","fd00::/8"]}`
	if err := sec.Validate([]byte(ok)); err != nil {
		t.Fatal(err)
	}
}

func TestAuthSettingsDefaults(t *testing.T) {
	var st AuthSettings
	if err := json.Unmarshal([]byte(`{}`), &st); err != nil {
		t.Fatal(err)
	}
	st.normalize()
	if st.SessionTTL() != 12*time.Hour || st.GroupsClaim != "groups" || len(st.Scopes) != 4 || st.OIDCReady() {
		t.Fatalf("defaults %+v", st)
	}
}
