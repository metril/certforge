package challenge

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestSplitConfig(t *testing.T) {
	pub, sec, err := SplitConfig("cloudflare", map[string]string{
		"CF_API_EMAIL": "ops@example.com", "CF_DNS_API_TOKEN": "tok", "CF_ZONE_API_TOKEN": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pub["CF_API_EMAIL"] != "ops@example.com" || sec["CF_DNS_API_TOKEN"] != "tok" || len(pub)+len(sec) != 2 {
		t.Fatalf("pub=%v sec=%v", pub, sec)
	}
	if _, _, err := SplitConfig("cloudflare", map[string]string{"LD_PRELOAD": "/tmp/x.so"}); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, _, err := SplitConfig("cloudflare", map[string]string{"CF_DNS_API_TOKEN": Unchanged}); err == nil {
		t.Fatal("sentinel on create must fail")
	}
}

// Review Focus (fix round 1, item 4): a _FILE/_PATH config value names a
// path on the server's own filesystem, not something a caller can supply.
func TestSplitConfigRejectsServerPath(t *testing.T) {
	if _, _, err := SplitConfig("gcloud", map[string]string{"GCE_SERVICE_ACCOUNT_FILE": "/etc/secrets/gcloud.json"}); !errors.Is(err, ErrServerPath) {
		t.Fatalf("server path field: %v", err)
	}
	// Empty is dropped like any other empty value, not rejected.
	if _, _, err := SplitConfig("gcloud", map[string]string{"GCE_SERVICE_ACCOUNT_FILE": ""}); err != nil {
		t.Fatalf("empty server path field: %v", err)
	}
}

// Review Focus: a NUL byte in a config value would corrupt the encrypted
// blob and any C-string boundary lego or the OS environment relies on.
func TestSplitConfigRejectsNULByte(t *testing.T) {
	_, _, err := SplitConfig("cloudflare", map[string]string{"CF_DNS_API_TOKEN": "tok\x00en"})
	if err == nil {
		t.Fatal("want error for NUL byte in value")
	}
}

func TestMergeUpdateUnchangedSentinel(t *testing.T) {
	oldPublic := map[string]string{"CF_API_EMAIL": "old@example.com"}
	oldSecret := map[string]string{"CF_DNS_API_TOKEN": "old-token", "CF_ZONE_API_TOKEN": "old-zone"}
	pub, sec, changed, reused, err := MergeUpdate("cloudflare", oldPublic, oldSecret, map[string]string{
		"CF_API_EMAIL": "new@example.com", "CF_DNS_API_TOKEN": Unchanged, // keep
		// CF_ZONE_API_TOKEN omitted: removed
		"CF_API_KEY": Unchanged, // never stored: dropped
	})
	if err != nil {
		t.Fatal(err)
	}
	if sec["CF_DNS_API_TOKEN"] != "old-token" || len(sec) != 1 || pub["CF_API_EMAIL"] != "new@example.com" {
		t.Fatalf("pub=%v sec=%v", pub, sec)
	}
	if got := SecretKeys(sec); len(got) != 1 || got[0] != "CF_DNS_API_TOKEN" {
		t.Fatalf("SecretKeys = %v", got)
	}
	if len(changed) != 1 || changed[0] != "CF_API_EMAIL" {
		t.Fatalf("changedPublic = %v", changed)
	}
	if !reused {
		t.Fatal("reusedSecret should be true: CF_DNS_API_TOKEN was sent as Unchanged")
	}
}

// Review Focus (fix wave item 4): a secret update alongside a public change
// that never touches a secret field must not be reported as reusing one —
// CF_API_KEY here is Unchanged but was never a secret field with a stored
// value, and no other secret is referenced at all.
func TestMergeUpdateReusedSecretOnlyWhenFieldIsSecret(t *testing.T) {
	_, _, changed, reused, err := MergeUpdate("cloudflare", map[string]string{"CF_API_EMAIL": "a@example.com"}, map[string]string{"CF_DNS_API_TOKEN": "t"},
		map[string]string{"CF_API_EMAIL": "b@example.com", "CF_DNS_API_TOKEN": "t2"})
	if err != nil {
		t.Fatal(err)
	}
	if reused {
		t.Fatal("reusedSecret should be false: no secret field was sent as Unchanged")
	}
	if len(changed) != 1 || changed[0] != "CF_API_EMAIL" {
		t.Fatalf("changedPublic = %v", changed)
	}
}

func TestCloudflareHasTwoAuthMethods(t *testing.T) {
	m, ok := Lookup("cloudflare")
	if !ok || len(m.AuthMethods) != 2 {
		t.Fatalf("methods=%v", m.AuthMethods)
	}
}

func TestSplitConfigAliasCanonicalized(t *testing.T) {
	_, sec, err := SplitConfig("cloudflare", map[string]string{"CF_API_EMAIL": "a@b.c", "CLOUDFLARE_API_KEY": "k"})
	if err != nil || sec["CF_API_KEY"] != "k" || len(sec) != 1 {
		t.Fatalf("sec=%v err=%v", sec, err)
	}
	if _, _, err := SplitConfig("cloudflare", map[string]string{"CF_DNS_API_TOKEN": "a", "CF_API_KEY": "x", "CLOUDFLARE_API_KEY": "y", "CF_API_EMAIL": "e"}); !errors.Is(err, ErrAliasConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, _, err := SplitConfig("cloudflare", map[string]string{"CF_API_EMAIL": "e", "CF_API_KEY": "x", "CLOUDFLARE_API_KEY": "x"}); err != nil {
		t.Fatalf("same value: %v", err)
	}
}

func TestSplitConfigAuthMethods(t *testing.T) {
	for name, cfg := range map[string]map[string]string{
		"none":    {},
		"partial": {"CF_API_EMAIL": "e"},
		"empty":   {"CF_DNS_API_TOKEN": ""},
	} {
		_, _, err := SplitConfig("cloudflare", cfg)
		if !errors.Is(err, ErrNoAuthMethod) {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "none" && !strings.Contains(err.Error(), "API token (CF_DNS_API_TOKEN) | ") && !strings.Contains(err.Error(), "Email + API key (CF_API_EMAIL, CF_API_KEY)") {
			t.Fatalf("msg: %v", err)
		}
	}
	if _, _, err := SplitConfig("cloudflare", map[string]string{"CF_DNS_API_TOKEN": "t"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SplitConfig("route53", map[string]string{}); err != nil {
		t.Fatalf("ambient: %v", err)
	}
	if err := Register(ProviderMeta{Code: "unit-nomethods", Name: "x", Schema: []byte(`{"properties":{"A":{"type":"string"}}}`)}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SplitConfig("unit-nomethods", map[string]string{}); err != nil {
		t.Fatalf("method-less: %v", err)
	}
}

func TestMergeUpdateLegacyAliasKeyedStored(t *testing.T) {
	pub, sec, changed, reused, err := MergeUpdate("cloudflare",
		map[string]string{"CF_API_EMAIL": "e"}, map[string]string{"CLOUDFLARE_API_KEY": "old"},
		map[string]string{"CF_API_EMAIL": "e", "CF_API_KEY": Unchanged})
	if err != nil || sec["CF_API_KEY"] != "old" || !reused || len(changed) != 0 || pub["CF_API_EMAIL"] != "e" {
		t.Fatalf("pub=%v sec=%v changed=%v reused=%v err=%v", pub, sec, changed, reused, err)
	}
	got := CanonicalizeStored("cloudflare", map[string]string{"CLOUDFLARE_API_KEY": "k"})
	if got["CF_API_KEY"] != "k" || len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestCheckURLFields(t *testing.T) {
	cases := []struct {
		name  string
		cfg   map[string]string
		allow bool
		bad   string
	}{
		{"loopback", map[string]string{"HTTPREQ_ENDPOINT": "http://127.0.0.1/"}, false, "HTTPREQ_ENDPOINT"},
		{"loopback allowed", map[string]string{"HTTPREQ_ENDPOINT": "http://127.0.0.1/"}, true, ""},
		{"metadata always", map[string]string{"HTTPREQ_ENDPOINT": "http://169.254.169.254/"}, true, "HTTPREQ_ENDPOINT"},
		{"public", map[string]string{"HTTPREQ_ENDPOINT": "https://dns.example.test"}, false, ""},
		{"rfc1918", map[string]string{"HTTPREQ_ENDPOINT": "http://10.0.0.5"}, false, ""},
		{"unchanged skipped", map[string]string{"HTTPREQ_ENDPOINT": Unchanged}, false, ""},
		{"non-url field skipped", map[string]string{"HTTPREQ_PASSWORD": "http://127.0.0.1"}, false, ""},
	}
	for _, c := range cases {
		err := CheckURLFields("httpreq", c.cfg, c.allow)
		if c.bad == "" && err != nil || c.bad != "" && (err == nil || !strings.Contains(err.Error(), c.bad)) {
			t.Errorf("%s: err = %v, want field %q", c.name, err, c.bad)
		}
	}
}

func TestCheckURLFieldsHostFields(t *testing.T) {
	for _, c := range []struct{ code, field string }{
		{"bindman", "BINDMAN_MANAGER_ADDRESS"}, {"vinyldns", "VINYLDNS_HOST"}, {"infoblox", "INFOBLOX_HOST"},
		{"rfc2136", "RFC2136_NAMESERVER"}, {"efficientip", "EFFICIENTIP_HOSTNAME"}, {"edgedns", "AKAMAI_HOST"},
	} {
		for _, v := range []string{"127.0.0.1", "127.0.0.1:8080", "localhost:53", "169.254.169.254"} {
			if err := CheckURLFields(c.code, map[string]string{c.field: v}, false); err == nil {
				t.Errorf("%s=%q accepted", c.field, v)
			}
		}
		if err := CheckURLFields(c.code, map[string]string{c.field: "dns.example.test:8443"}, false); err != nil {
			t.Errorf("%s: public host refused: %v", c.field, err)
		}
	}
	if err := CheckURLFields("ovh", map[string]string{"OVH_ENDPOINT": "ovh-eu"}, false); err != nil {
		t.Errorf("ovh region alias refused: %v", err)
	}
}

// Every schema field whose name or description says URL/URI/endpoint/host/
// address must be covered by isURLField, so a schema regeneration cannot add
// an unchecked network field. notNetwork lists matches that are not hosts.
func TestEveryNetworkFieldIsChecked(t *testing.T) {
	word := regexp.MustCompile(`(?i)\b(urls?|uri|endpoints?|hosts?|hostname|address|nameserver)\b`)
	notNetwork := map[string]bool{"PDNS_SERVER_NAME": true} // a PowerDNS server id, not a host
	for _, m := range Providers() {
		var s struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(m.Schema, &s); err != nil {
			t.Fatal(err)
		}
		for name, p := range s.Properties {
			hit := word.MatchString(strings.ReplaceAll(name, "_", " ")) || word.MatchString(p.Description)
			if hit && !isURLField(name) && !notNetwork[name] {
				t.Errorf("%s.%s (%q) looks like a network field but is not checked", m.Code, name, p.Description)
			}
		}
	}
}
