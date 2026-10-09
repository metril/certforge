package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
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
		err := CheckURLFields(context.Background(), "httpreq", c.cfg, c.allow, stubResolver)
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
			if err := CheckURLFields(context.Background(), c.code, map[string]string{c.field: v}, false, stubResolver); err == nil {
				t.Errorf("%s=%q accepted", c.field, v)
			}
		}
		if err := CheckURLFields(context.Background(), c.code, map[string]string{c.field: "dns.example.test:8443"}, false, stubResolver); err != nil {
			t.Errorf("%s: public host refused: %v", c.field, err)
		}
	}
	if err := CheckURLFields(context.Background(), "ovh", map[string]string{"OVH_ENDPOINT": "ovh-eu"}, false, stubResolver); err != nil {
		t.Errorf("ovh region alias refused: %v", err)
	}
}

// Every schema field whose name or description says URL/URI/endpoint/host/
// address must be covered by isURLField, so a schema regeneration cannot add
// an unchecked network field. notNetwork lists matches that are not hosts.
func TestEveryNetworkFieldIsChecked(t *testing.T) {
	word := regexp.MustCompile(`(?i)\b(urls?|uri|endpoints?|hosts?|hostname|address|nameserver)\b`)
	notNetwork := map[string]bool{"PDNS_SERVER_NAME": true, "SELECTELV2_AUTH_REGION": true} // a PowerDNS server id / a Selectel region name, not hosts
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

// mapResolver resolves names from a fixed table; any other name fails.
type mapResolver map[string][]string

func (m mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ips, ok := m[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := make([]netip.Addr, len(ips))
	for i, ip := range ips {
		out[i] = netip.MustParseAddr(ip)
	}
	return out, nil
}

var stubResolver = mapResolver{
	"dns.example.test": {"203.0.113.9"}, "good.example.test": {"203.0.113.9"},
	"private.example.test": {"10.1.2.3"},
	"127.0.0.1.nip.io":     {"127.0.0.1"},
	"rebind.example.test":  {"203.0.113.9", "169.254.169.254"},
	"lo.example.test":      {"::1"},
}

func TestCheckURLFieldsResolvesHostnames(t *testing.T) {
	check := func(v string, allow bool) error {
		return CheckURLFields(context.Background(), "httpreq", map[string]string{"HTTPREQ_ENDPOINT": v}, allow, stubResolver)
	}
	for _, v := range []string{
		"https://127.0.0.1.nip.io/x", "https://rebind.example.test", "https://lo.example.test",
		"http://metadata.google.internal/computeMetadata/v1/", "http://Metadata.Google.Internal./", "https://nxdomain.example.test",
	} {
		err := check(v, false)
		if err == nil || !strings.Contains(err.Error(), "HTTPREQ_ENDPOINT") {
			t.Errorf("%s: err = %v, want a refusal naming the field", v, err)
		}
	}
	if err := check("https://127.0.0.1.nip.io/x", true); err != nil {
		t.Errorf("loopback-resolving name with opt-out: %v", err)
	}
	if err := check("https://rebind.example.test", true); err == nil {
		t.Error("metadata-resolving name accepted with opt-out")
	}
	if err := check("http://metadata.google.internal/", true); err == nil {
		t.Error("metadata name accepted with opt-out")
	}
	if err := check("https://private.example.test", false); err != nil {
		t.Errorf("RFC 1918 resolution refused: %v", err)
	}
}

// An Unchanged sentinel under an alias key keeps the stored (canonical) secret.
func TestMergeUpdateUnchangedUnderAliasKey(t *testing.T) {
	_, sec, _, reused, err := MergeUpdate("cloudflare", nil, map[string]string{"CF_DNS_API_TOKEN": "old-token"},
		map[string]string{"CLOUDFLARE_DNS_API_TOKEN": Unchanged})
	if err != nil {
		t.Fatal(err)
	}
	if sec["CF_DNS_API_TOKEN"] != "old-token" || len(sec) != 1 || !reused {
		t.Fatalf("sec=%v reused=%v", sec, reused)
	}
}

func captureWarn(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestBuildDropsRetiredStoredKey(t *testing.T) {
	buf := captureWarn(t)
	if _, err := Build("dode", map[string]string{"DODE_TOKEN": "tok-secret", "DODE_TTL": "120"}); err != nil {
		t.Fatalf("stored retired key must not fail the build: %v", err)
	}
	log := buf.String()
	if !strings.Contains(log, "DODE_TTL") || !strings.Contains(log, "dode") || strings.Contains(log, "120") || strings.Contains(log, "tok-secret") {
		t.Fatalf("log = %q", log)
	}
}

func TestMergeUpdateDropsRetiredStoredKey(t *testing.T) {
	buf := captureWarn(t)
	pub, sec, _, _, err := MergeUpdate("dode",
		map[string]string{"DODE_TTL": "120"}, map[string]string{"DODE_TOKEN": "old"},
		map[string]string{"DODE_TOKEN": Unchanged})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub["DODE_TTL"]; ok || sec["DODE_TOKEN"] != "old" {
		t.Fatalf("pub=%v sec=%v", pub, sec)
	}
	if !strings.Contains(buf.String(), "DODE_TTL") {
		t.Fatalf("no drop log: %q", buf.String())
	}
	// New input carrying the retired key is still refused.
	if _, _, _, _, err := MergeUpdate("dode", nil, map[string]string{"DODE_TOKEN": "old"},
		map[string]string{"DODE_TOKEN": Unchanged, "DODE_TTL": "120"}); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("err = %v", err)
	}
}

// lego's f5xc builds https://<tenant>.<server>; both fields end up inside a
// host, so they must not carry URL syntax and the composed host is checked.
func TestCheckURLFieldsF5XCComposedHost(t *testing.T) {
	r := mapResolver{
		"acme.console.ves.volterra.io": {"203.0.113.9"},
		"acme.dns.example.test":        {"203.0.113.9"},
		"acme.lo.example.test":         {"::1"},
	}
	cases := []struct {
		name string
		cfg  map[string]string
		bad  string
	}{
		{"tenant injects authority", map[string]string{"F5XC_TENANT_NAME": "@127.0.0.1:8200/#"}, "F5XC_TENANT_NAME"},
		{"tenant with slash", map[string]string{"F5XC_TENANT_NAME": "a/b"}, "F5XC_TENANT_NAME"},
		{"tenant with space", map[string]string{"F5XC_TENANT_NAME": "a b"}, "F5XC_TENANT_NAME"},
		{"server injects path", map[string]string{"F5XC_TENANT_NAME": "acme", "F5XC_SERVER": "dns.example.test/#"}, "F5XC_SERVER"},
		{"server with port", map[string]string{"F5XC_TENANT_NAME": "acme", "F5XC_SERVER": "dns.example.test:8443"}, "F5XC_SERVER"},
		{"composed host loopback", map[string]string{"F5XC_TENANT_NAME": "acme", "F5XC_SERVER": "lo.example.test"}, "F5XC_SERVER"},
		{"default server ok", map[string]string{"F5XC_TENANT_NAME": "acme"}, ""},
		{"custom server ok", map[string]string{"F5XC_TENANT_NAME": "acme", "F5XC_SERVER": "dns.example.test"}, ""},
	}
	for _, c := range cases {
		err := CheckURLFields(context.Background(), "f5xc", c.cfg, false, r)
		if c.bad == "" && err != nil || c.bad != "" && (err == nil || !strings.Contains(err.Error(), c.bad)) {
			t.Errorf("%s: err = %v, want field %q", c.name, err, c.bad)
		}
	}
}
