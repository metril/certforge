package issuance

import "testing"

func TestValidateResolversDoH(t *testing.T) {
	if err := validateResolvers("resolvers", []string{"1.1.1.1:53", "https://cloudflare-dns.com/dns-query"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"https://", "https:///x", "https://a b/x"} {
		if err := validateResolvers("resolvers", []string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEffectiveDNSServersSkipsDoH(t *testing.T) {
	got, err := effectiveDNSServers([]string{"https://x/dns-query", "9.9.9.9"})
	if err != nil || len(got) != 1 || got[0] != "9.9.9.9:53" {
		t.Fatalf("got %v err %v", got, err)
	}
}
