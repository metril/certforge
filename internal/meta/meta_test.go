package meta

import (
	"encoding/json"
	"testing"
)

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	if got := r.List(KindDNSProvider); got == nil || len(got) != 0 {
		t.Fatalf("empty list = %#v", got)
	}
	r.Add(KindDNSProvider, Entry{Code: "route53", Name: "Route 53", Schema: json.RawMessage(`{}`)})
	r.Add(KindDNSProvider, Entry{Code: "cloudflare", Name: "Cloudflare", Schema: json.RawMessage(`{}`)})
	r.Add(KindDNSProvider, Entry{Code: "cloudflare", Name: "Cloudflare v2", Schema: json.RawMessage(`{}`)})
	got := r.List(KindDNSProvider)
	if len(got) != 2 || got[0].Code != "cloudflare" || got[0].Name != "Cloudflare v2" || got[1].Code != "route53" {
		t.Fatalf("list %+v", got)
	}
	if len(r.List(KindSigner)) != 0 {
		t.Fatal("kinds leak")
	}
}
