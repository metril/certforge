package challenge

import (
	"encoding/json"
	"testing"
)

func TestProvidersLoadedFromSchemas(t *testing.T) {
	ps := Providers()
	if len(ps) < 100 {
		t.Fatalf("only %d providers loaded", len(ps))
	}
	cf, ok := Lookup("cloudflare")
	if !ok || cf.Name != "Cloudflare" {
		t.Fatalf("cloudflare = %+v", cf)
	}
	var s struct {
		Properties map[string]struct{ Secret bool } `json:"properties"`
	}
	if err := json.Unmarshal(cf.Schema, &s); err != nil {
		t.Fatal(err)
	}
	if !s.Properties["CF_DNS_API_TOKEN"].Secret || s.Properties["CF_API_EMAIL"].Secret {
		t.Fatalf("secret flags wrong: %+v", s.Properties)
	}
	if _, ok := Lookup("exec"); ok {
		t.Fatal("exec provider must not be offered")
	}
	if m, ok := Lookup("acmedns"); !ok || m.Code != "acme-dns" {
		t.Fatalf("alias lookup = %+v %v", m, ok)
	}
}
