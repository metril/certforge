package challenge

import (
	"errors"
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

func TestMergeUpdateUnchangedSentinel(t *testing.T) {
	old := map[string]string{"CF_DNS_API_TOKEN": "old-token", "CF_ZONE_API_TOKEN": "old-zone"}
	pub, sec, err := MergeUpdate("cloudflare", old, map[string]string{
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
}
