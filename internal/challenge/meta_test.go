package challenge

import (
	"testing"

	"github.com/metril/certforge/internal/meta"
)

func TestAddToMeta(t *testing.T) {
	r := meta.NewRegistry()
	AddToMeta(r)
	got := r.List(meta.KindDNSProvider)
	if len(got) != len(Providers()) {
		t.Fatalf("%d entries, want %d", len(got), len(Providers()))
	}
	for _, e := range got {
		if e.Code == "acme-dns" && (len(e.Aliases) != 1 || e.Aliases[0] != "acmedns") {
			t.Fatalf("aliases lost: %+v", e)
		}
	}
}
