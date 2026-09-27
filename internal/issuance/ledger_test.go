package issuance

import (
	"strings"
	"testing"
)

func TestRegisteredDomains(t *testing.T) {
	got := RegisteredDomains([]string{"a.b.example.co.uk"})
	if strings.Join(got, ",") != "example.co.uk" {
		t.Fatalf("got %v", got)
	}
	// Sorted, unique, wildcard stripped, an unresolvable name falls back to
	// itself.
	got = RegisteredDomains([]string{"*.z.example.test", "a.example.test", "example.test", "localhost"})
	if strings.Join(got, ",") != "example.test,localhost" {
		t.Fatalf("got %v", got)
	}
}

func TestNamesHash(t *testing.T) {
	a := NamesHash([]string{"Example.test", "a.example.test"})
	b := NamesHash([]string{"a.example.test", "EXAMPLE.TEST"})
	if a != b {
		t.Fatalf("hash not order/case independent: %s != %s", a, b)
	}
	c := NamesHash([]string{"other.test"})
	if a == c {
		t.Fatal("different name sets hashed the same")
	}
}
