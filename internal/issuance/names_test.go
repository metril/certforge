package issuance

import (
	"strings"
	"testing"
)

func TestNormalizeNames(t *testing.T) {
	got, err := NormalizeNames("Example.test.", []string{"*.example.test", "example.test", " other.test ", "192.0.2.7"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "example.test,*.example.test,other.test,192.0.2.7" {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"a.*.example.test", "localhost", "-a.example.test", "a b.example.test", "*"} {
		if _, err := NormalizeNames(bad, nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
