package backup

import (
	"errors"
	"testing"
)

func TestVerifyManifestTableList(t *testing.T) {
	sums := func(tables ...string) map[string]TableSum {
		m := map[string]TableSum{}
		for _, tb := range tables {
			m[tb] = TableSum{Name: tb, SHA256: "h"}
		}
		return m
	}
	older := Manifest[:len(Manifest)-1]
	rev := append([]string(nil), older...)
	rev[1], rev[2] = rev[2], rev[1]
	cases := []struct {
		name   string
		header []string
		ok     bool
	}{
		{"full", Manifest, true},
		{"older prefix", older, true},
		{"unknown table", append(append([]string(nil), older...), "bogus"), false},
		{"wrong order", rev, false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		s := sums(c.header...)
		err := verifyManifest(c.header, s, s)
		if c.ok && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrTampered) {
			t.Errorf("%s: err = %v, want ErrTampered", c.name, err)
		}
	}
	// header lists a table the tar lacks.
	if err := verifyManifest(older, sums(older[:len(older)-1]...), sums(older...)); !errors.Is(err, ErrTampered) {
		t.Errorf("missing tar table: %v", err)
	}
}
