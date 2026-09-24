package challenge

import "testing"

func TestMatcher(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "anything.example", true},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "b.a.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "*.example.com", true},
		{"*.example.com", "*.a.example.com", false},
		{"example.com", "example.com", true},
		{"example.com", "b.a.example.com", true},
		{"example.com", "*.example.com", true},
		{"example.com", "*.a.example.com", true},
		{"example.com", "badexample.com", false},
		{"Example.COM.", "a.example.com", true},
		{"other.net", "a.example.com", false},
	}
	for _, c := range cases {
		m, err := ParseMatch(c.pattern)
		if err != nil {
			t.Fatalf("ParseMatch(%q): %v", c.pattern, err)
		}
		if got := m.Matches(c.name); got != c.want {
			t.Errorf("%q matches %q = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestParseMatchRejects(t *testing.T) {
	for _, p := range []string{"", "  ", "a.*.example.com", "*.*.example.com", "=a.example.com", "a..example.com", "ex ample.com"} {
		if _, err := ParseMatch(p); err == nil {
			t.Errorf("ParseMatch(%q) accepted", p)
		}
	}
}
