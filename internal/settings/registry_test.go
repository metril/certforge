package settings

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func TestDefaultRegistrySections(t *testing.T) {
	if got := DefaultRegistry().Names(); !slices.Equal(got, []string{"backup", "general"}) {
		t.Fatalf("names %v", got)
	}
}

func TestGeneralValidation(t *testing.T) {
	sec, ok := DefaultRegistry().Section("general")
	if !ok {
		t.Fatal("general missing")
	}
	if err := sec.Validate([]byte(`{"baseUrl":"https://certs.example.com"}`)); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	for _, bad := range []string{`{"baseUrl":"ftp://x"}`, `{"unknown":1}`, `not json`, `[]`} {
		if err := sec.Validate([]byte(bad)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v", bad, err)
		}
	}
}

func TestRegisterRejects(t *testing.T) {
	r := NewRegistry()
	schema := json.RawMessage(`{"type":"object","properties":{"n":{"type":"integer"}}}`)
	if err := r.Register("ok", schema, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"duplicate":   func() error { return r.Register("ok", schema, json.RawMessage(`{}`)) },
		"bad default": func() error { return r.Register("d", schema, json.RawMessage(`{"n":"x"}`)) },
		"bad name":    func() error { return r.Register("Bad Name", schema, json.RawMessage(`{}`)) },
		"bad schema":  func() error { return r.Register("s", json.RawMessage(`{"type":5}`), json.RawMessage(`{}`)) },
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
