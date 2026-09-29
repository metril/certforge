package settings

import (
	"encoding/json"
	"errors"
	"fmt"
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

const secretSchema = `{"type":"object","additionalProperties":false,"properties":{
  "issuer":{"type":"string","description":"Issuer."},
  "clientSecret":{"type":"string","secret":true,"description":"Secret."}}}`

func TestSecretKeys(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("s", json.RawMessage(secretSchema), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.Section("s")
	if got := sec.SecretKeys(); !slices.Equal(got, []string{"clientSecret"}) {
		t.Fatalf("SecretKeys = %v", got)
	}
	pub, err := sec.Public(json.RawMessage(`{"issuer":"https://idp","clientSecret":"x"}`))
	if err != nil || string(pub) != `{"issuer":"https://idp"}` {
		t.Fatalf("Public = %s, %v", pub, err)
	}
}

func TestSecretSchemaRules(t *testing.T) {
	for name, schema := range map[string]string{
		"non-string": `{"type":"object","properties":{"k":{"type":"integer","secret":true}}}`,
		"required":   `{"type":"object","required":["k"],"properties":{"k":{"type":"string","secret":true}}}`,
	} {
		if err := NewRegistry().Register("s", json.RawMessage(schema), json.RawMessage(`{"k":"v"}`)); err == nil {
			t.Fatalf("%s: registered", name)
		}
	}
	// A secret property that also carries pattern/enum/const/format would echo
	// the rejected value (which may be the actual secret) into jsonschema's
	// error text on a validation failure; these annotations are rejected on
	// the schema itself, regardless of what the (secret-free) default holds.
	for name, schema := range map[string]string{
		"pattern": `{"type":"object","properties":{"k":{"type":"string","secret":true,"pattern":"^s3cret$"}}}`,
		"enum":    `{"type":"object","properties":{"k":{"type":"string","secret":true,"enum":["s3cret"]}}}`,
		"const":   `{"type":"object","properties":{"k":{"type":"string","secret":true,"const":"s3cret"}}}`,
		"format":  `{"type":"object","properties":{"k":{"type":"string","secret":true,"format":"email"}}}`,
	} {
		if err := NewRegistry().Register("s", json.RawMessage(schema), json.RawMessage(`{}`)); err == nil {
			t.Errorf("%s: registered", name)
		}
	}
	if err := NewRegistry().Register("s", json.RawMessage(secretSchema), json.RawMessage(`{"clientSecret":"x"}`)); err == nil {
		t.Fatal("default holding a secret was accepted")
	}
}

func TestAddCheck(t *testing.T) {
	r := NewRegistry()
	r.MustRegister("s", json.RawMessage(secretSchema), json.RawMessage(`{}`))
	if err := r.AddCheck("s", func(json.RawMessage) error { return errors.New("nope") }); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.Section("s")
	if err := sec.Validate([]byte(`{}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if err := r.AddCheck("missing", nil); err == nil {
		t.Fatal("AddCheck on unknown section succeeded")
	}
}

// TestBackupSettingsDirectoryRules covers Phase 6A Task 1's extended
// "backup" section: directory is required once schedule is not off, must be
// absolute, and must be a writable directory (checkBackupDirectory creates
// and removes a probe file).
func TestBackupSettingsDirectoryRules(t *testing.T) {
	sec, ok := DefaultRegistry().Section("backup")
	if !ok {
		t.Fatal("backup missing")
	}
	if err := sec.Validate(sec.Default); err != nil {
		t.Fatalf("default rejected: %v", err)
	}
	if err := sec.Validate([]byte(`{"schedule":"off"}`)); err != nil {
		t.Fatalf("schedule off, no directory: %v", err)
	}
	if err := sec.Validate([]byte(`{"schedule":"daily"}`)); err == nil {
		t.Fatal("schedule daily, no directory: accepted")
	}
	if err := sec.Validate([]byte(`{"schedule":"daily","directory":"relative/path"}`)); err == nil {
		t.Fatal("relative directory: accepted")
	}
	dir := t.TempDir()
	if err := sec.Validate([]byte(fmt.Sprintf(`{"schedule":"daily","directory":%q}`, dir))); err != nil {
		t.Fatalf("writable directory: %v", err)
	}
	if err := sec.Validate([]byte(`{"schedule":"weekly","directory":"/certforge-test-nonexistent-dir"}`)); err == nil {
		t.Fatal("nonexistent directory: accepted")
	}
}

func TestAddUpdateCheck(t *testing.T) {
	r := NewRegistry()
	r.MustRegister("s", json.RawMessage(secretSchema), json.RawMessage(`{}`))
	if err := r.AddUpdateCheck("s", func(stored, next json.RawMessage) error {
		if stored == nil {
			return nil
		}
		return errors.New("nope")
	}); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.Section("s")
	if err := sec.ValidateUpdate(nil, []byte(`{}`)); err != nil {
		t.Fatalf("nil stored: %v", err)
	}
	if err := sec.ValidateUpdate(json.RawMessage(`{}`), []byte(`{}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if err := r.AddUpdateCheck("missing", nil); err == nil {
		t.Fatal("AddUpdateCheck on unknown section succeeded")
	}
}
