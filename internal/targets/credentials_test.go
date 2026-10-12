package targets_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/metril/certforge/internal/targets"
)

func compile(t *testing.T, schema json.RawMessage) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(schema)))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("s.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("s.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKindSchemas(t *testing.T) {
	if got, want := targets.Kinds(), []string{"apiKey", "password", "ssh", "token"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Kinds = %v, want %v", got, want)
	}
	cases := []struct {
		kind, doc string
		ok        bool
		secrets   []string
	}{
		{"ssh", `{"username":"u","password":"p"}`, true, []string{"password", "privateKey"}},
		{"ssh", `{"username":"u","privateKey":"k"}`, true, nil},
		{"ssh", `{"username":"u"}`, false, nil},
		{"ssh", `{"password":"p"}`, false, nil},
		{"ssh", `{"username":"u","privateKey":"` + strings.Repeat("a", 8193) + `"}`, false, nil},
		{"password", `{"username":"u","password":"p"}`, true, []string{"password"}},
		{"password", `{"username":"u"}`, false, nil},
		{"apiKey", `{"apiKey":"k"}`, true, []string{"apiKey"}},
		{"apiKey", `{"apiKey":"k","username":"u"}`, true, nil},
		{"apiKey", `{"username":"u"}`, false, nil},
		{"token", `{"token":"t"}`, true, []string{"token"}},
		{"token", `{"token":"t","x":1}`, false, nil},
	}
	for _, c := range cases {
		schema, ok := targets.KindSchema(c.kind)
		if !ok {
			t.Fatalf("no schema for %s", c.kind)
		}
		s := compile(t, schema)
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(c.doc))
		if err := s.Validate(inst); (err == nil) != c.ok {
			t.Errorf("%s %s: err = %v, want ok=%v", c.kind, c.doc, err, c.ok)
		}
		if c.secrets != nil {
			got, err := targets.SecretProps(schema)
			if err != nil || !reflect.DeepEqual(got, c.secrets) {
				t.Errorf("%s SecretProps = %v, %v; want %v", c.kind, got, err, c.secrets)
			}
		}
	}
	if _, ok := targets.KindSchema("nope"); ok {
		t.Error("unknown kind has a schema")
	}
}

func TestAcceptedKinds(t *testing.T) {
	got := targets.AcceptedKinds(json.RawMessage(`{"type":"object","credentialKinds":["ssh","password"]}`))
	if !reflect.DeepEqual(got, []string{"ssh", "password"}) {
		t.Errorf("got %v", got)
	}
	if got := targets.AcceptedKinds(json.RawMessage(`{"type":"object"}`)); got != nil {
		t.Errorf("absent keyword: %v", got)
	}
	// The keyword is ignored by schema compilation and validation.
	s := compile(t, json.RawMessage(`{"type":"object","credentialKinds":["ssh"]}`))
	inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(`{}`))
	if err := s.Validate(inst); err != nil {
		t.Errorf("credentialKinds not tolerated: %v", err)
	}
}

func TestResolve(t *testing.T) {
	cfg := json.RawMessage(`{"host":"h","username":"old"}`)
	cred := &targets.Credential{
		Kind:    "password",
		Public:  json.RawMessage(`{"username":"admin"}`),
		Secrets: map[string]string{"password": "pw"},
	}

	// nil credential is plain Merge.
	out, err := targets.Resolve(json.RawMessage(`{"host":"h"}`), map[string]string{"password": "own"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if m["password"] != "own" || m["host"] != "h" {
		t.Errorf("nil cred: %v", m)
	}

	// Overlay.
	out, err = targets.Resolve(json.RawMessage(`{"host":"h"}`), nil, cred)
	if err != nil {
		t.Fatal(err)
	}
	m = nil
	_ = json.Unmarshal(out, &m)
	if m["host"] != "h" || m["username"] != "admin" || m["password"] != "pw" {
		t.Errorf("overlay: %v", m)
	}

	// Conflicts in config and in target secrets.
	if _, err := targets.Resolve(cfg, nil, cred); err == nil || !strings.Contains(err.Error(), "username") {
		t.Errorf("config conflict err = %v", err)
	}
	bad, err := targets.Conflicts(json.RawMessage(`{"host":"h"}`), map[string]string{"password": "x"}, cred)
	if err != nil || !reflect.DeepEqual(bad, []string{"password"}) {
		t.Errorf("Conflicts = %v, %v", bad, err)
	}
	if _, err := targets.Resolve(json.RawMessage(`{"host":"h"}`), map[string]string{"password": "x"}, cred); err == nil {
		t.Error("secret conflict not rejected")
	}
}
