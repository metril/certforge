package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	out := t.TempDir()
	docs := filepath.Join(out, "dns-providers.md")
	if err := generate("testdata", out, docs); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "fakedns.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f providerFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"FAKE_API_TOKEN": true, "FAKE_PASSWORD": true, "FAKE_USERNAME": false, "FAKE_TTL": false,
		"FAKE_KEY_FILE_PATH_HINT": true, "FAKE_CREDENTIALS_FILE": false}
	for k, secret := range want {
		p, ok := f.Schema.Properties[k]
		if !ok {
			t.Fatalf("missing %s", k)
		}
		if p.Secret != secret {
			t.Errorf("%s secret = %v, want %v", k, p.Secret, secret)
		}
	}
	wantServerPath := map[string]bool{"FAKE_CREDENTIALS_FILE": true, "FAKE_KEY_FILE_PATH_HINT": false, "FAKE_API_TOKEN": false}
	for k, sp := range wantServerPath {
		p, ok := f.Schema.Properties[k]
		if !ok {
			t.Fatalf("missing %s", k)
		}
		if p.ServerPath != sp {
			t.Errorf("%s serverPath = %v, want %v", k, p.ServerPath, sp)
		}
	}
	if f.Aliases[0] != "fake" || f.Schema.AdditionalProperties {
		t.Errorf("aliases/additionalProperties wrong: %+v", f)
	}
	if _, err := os.Stat(filepath.Join(out, "exec.json")); !os.IsNotExist(err) {
		t.Error("exec provider must be skipped")
	}
	md, _ := os.ReadFile(docs)
	if !strings.Contains(string(md), "## Fake DNS") || !strings.Contains(string(md), "| `FAKE_API_TOKEN` | credentials | yes |") {
		t.Errorf("docs missing provider section:\n%s", md)
	}
}

// TestRealProviderSecretClassification reads the committed schema files
// generated from lego's real provider metadata and checks a handful of
// fields the regex alone gets wrong: three secrets the name regex misses
// (forceSecret) and three name-regex matches that are not secrets
// (forceNonSecret / the _KEY_ID, _PATH, _FILE suffix rule).
func TestRealProviderSecretClassification(t *testing.T) {
	cases := []struct {
		provider, field string
		secret          bool
	}{
		{"gcloud", "GCE_SERVICE_ACCOUNT", true}, // forceSecret: no name-regex match otherwise
		{"epik", "EPIK_SIGNATURE", true},        // forceSecret: no name-regex match otherwise
		{"httpreq", "HTTPREQ_PASSWORD", true},   // Additional group, name-regex match
		{"route53", "AWS_ACCESS_KEY_ID", false}, // _KEY_ID suffix: an identifier, not the secret
		{"scaleway", "SCW_ACCESS_KEY", false},   // forceNonSecret: paired with secret SCW_SECRET_KEY
		{"rfc2136", "RFC2136_TSIG_KEY", false},  // forceNonSecret: key name, not RFC2136_TSIG_SECRET's payload
	}
	for _, c := range cases {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "challenge", "schemas", c.provider+".json"))
		if err != nil {
			t.Fatalf("%s: %v", c.provider, err)
		}
		var f providerFile
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatalf("%s: %v", c.provider, err)
		}
		p, ok := f.Schema.Properties[c.field]
		if !ok {
			t.Fatalf("%s: missing field %s", c.provider, c.field)
		}
		if p.Secret != c.secret {
			t.Errorf("%s.%s secret = %v, want %v", c.provider, c.field, p.Secret, c.secret)
		}
	}
}

// TestRealProviderServerPathClassification checks the committed schema
// files mark a couple of real _FILE/_PATH fields serverPath, and that a
// same-provider field with neither suffix (including gcloud's own
// GCE_SERVICE_ACCOUNT, whose *_FILE sibling is the serverPath one) is not.
func TestRealProviderServerPathClassification(t *testing.T) {
	cases := []struct {
		provider, field string
		serverPath      bool
	}{
		{"gcloud", "GCE_SERVICE_ACCOUNT_FILE", true},
		{"gcloud", "GCE_SERVICE_ACCOUNT", false},
		{"azuredns", "AZURE_CLIENT_CERTIFICATE_PATH", true},
	}
	for _, c := range cases {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "challenge", "schemas", c.provider+".json"))
		if err != nil {
			t.Fatalf("%s: %v", c.provider, err)
		}
		var f providerFile
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatalf("%s: %v", c.provider, err)
		}
		p, ok := f.Schema.Properties[c.field]
		if !ok {
			t.Fatalf("%s: missing field %s", c.provider, c.field)
		}
		if p.ServerPath != c.serverPath {
			t.Errorf("%s.%s serverPath = %v, want %v", c.provider, c.field, p.ServerPath, c.serverPath)
		}
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if err := generate("testdata", a, filepath.Join(a, "d.md")); err != nil {
		t.Fatal(err)
	}
	if err := generate("testdata", b, filepath.Join(b, "d.md")); err != nil {
		t.Fatal(err)
	}
	x, _ := os.ReadFile(filepath.Join(a, "fakedns.json"))
	y, _ := os.ReadFile(filepath.Join(b, "fakedns.json"))
	if string(x) != string(y) {
		t.Fatal("output differs between runs")
	}
}
