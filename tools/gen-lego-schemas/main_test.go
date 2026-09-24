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
	want := map[string]bool{"FAKE_API_TOKEN": true, "FAKE_PASSWORD": true, "FAKE_USERNAME": false, "FAKE_TTL": false, "FAKE_KEY_FILE_PATH_HINT": false}
	for k, secret := range want {
		p, ok := f.Schema.Properties[k]
		if !ok {
			t.Fatalf("missing %s", k)
		}
		if p.Secret != secret {
			t.Errorf("%s secret = %v, want %v", k, p.Secret, secret)
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
