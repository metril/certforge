package deploy

import (
	"encoding/json"
	"testing"

	"github.com/metril/certforge/internal/render"
)

// TestVaultKVPathTemplate covers renderPath: the three known placeholders
// substitute, an unknown one is rejected, and the rendered result must not
// start with / or contain .. or fall outside the allowed character set.
func TestVaultKVPathTemplate(t *testing.T) {
	cases := []struct {
		name    string
		tmpl    string
		want    string
		wantErr bool
	}{
		{name: "default template", tmpl: "certforge/{org}/{name}", want: "certforge/acme/web"},
		{name: "cert placeholder", tmpl: "certs/{cert}/bundle", want: "certs/c1/bundle"},
		{name: "all placeholders", tmpl: "{org}/{cert}/{name}", want: "acme/c1/web"},
		{name: "no placeholders", tmpl: "static/path", want: "static/path"},
		{name: "unknown placeholder", tmpl: "certforge/{other}", wantErr: true},
		{name: "leading slash", tmpl: "/etc/passwd", wantErr: true},
		{name: "dot dot", tmpl: "certforge/../escape", wantErr: true},
		{name: "dot dot after substitution", tmpl: "certforge/{org}/../escape", wantErr: true},
		{name: "bad characters", tmpl: "certforge/{org}/has space", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := renderPath(c.tmpl, "acme", "c1", "web")
			if c.wantErr {
				if err == nil {
					t.Fatalf("renderPath(%q) = %q, want error", c.tmpl, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("renderPath(%q): %v", c.tmpl, err)
			}
			if got != c.want {
				t.Fatalf("renderPath(%q) = %q, want %q", c.tmpl, got, c.want)
			}
		})
	}
}

// TestVaultKVDocumentShape covers vaultKVData: without a layout, the four
// canonical PEM names map to cfg.Keys' field names and the key is dropped
// unless includeKey; with a layout, each file keeps its own base name.
func TestVaultKVDocumentShape(t *testing.T) {
	var cfg VaultKVConfig
	cfg.fillDefaults()

	noLayout := []render.File{
		{Name: "fullchain.pem", Data: []byte("FULLCHAIN")},
		{Name: "cert.pem", Data: []byte("CERT")},
		{Name: "chain.pem", Data: []byte("CHAIN")},
		{Name: "privkey.pem", Data: []byte("KEY"), Secret: true},
	}
	data := vaultKVData(noLayout, cfg)
	if len(data) != 3 {
		t.Fatalf("data = %+v, want 3 fields (key dropped)", data)
	}
	if data["fullchain.pem"] != "FULLCHAIN" || data["cert.pem"] != "CERT" || data["chain.pem"] != "CHAIN" {
		t.Fatalf("data = %+v", data)
	}
	if _, ok := data["privkey.pem"]; ok {
		t.Fatalf("data has key material without includeKey: %+v", data)
	}

	cfg.IncludeKey = true
	data = vaultKVData(noLayout, cfg)
	if len(data) != 4 || data["privkey.pem"] != "KEY" {
		t.Fatalf("data with includeKey = %+v", data)
	}

	cfg.Keys = KeyNames{Fullchain: "custom-fullchain", Cert: "custom-cert", Chain: "custom-chain", Key: "custom-key"}
	data = vaultKVData(noLayout, cfg)
	if data["custom-fullchain"] != "FULLCHAIN" || data["custom-key"] != "KEY" {
		t.Fatalf("data with custom keys = %+v", data)
	}

	cfg = VaultKVConfig{}
	cfg.fillDefaults()
	layout := []render.File{
		{Name: "cabundle.pem", Data: []byte("CA")},
		{Name: "keystore.p12", Data: []byte("P12"), Secret: true},
	}
	data = vaultKVData(layout, cfg)
	if len(data) != 1 || data["cabundle.pem"] != "CA" {
		t.Fatalf("layout data = %+v", data)
	}
	if _, ok := data["keystore.p12"]; ok {
		t.Fatalf("layout data has key-bearing file without includeKey: %+v", data)
	}

	cfg.IncludeKey = true
	data = vaultKVData(layout, cfg)
	if len(data) != 2 || data["keystore.p12"] != "P12" {
		t.Fatalf("layout data with includeKey = %+v", data)
	}
}

// TestVaultKVParseConfig covers ParseConfig: defaults are filled in,
// additional fields are rejected, and an invalid mount or path is 422'd
// (via delivery.FieldError).
func TestVaultKVParseConfig(t *testing.T) {
	cfg, err := VaultKV{}.ParseConfig(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("ParseConfig({}): %v", err)
	}
	var got VaultKVConfig
	if err := json.Unmarshal(cfg, &got); err != nil {
		t.Fatal(err)
	}
	if got.Mount != "secret" || got.Path != "certforge/{org}/{name}" || got.Keys.Fullchain != "fullchain.pem" || got.IncludeKey {
		t.Fatalf("defaults = %+v", got)
	}

	if _, err := (VaultKV{}).ParseConfig(json.RawMessage(`{"nope": 1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := (VaultKV{}).ParseConfig(json.RawMessage(`{"mount": "??"}`)); err == nil {
		t.Fatal("bad mount accepted")
	}
	if _, err := (VaultKV{}).ParseConfig(json.RawMessage(`{"path": "/etc/passwd"}`)); err == nil {
		t.Fatal("absolute path accepted")
	}
	if _, err := (VaultKV{}).ParseConfig(json.RawMessage(`{"path": "{unknown}"}`)); err == nil {
		t.Fatal("unknown placeholder accepted")
	}
}

// TestRunsOn covers RunsOn: vault-kv runs on the server, everything else on
// an agent.
func TestRunsOn(t *testing.T) {
	if RunsOn(TypeVaultKV) != "server" {
		t.Fatalf("RunsOn(vault-kv) = %q, want server", RunsOn(TypeVaultKV))
	}
	if RunsOn("traefik") != "agent" {
		t.Fatalf("RunsOn(traefik) = %q, want agent", RunsOn("traefik"))
	}
}
