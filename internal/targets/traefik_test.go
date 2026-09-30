package targets

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
)

// TestTraefikRegistryGolden: Traefik.Files, reached only through the
// registry (Get, Parse, Files), renders byte-identical output to
// delivery.RenderTraefik called directly — the same rendering
// internal/delivery's own TestRenderTraefikGolden checks against golden
// files. This task changes only how a caller reaches RenderTraefik, never
// what it renders.
func TestTraefikRegistryGolden(t *testing.T) {
	reg := NewRegistry()
	RegisterBuiltins(reg)
	target, ok := reg.Get("traefik")
	if !ok {
		t.Fatal("traefik not registered")
	}
	ft, ok := target.(FileTarget)
	if !ok {
		t.Fatal("traefik is not a FileTarget")
	}

	rawCfg := json.RawMessage(`{"dir":"/data/traefik","pathPrefix":"/etc/traefik/dynamic","defaultCert":true,"stores":["default","internal"]}`)
	cfg, err := target.Parse(rawCfg)
	if err != nil {
		t.Fatal(err)
	}
	m := &render.Material{LeafDER: []byte("leaf"), ChainDER: [][]byte{[]byte("int")}, PrivateKeyPKCS8: []byte("key")}
	names := []string{"api.example.test"}

	got, err := ft.Files(Request{CertName: "api.example.test", Names: names, Material: m, Config: cfg.Public})
	if err != nil {
		t.Fatal(err)
	}

	var tc delivery.TraefikConfig
	if err := json.Unmarshal(cfg.Public, &tc); err != nil {
		t.Fatal(err)
	}
	mat, err := delivery.TargetMaterial(*m)
	if err != nil {
		t.Fatal(err)
	}
	want := delivery.RenderTraefik("api.example.test", names, tc, mat.Fullchain, mat.Key)
	if len(got) != len(want) {
		t.Fatalf("%d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Path != want[i].Path || got[i].Mode != want[i].Mode || !bytes.Equal(got[i].Data, want[i].Data) {
			t.Errorf("file %d differs:\ngot  %+v\nwant %+v", i, got[i], want[i])
		}
	}

	paths, err := ft.Paths(cfg.Public, "api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := delivery.RenderTraefik("api.example.test", nil, tc, nil, nil)
	if len(paths) != len(wantPaths) {
		t.Fatalf("%d paths, want %d", len(paths), len(wantPaths))
	}
	for i := range wantPaths {
		if paths[i] != wantPaths[i].Path {
			t.Errorf("path %d = %s, want %s", i, paths[i], wantPaths[i].Path)
		}
	}
}

// TestTraefikModes covers Traefik's fixed mode and key policy: always
// agent, always needing the key.
func TestTraefikModes(t *testing.T) {
	tr := Traefik{}
	if tr.RunsOn() != Agent {
		t.Fatalf("RunsOn = %s, want agent", tr.RunsOn())
	}
	if tr.KeyPolicy() != Always {
		t.Fatalf("KeyPolicy = %s, want always", tr.KeyPolicy())
	}
	cfg, err := tr.Parse(json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NeedsKey || len(cfg.Secrets) != 0 || cfg.URLs != nil {
		t.Fatalf("Parse config = %+v", cfg)
	}
}

// TestTraefikFilesNoMaterial covers Files with req.Material nil (C3): only
// the ACME router file renders, and nothing at all without acmeServiceUrl.
func TestTraefikFilesNoMaterial(t *testing.T) {
	tr := Traefik{}
	withACME := json.RawMessage(`{"dir":"/etc/traefik/dynamic","acmeServiceUrl":"http://agent:8080"}`)
	files, err := tr.Files(Request{CertName: "Web", Names: []string{"web.example.test"}, Config: withACME})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "/etc/traefik/dynamic/certforge-acme-web.yml" {
		t.Fatalf("files %+v", files)
	}
	noACME := json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`)
	if files, err := tr.Files(Request{CertName: "Web", Names: []string{"web.example.test"}, Config: noACME}); err != nil || len(files) != 0 {
		t.Fatalf("without acmeServiceUrl: files %+v err %v", files, err)
	}
}
