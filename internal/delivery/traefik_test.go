package delivery

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/metril/certforge/internal/agentproto"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestRenderTraefikGolden(t *testing.T) {
	for _, tc := range []struct {
		golden, name string
		cfg          TraefikConfig
		paths        [3]string
	}{
		{"traefik-basic.yml", "Web Frontend", TraefikConfig{Dir: "/etc/traefik/dynamic"},
			[3]string{"/etc/traefik/dynamic/certs/web-frontend/fullchain.pem", "/etc/traefik/dynamic/certs/web-frontend/privkey.pem", "/etc/traefik/dynamic/certforge-web-frontend.yml"}},
		{"traefik-default.yml", "api.example.test", TraefikConfig{Dir: "/data/traefik", PathPrefix: "/etc/traefik/dynamic", DefaultCert: true, Stores: []string{"default", "internal"}},
			[3]string{"/data/traefik/certs/api.example.test/fullchain.pem", "/data/traefik/certs/api.example.test/privkey.pem", "/data/traefik/certforge-api.example.test.yml"}},
	} {
		files := RenderTraefik(tc.name, tc.cfg, []byte("FULLCHAIN"), []byte("KEY"))
		if len(files) != 3 {
			t.Fatalf("%s: %d files", tc.golden, len(files))
		}
		for i, f := range files {
			if f.Path != tc.paths[i] {
				t.Errorf("%s: path %d = %s", tc.golden, i, f.Path)
			}
		}
		if files[0].Mode != "0644" || files[1].Mode != "0600" || files[2].Mode != "0644" || string(files[1].Data) != "KEY" {
			t.Errorf("%s: modes %s %s %s", tc.golden, files[0].Mode, files[1].Mode, files[2].Mode)
		}
		path := filepath.Join("testdata", tc.golden)
		if *update {
			if err := os.WriteFile(path, files[2].Data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(files[2].Data) != string(want) {
			t.Errorf("%s:\n%s\nwant:\n%s", tc.golden, files[2].Data, want)
		}
	}
}

func TestRenderTraefikACME(t *testing.T) {
	cfg := TraefikConfig{Dir: "/etc/traefik/dynamic", AcmeServiceURL: "http://agent:8080"}
	files := RenderTraefik("Web Frontend", cfg, []byte("FULLCHAIN"), []byte("KEY"))
	if len(files) != 4 {
		t.Fatalf("%d files", len(files))
	}
	acme := files[3]
	if acme.Path != "/etc/traefik/dynamic/certforge-acme-web-frontend.yml" || acme.Mode != "0644" {
		t.Fatalf("acme file %+v", acme)
	}
	path := filepath.Join("testdata", "traefik-acme.yml")
	if *update {
		if err := os.WriteFile(path, acme.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(acme.Data) != string(want) {
		t.Errorf("acme file:\n%s\nwant:\n%s", acme.Data, want)
	}

	// No acmeServiceUrl: no fourth file, same as before this task.
	if got := RenderTraefik("Web Frontend", TraefikConfig{Dir: "/etc/traefik/dynamic"}, []byte("FULLCHAIN"), []byte("KEY")); len(got) != 3 {
		t.Fatalf("without acmeServiceUrl: %d files", len(got))
	}

	// ParseTarget rejects a relative or non-http(s) acmeServiceUrl.
	for name, raw := range map[string]string{
		"relative": `{"dir":"/x","acmeServiceUrl":"/foo"}`,
		"ftp":      `{"dir":"/x","acmeServiceUrl":"ftp://agent:21"}`,
	} {
		var fe *FieldError
		if _, err := ParseTarget("traefik", json.RawMessage(raw)); !errors.As(err, &fe) || fe.Field != "config.acmeServiceUrl" {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestGrantFilesNoVersionEmitsACMEOnly covers C3: a grant on a certificate
// with no version yet still needs its Traefik ACME router file rendered, so
// the very first issuance can validate through Traefik.
func TestGrantFilesNoVersionEmitsACMEOnly(t *testing.T) {
	target := &agentproto.Target{Type: "traefik", Config: json.RawMessage(`{"dir":"/etc/traefik/dynamic","acmeServiceUrl":"http://agent:8080"}`)}
	files, err := GrantFiles(nil, nil, &Layout{Files: []OutputFile{okFile("/etc/ssl/web.pem")}}, target, "Web")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "/etc/traefik/dynamic/certforge-acme-web.yml" {
		t.Fatalf("files %+v", files)
	}

	noACME := &agentproto.Target{Type: "traefik", Config: json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`)}
	if files, err := GrantFiles(nil, nil, nil, noACME, "Web"); err != nil || len(files) != 0 {
		t.Fatalf("without acmeServiceUrl: files %+v err %v", files, err)
	}

	if files, err := GrantFiles(nil, nil, nil, nil, "Web"); err != nil || len(files) != 0 {
		t.Fatalf("no target: files %+v err %v", files, err)
	}
}
