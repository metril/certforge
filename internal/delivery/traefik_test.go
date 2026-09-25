package delivery

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
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
