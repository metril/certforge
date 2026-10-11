package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestRenderTraefikGolden(t *testing.T) {
	for _, tc := range []struct {
		golden, name string
		cfg          TraefikConfig
		opts         TraefikGrantOptions
		paths        [3]string
	}{
		{"traefik-basic.yml", "Web Frontend", TraefikConfig{Dir: "/etc/traefik/dynamic"}, TraefikGrantOptions{},
			[3]string{"/etc/traefik/dynamic/certs/web-frontend/fullchain.pem", "/etc/traefik/dynamic/certs/web-frontend/privkey.pem", "/etc/traefik/dynamic/certforge-web-frontend.yml"}},
		{"traefik-default.yml", "api.example.test", TraefikConfig{Dir: "/data/traefik", PathPrefix: "/etc/traefik/dynamic", Stores: []string{"default", "internal"}}, TraefikGrantOptions{DefaultCert: true},
			[3]string{"/data/traefik/certs/api.example.test/fullchain.pem", "/data/traefik/certs/api.example.test/privkey.pem", "/data/traefik/certforge-api.example.test.yml"}},
	} {
		files := RenderTraefik(tc.name, nil, tc.cfg, tc.opts, []byte("FULLCHAIN"), []byte("KEY"))
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
	// A wildcard SAN alongside the two ordinary names: it must not appear
	// in the router at all (Traefik v3 rejects Host(`*...`), and no ACME
	// challenge type validates a wildcard over http-01 anyway).
	names := []string{"web-frontend.example.test", "www.web-frontend.example.test", "*.web-frontend.example.test"}
	files := RenderTraefik("Web Frontend", names, cfg, TraefikGrantOptions{}, []byte("FULLCHAIN"), []byte("KEY"))
	if len(files) != 4 {
		t.Fatalf("%d files", len(files))
	}
	acme := files[3]
	if acme.Path != "/etc/traefik/dynamic/certforge-acme-web-frontend.yml" || acme.Mode != "0644" {
		t.Fatalf("acme file %+v", acme)
	}
	if bytes.Contains(acme.Data, []byte("*.")) {
		t.Fatalf("wildcard leaked into the router file:\n%s", acme.Data)
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
	if got := RenderTraefik("Web Frontend", names, TraefikConfig{Dir: "/etc/traefik/dynamic"}, TraefikGrantOptions{}, []byte("FULLCHAIN"), []byte("KEY")); len(got) != 3 {
		t.Fatalf("without acmeServiceUrl: %d files", len(got))
	}

	// ParseTraefik rejects a relative or non-http(s) acmeServiceUrl.
	for name, raw := range map[string]string{
		"relative": `{"dir":"/x","acmeServiceUrl":"/foo"}`,
		"ftp":      `{"dir":"/x","acmeServiceUrl":"ftp://agent:21"}`,
	} {
		var fe *FieldError
		if _, err := ParseTraefik(json.RawMessage(raw)); !errors.As(err, &fe) || fe.Field != "config.acmeServiceUrl" {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestAcmeRouterFileHostRule (fix-wave re-review): Host() takes exactly one
// argument on Traefik v3 (the version compose.test.yaml and docs/guide/delivery.md
// use) — `Host(`a`,`b`)` is invalid and the whole router is rejected, not
// just under-matched. A single name still renders a plain `Host(`a`) &&
// PathPrefix(...)`; two or more render an OR chain of one-argument Host()
// calls, parenthesized so `&&` binds the whole disjunction, not just its
// last term.
func TestAcmeRouterFileHostRule(t *testing.T) {
	cfg := TraefikConfig{Dir: "/etc/traefik/dynamic", AcmeServiceURL: "http://agent:8080"}
	cases := []struct {
		name  string
		names []string
		rule  string
	}{
		{"single name", []string{"web.example.test"},
			"Host(`web.example.test`) && PathPrefix(`/.well-known/acme-challenge/`)"},
		{"two names", []string{"web.example.test", "www.web.example.test"},
			"(Host(`web.example.test`) || Host(`www.web.example.test`)) && PathPrefix(`/.well-known/acme-challenge/`)"},
		{"three names", []string{"a.test", "b.test", "c.test"},
			"(Host(`a.test`) || Host(`b.test`) || Host(`c.test`)) && PathPrefix(`/.well-known/acme-challenge/`)"},
		// Traefik v3 rejects Host(`*.example.test`) outright (host
		// matching does not accept wildcards there), and no ACME challenge
		// type validates a wildcard name over http-01 anyway — the router
		// only needs to claim requests for names it could ever prove
		// control of. A mixed apex + wildcard certificate (a common shape:
		// CommonName the apex, one SAN its wildcard) keeps the apex only.
		{"mixed apex and wildcard", []string{"apex.example.test", "*.apex.example.test"},
			"Host(`apex.example.test`) && PathPrefix(`/.well-known/acme-challenge/`)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := AcmeRouterFile("web", tc.names, cfg)
			if f == nil {
				t.Fatal("no ACME router file")
			}
			want := "      rule: " + tc.rule + "\n"
			if !bytes.Contains(f.Data, []byte(want)) {
				t.Errorf("rule line not found; want %q in:\n%s", want, f.Data)
			}
			if bytes.Contains(f.Data, []byte("*.")) {
				t.Errorf("wildcard leaked into the router file:\n%s", f.Data)
			}
		})
	}
}

// TestAcmeRouterFileAllWildcardOmitsFile (fix-wave re-review): a
// certificate whose every name is a wildcard has nothing an http-01 router
// could ever validate — Host(`*.example.test`) is also invalid Traefik v3
// syntax — so AcmeRouterFile renders no file at all, the same as an unset
// acmeServiceUrl, rather than a router with an empty or invalid Host().
func TestAcmeRouterFileAllWildcardOmitsFile(t *testing.T) {
	cfg := TraefikConfig{Dir: "/etc/traefik/dynamic", AcmeServiceURL: "http://agent:8080"}
	if f := AcmeRouterFile("web", []string{"*.example.test"}, cfg); f != nil {
		t.Fatalf("all-wildcard: got a file, want nil: %+v", f)
	}
	if f := AcmeRouterFile("web", []string{"*.example.test", "*.other.test"}, cfg); f != nil {
		t.Fatalf("all-wildcard (multiple): got a file, want nil: %+v", f)
	}
}

// TestGrantFilesNoVersionEmitsNothing covers C3, the layout-only half:
// GrantFiles renders nothing for a certificate with no version yet — a
// layout never renders without material. The Traefik ACME-router-only case
// this test covered before this task moved to
// internal/targets.TestGrantFilesNoVersionEmitsACMEOnly, now that a
// target's own files are targets.GrantFiles' job, not this package's.
func TestGrantFilesNoVersionEmitsNothing(t *testing.T) {
	if files, err := GrantFiles(nil, nil, &Layout{Files: []OutputFile{okFile("/etc/ssl/web.pem")}}); err != nil || len(files) != 0 {
		t.Fatalf("files %+v err %v", files, err)
	}
}

func renderPaths(files []File) (certDir, yml string) {
	return path.Dir(files[0].Path), string(files[2].Data)
}

func TestRenderTraefikGrantOptions(t *testing.T) {
	cfg := TraefikConfig{Dir: "/data/traefik", PathPrefix: "/etc/traefik/dynamic"}
	fc, key := []byte("FULLCHAIN"), []byte("KEY")
	for _, tc := range []struct {
		name      string
		cfg       TraefikConfig
		opts      TraefikGrantOptions
		wantDir   string
		wantInYML []string
		notInYML  []string
	}{
		{"custom dir under dir derives traefik path", cfg, TraefikGrantOptions{CertsDir: "/data/traefik/tls/web"},
			"/data/traefik/tls/web", []string{`certFile: "/etc/traefik/dynamic/tls/web/fullchain.pem"`, `keyFile: "/etc/traefik/dynamic/tls/web/privkey.pem"`}, nil},
		{"custom dir equal to dir", cfg, TraefikGrantOptions{CertsDir: "/data/traefik"},
			"/data/traefik", []string{`certFile: "/etc/traefik/dynamic/fullchain.pem"`}, nil},
		{"custom dir outside dir keeps path", cfg, TraefikGrantOptions{CertsDir: "/srv/tls/web"},
			"/srv/tls/web", []string{`certFile: "/srv/tls/web/fullchain.pem"`}, nil},
		{"sibling prefix is not under dir", cfg, TraefikGrantOptions{CertsDir: "/data/traefik2/web"},
			"/data/traefik2/web", []string{`certFile: "/data/traefik2/web/fullchain.pem"`}, nil},
		{"no pathPrefix keeps path", TraefikConfig{Dir: "/data/traefik"}, TraefikGrantOptions{CertsDir: "/data/traefik/tls/web"},
			"/data/traefik/tls/web", []string{`certFile: "/data/traefik/tls/web/fullchain.pem"`}, nil},
		{"explicit certsDirTraefik wins", cfg, TraefikGrantOptions{CertsDir: "/data/traefik/tls/web", CertsDirTraefik: "/mnt/x"},
			"/data/traefik/tls/web", []string{`certFile: "/mnt/x/fullchain.pem"`, `keyFile: "/mnt/x/privkey.pem"`}, nil},
		{"stores override", TraefikConfig{Dir: "/d", Stores: []string{"a"}}, TraefikGrantOptions{Stores: []string{"b", "c"}},
			"/d/certs/web", []string{`- "b"`, `- "c"`}, []string{`- "a"`}},
		{"target stores used", TraefikConfig{Dir: "/d", Stores: []string{"a"}}, TraefikGrantOptions{},
			"/d/certs/web", []string{`- "a"`}, nil},
		{"default cert via options", TraefikConfig{Dir: "/d"}, TraefikGrantOptions{DefaultCert: true},
			"/d/certs/web", []string{"defaultCertificate:"}, nil},
		{"no default cert", TraefikConfig{Dir: "/d"}, TraefikGrantOptions{},
			"/d/certs/web", nil, []string{"defaultCertificate:"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := RenderTraefik("web", nil, tc.cfg, tc.opts, fc, key)
			dir, yml := renderPaths(files)
			if dir != tc.wantDir || files[1].Path != tc.wantDir+"/privkey.pem" || files[0].Path != tc.wantDir+"/fullchain.pem" {
				t.Fatalf("dir = %s, files %s %s", dir, files[0].Path, files[1].Path)
			}
			if files[2].Path != path.Join(tc.cfg.Dir, "certforge-web.yml") {
				t.Errorf("yml path %s", files[2].Path)
			}
			for _, w := range tc.wantInYML {
				if !strings.Contains(yml, w) {
					t.Errorf("missing %q in:\n%s", w, yml)
				}
			}
			for _, w := range tc.notInYML {
				if strings.Contains(yml, w) {
					t.Errorf("unexpected %q in:\n%s", w, yml)
				}
			}
		})
	}
}

func TestParseTraefikGrantOptions(t *testing.T) {
	for _, raw := range []string{"", "null", "{}"} {
		got, err := ParseTraefikGrantOptions(json.RawMessage(raw))
		if err != nil || got.DefaultCert || got.CertsDir != "" || got.CertsDirTraefik != "" || got.Stores != nil {
			t.Errorf("%q: %+v %v", raw, got, err)
		}
	}
	got, err := ParseTraefikGrantOptions(json.RawMessage(`{"defaultCert":true,"certsDir":"/a/b","certsDirTraefik":"/c","stores":["x"]}`))
	if err != nil || !got.DefaultCert || got.CertsDir != "/a/b" || got.CertsDirTraefik != "/c" || len(got.Stores) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	for name, tc := range map[string]struct{ raw, field string }{
		"relative certsDir":        {`{"certsDir":"a/b"}`, "targetOptions.certsDir"},
		"unclean certsDir":         {`{"certsDir":"/a/../b"}`, "targetOptions.certsDir"},
		"relative certsDirTraefik": {`{"certsDirTraefik":"x"}`, "targetOptions.certsDirTraefik"},
		"unknown field":            {`{"bogus":1}`, "targetOptions"},
		"bad store":                {`{"stores":["a b"]}`, "targetOptions.stores"},
	} {
		var fe *FieldError
		if _, err := ParseTraefikGrantOptions(json.RawMessage(tc.raw)); !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if !json.Valid([]byte(TraefikGrantSchema)) {
		t.Error("TraefikGrantSchema is not valid JSON")
	}
}

func TestParseTraefikRejectsStaleDefaultCert(t *testing.T) {
	var fe *FieldError
	if _, err := ParseTraefik(json.RawMessage(`{"dir":"/x","defaultCert":true}`)); !errors.As(err, &fe) || fe.Field != "config" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(TraefikSchema, "defaultCert") {
		t.Error("TraefikSchema still has defaultCert")
	}
}
