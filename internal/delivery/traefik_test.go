package delivery

import (
	"bytes"
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
		files := RenderTraefik(tc.name, nil, tc.cfg, []byte("FULLCHAIN"), []byte("KEY"))
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
	files := RenderTraefik("Web Frontend", names, cfg, []byte("FULLCHAIN"), []byte("KEY"))
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
	if got := RenderTraefik("Web Frontend", names, TraefikConfig{Dir: "/etc/traefik/dynamic"}, []byte("FULLCHAIN"), []byte("KEY")); len(got) != 3 {
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

// TestAcmeRouterFileHostRule (fix-wave re-review): Host() takes exactly one
// argument on Traefik v3 (the version compose.test.yaml and docs/agent.md
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

// TestGrantFilesNoVersionEmitsACMEOnly covers C3: a grant on a certificate
// with no version yet still needs its Traefik ACME router file rendered, so
// the very first issuance can validate through Traefik.
func TestGrantFilesNoVersionEmitsACMEOnly(t *testing.T) {
	target := &agentproto.Target{Type: "traefik", Config: json.RawMessage(`{"dir":"/etc/traefik/dynamic","acmeServiceUrl":"http://agent:8080"}`)}
	files, err := GrantFiles(nil, nil, &Layout{Files: []OutputFile{okFile("/etc/ssl/web.pem")}}, target, "Web", []string{"web.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "/etc/traefik/dynamic/certforge-acme-web.yml" {
		t.Fatalf("files %+v", files)
	}

	noACME := &agentproto.Target{Type: "traefik", Config: json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`)}
	if files, err := GrantFiles(nil, nil, nil, noACME, "Web", []string{"web.example.test"}); err != nil || len(files) != 0 {
		t.Fatalf("without acmeServiceUrl: files %+v err %v", files, err)
	}

	if files, err := GrantFiles(nil, nil, nil, nil, "Web", []string{"web.example.test"}); err != nil || len(files) != 0 {
		t.Fatalf("no target: files %+v err %v", files, err)
	}
}
