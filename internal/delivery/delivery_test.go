package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/render"
)

var material = render.Material{LeafDER: []byte("leaf"), ChainDER: [][]byte{[]byte("int")}, PrivateKeyPKCS8: []byte("key")}

func okFile(path string) OutputFile {
	return OutputFile{Path: path, Format: "pem", Parts: []string{"fullchain"}, Mode: "0644"}
}

// Review Focus: unsafe paths never reach an agent.
func TestValidateFilesRejectsUnsafePaths(t *testing.T) {
	good := []OutputFile{okFile("/etc/ssl/web/fullchain.pem"),
		{Path: "/etc/ssl/web/key.pem", Format: "pem", Parts: []string{"key"}, Owner: "root", Group: "ssl-cert", Mode: "640"}}
	if err := ValidateFiles(good); err != nil {
		t.Fatal(err)
	}
	many := make([]OutputFile, 21)
	for i := range many {
		many[i] = okFile("/etc/ssl/f" + strings.Repeat("x", i) + ".pem")
	}
	for name, files := range map[string][]OutputFile{
		"none":      nil,
		"too many":  many,
		"relative":  {okFile("etc/ssl/x.pem")},
		"dotdot":    {okFile("/etc/../x.pem")},
		"dot":       {okFile("/etc/./x.pem")},
		"trailing":  {okFile("/etc/ssl/")},
		"root":      {okFile("/")},
		"nul":       {okFile("/etc/x\x00.pem")},
		"duplicate": {okFile("/etc/x.pem"), okFile("/etc/x.pem")},
		"format":    {{Path: "/etc/x.der", Format: "der", Parts: []string{"cert"}, Mode: "0644"}},
		"no parts":  {{Path: "/etc/x.pem", Format: "pem", Mode: "0644"}},
		"bad part":  {{Path: "/etc/x.pem", Format: "pem", Parts: []string{"pfx"}, Mode: "0644"}},
		"bad mode":  {{Path: "/etc/x.pem", Format: "pem", Parts: []string{"cert"}, Mode: "0999"}},
		"bad owner": {{Path: "/etc/x.pem", Format: "pem", Parts: []string{"cert"}, Owner: "a b", Mode: "0644"}},
	} {
		var fe *FieldError
		if err := ValidateFiles(files); !errors.As(err, &fe) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRenderLayoutConcatenatesParts(t *testing.T) {
	files, err := RenderLayout(material, []OutputFile{{Path: "/etc/x.pem", Format: "pem", Parts: []string{"cert", "key"}, Owner: "root", Mode: "640"}})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := render.PEM{}.Render(material, render.OutputOpts{Parts: []string{"cert", "key"}})
	if len(files) != 1 || !bytes.Equal(files[0].Data, append(append([]byte{}, want[0].Data...), want[1].Data...)) ||
		files[0].Mode != "0640" || files[0].Owner != "root" {
		t.Fatalf("files %+v", files)
	}
	if _, err := RenderLayout(render.Material{LeafDER: []byte("leaf")}, []OutputFile{{Path: "/k", Format: "pem", Parts: []string{"key"}, Mode: "0600"}}); !errors.Is(err, render.ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
}

// Review Focus: certificate names never escape the target directory.
func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"Web Frontend":     "web-frontend",
		"../../etc":        "etc",
		"..":               "cert",
		"api.example.test": "api.example.test",
		"*.example.test":   "example.test",
		"a/b":              "a-b",
	} {
		if got := SafeName(in); got != want || strings.Contains(got, "/") {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTarget(t *testing.T) {
	if c, err := ParseTarget("traefik", json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`)); err != nil || c.Dir != "/etc/traefik/dynamic" {
		t.Fatalf("valid: %+v %v", c, err)
	}
	for name, tc := range map[string]struct{ typ, raw, field string }{
		"type":       {"nginx", `{"dir":"/x"}`, "type"},
		"unknown":    {"traefik", `{"dir":"/x","nope":1}`, "config"},
		"relative":   {"traefik", `{"dir":"etc/traefik"}`, "config.dir"},
		"prefix":     {"traefik", `{"dir":"/x","pathPrefix":"rel"}`, "config.pathPrefix"},
		"store name": {"traefik", `{"dir":"/x","stores":["a b"]}`, "config.stores"},
	} {
		var fe *FieldError
		if _, err := ParseTarget(tc.typ, json.RawMessage(tc.raw)); !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestGrantFilesOrderAndDigests(t *testing.T) {
	target := &agentproto.Target{Type: "traefik", Config: json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`)}
	files, err := GrantFiles(material, []OutputFile{okFile("/etc/ssl/web.pem")}, target, "Web")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	want := "/etc/ssl/web.pem,/etc/traefik/dynamic/certs/web/fullchain.pem,/etc/traefik/dynamic/certs/web/privkey.pem,/etc/traefik/dynamic/certforge-web.yml"
	if strings.Join(paths, ",") != want {
		t.Fatalf("paths %v", paths)
	}
	specs := Specs(files)
	if specs[2].Mode != "0600" || specs[2].SHA256 != Digest(files[2].Data) || len(specs[0].SHA256) != 64 {
		t.Fatalf("specs %+v", specs)
	}
	m, _ := TargetMaterial(material)
	if !bytes.Equal(files[1].Data, m.Fullchain) || !bytes.Equal(files[2].Data, m.Key) {
		t.Fatal("target material differs from the rendered target files")
	}
}

func TestCompare(t *testing.T) {
	expected := []agentproto.FileSpec{{Path: "/a", SHA256: "1"}, {Path: "/b", SHA256: "2"}, {Path: "/c", SHA256: "3"}, {Path: "/d", SHA256: "4"}}
	installed := []agentproto.FileDigest{{Path: "/a", SHA256: "1"}, {Path: "/b", SHA256: "9"}, {Path: "/c", SHA256: ""}, {Path: "/z", SHA256: "0"}}
	missing, mismatched := Compare(expected, installed)
	if strings.Join(missing, ",") != "/c,/d" || strings.Join(mismatched, ",") != "/b" {
		t.Fatalf("missing %v mismatched %v", missing, mismatched)
	}
}

func TestValidateHook(t *testing.T) {
	if err := ValidateHook("post_deploy", []string{"/usr/local/bin/reload-nginx", "--quiet"}, 60); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		phase   string
		argv    []string
		timeout int
	}{
		"phase":    {"post_issue", []string{"/bin/true"}, 60},
		"empty":    {"post_deploy", nil, 60},
		"shell":    {"post_deploy", []string{"sh", "-c", "reload"}, 60},
		"relative": {"post_deploy", []string{"bin/reload"}, 60},
		"timeout":  {"post_deploy", []string{"/bin/true"}, 0},
		"long":     {"post_deploy", []string{"/bin/true"}, 3601},
	} {
		var fe *FieldError
		if err := ValidateHook(tc.phase, tc.argv, tc.timeout); !errors.As(err, &fe) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
