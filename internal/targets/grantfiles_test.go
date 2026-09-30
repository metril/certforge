package targets

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
)

func okFile(path string) delivery.OutputFile {
	return delivery.OutputFile{Path: path, Format: "pem", Parts: []string{"fullchain"}, Mode: "0644"}
}

// TestGrantFilesLayoutAndTarget covers the combined case
// internal/delivery's own GrantFiles used to cover before it became
// layout-only: a grant's layout files, then its Traefik target's files, in
// write order.
func TestGrantFilesLayoutAndTarget(t *testing.T) {
	reg := NewRegistry()
	RegisterBuiltins(reg)
	m := &render.Material{LeafDER: []byte("leaf"), ChainDER: [][]byte{[]byte("int")}, PrivateKeyPKCS8: []byte("key")}
	target := &agentproto.Target{Type: "traefik", Config: json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`)}

	files, err := GrantFiles(reg, m, nil, &delivery.Layout{Files: []delivery.OutputFile{okFile("/etc/ssl/web.pem")}}, target, "Web", []string{"web.example.test"})
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
}

// TestGrantFilesNoVersionEmitsACMEOnly covers C3, moved from
// internal/delivery's own GrantFiles (now layout-only): a grant on a
// certificate with no version yet still needs its Traefik ACME router file
// rendered, so the very first issuance can validate through Traefik.
func TestGrantFilesNoVersionEmitsACMEOnly(t *testing.T) {
	reg := NewRegistry()
	RegisterBuiltins(reg)

	target := &agentproto.Target{Type: "traefik", Config: json.RawMessage(`{"dir":"/etc/traefik/dynamic","acmeServiceUrl":"http://agent:8080"}`)}
	files, err := GrantFiles(reg, nil, nil, &delivery.Layout{Files: []delivery.OutputFile{okFile("/etc/ssl/web.pem")}}, target, "Web", []string{"web.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "/etc/traefik/dynamic/certforge-acme-web.yml" {
		t.Fatalf("files %+v", files)
	}

	noACME := &agentproto.Target{Type: "traefik", Config: json.RawMessage(`{"dir":"/etc/traefik/dynamic"}`)}
	if files, err := GrantFiles(reg, nil, nil, nil, noACME, "Web", []string{"web.example.test"}); err != nil || len(files) != 0 {
		t.Fatalf("without acmeServiceUrl: files %+v err %v", files, err)
	}

	if files, err := GrantFiles(reg, nil, nil, nil, nil, "Web", []string{"web.example.test"}); err != nil || len(files) != 0 {
		t.Fatalf("no target: files %+v err %v", files, err)
	}
}

// TestGrantFilesUnknownType covers a target naming a type the registry does
// not hold.
func TestGrantFilesUnknownType(t *testing.T) {
	reg := NewRegistry()
	target := &agentproto.Target{Type: "nope", Config: json.RawMessage(`{}`)}
	if _, err := GrantFiles(reg, nil, nil, nil, target, "Web", nil); err == nil {
		t.Fatal("unknown type: want error")
	}
}
