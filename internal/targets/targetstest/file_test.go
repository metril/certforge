package targetstest_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/targetstest"
)

func TestFileParseRejectsMissingDir(t *testing.T) {
	f := &targetstest.File{Code: "file-test"}
	if _, err := f.Parse(json.RawMessage(`{}`)); err == nil {
		t.Fatal("Parse did not fail with no dir")
	}
}

func TestFileRunsOnAgentAlways(t *testing.T) {
	f := &targetstest.File{Code: "file-test"}
	if f.RunsOn() != targets.Agent {
		t.Errorf("RunsOn = %v, want Agent", f.RunsOn())
	}
	if f.KeyPolicy() != targets.Always {
		t.Errorf("KeyPolicy = %v, want Always", f.KeyPolicy())
	}
}

func TestFileFilesWritesSafeNamedPEM(t *testing.T) {
	f := &targetstest.File{Code: "file-test"}
	m := &render.Material{LeafDER: []byte("leaf-der-bytes")}
	req := targets.Request{CertName: "My Cert!", Material: m, Config: json.RawMessage(`{"dir":"/etc/certforge"}`)}

	files, err := f.Files(req)
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("Files returned %d files, want 1", len(files))
	}
	if files[0].Path != "/etc/certforge/my-cert.pem" {
		t.Errorf("Path = %q, want /etc/certforge/my-cert.pem", files[0].Path)
	}
	if !strings.Contains(string(files[0].Data), "BEGIN CERTIFICATE") {
		t.Errorf("Data does not contain a PEM certificate block: %s", files[0].Data)
	}

	paths, err := f.Paths(req.Config, req.CertName)
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	if len(paths) != 1 || paths[0] != files[0].Path {
		t.Errorf("Paths = %v, want [%s]", paths, files[0].Path)
	}
}

func TestFileFilesNoMaterial(t *testing.T) {
	f := &targetstest.File{Code: "file-test"}
	files, err := f.Files(targets.Request{CertName: "x", Config: json.RawMessage(`{"dir":"/d"}`)})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if files != nil {
		t.Fatalf("Files = %v, want nil for a version-less grant", files)
	}
}

func TestFileDeployHasNoSideEffects(t *testing.T) {
	f := &targetstest.File{Code: "file-test"}
	m := &render.Material{LeafDER: []byte("leaf-der-bytes")}
	req := targets.Request{CertName: "cert", Material: m, Config: json.RawMessage(`{"dir":"/etc/certforge"}`)}

	res, err := f.Deploy(context.Background(), req)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("Deploy result has %d files, want 1", len(res.Files))
	}
	if f.Reloads != 0 {
		t.Errorf("Deploy triggered a reload: Reloads = %d", f.Reloads)
	}
}

func TestFileReloadCountsAndReturnsErr(t *testing.T) {
	f := &targetstest.File{Code: "file-test"}
	if _, err := f.Reload(context.Background(), targets.Request{}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if f.Reloads != 1 {
		t.Fatalf("Reloads = %d, want 1", f.Reloads)
	}

	f.ReloadErr = errors.New("reload failed")
	if _, err := f.Reload(context.Background(), targets.Request{}); !errors.Is(err, f.ReloadErr) {
		t.Fatalf("Reload error = %v, want %v", err, f.ReloadErr)
	}
	if f.Reloads != 2 {
		t.Fatalf("Reloads = %d, want 2", f.Reloads)
	}
}
