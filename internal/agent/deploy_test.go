//go:build unix

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

func testDeployer(allow ...string) *Deployer {
	return &Deployer{Files: &FileWriter{Log: discard, EUID: 1000, Lookup: lookupIDs}, Hooks: &HookRunner{Allow: allow}, Log: discard}
}

func traefikGrant(dir string) (agentproto.Assignment, agentproto.Bundle) {
	cfg, _ := json.Marshal(map[string]string{"dir": filepath.Join(dir, "traefik")})
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "Web", VersionID: uuid.New(), Target: &agentproto.Target{Type: "traefik", Config: cfg}}
	b := agentproto.Bundle{VersionID: a.VersionID,
		Files:    []agentproto.BundleFile{{Path: filepath.Join(dir, "ssl", "web.pem"), Mode: "0644", Content: []byte("PEM")}},
		Material: &agentproto.Material{Fullchain: []byte("FULL"), Key: []byte("KEY")}}
	return a, b
}

func TestDeployerLayoutTraefikAndRemove(t *testing.T) {
	dir := t.TempDir()
	d := testDeployer()
	a, b := traefikGrant(dir)
	res, written := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateOK || len(written) != 4 || len(res.Installed) != 4 || res.VersionID != a.VersionID {
		t.Fatalf("res %+v written %d", res, len(written))
	}
	yml := filepath.Join(dir, "traefik", "certforge-web.yml")
	want := delivery.RenderTraefik("Web", delivery.TraefikConfig{Dir: filepath.Join(dir, "traefik")}, []byte("FULL"), []byte("KEY"))
	got, _ := os.ReadFile(yml)
	if !bytes.Equal(got, want[2].Data) || mode(t, filepath.Join(dir, "traefik", "certs", "web", "privkey.pem")) != 0o600 {
		t.Fatalf("yml %s", got)
	}
	if written[0].SHA256 != delivery.Digest([]byte("PEM")) || written[3].Path != yml {
		t.Fatalf("written %+v", written)
	}
	removed, err := d.Remove(written)
	if err != nil || removed[0] != yml {
		t.Fatalf("removal order %v %v", removed, err)
	}
	for _, f := range written {
		if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", f.Path)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "traefik", "certs", "web")); !os.IsNotExist(err) {
		t.Fatal("empty certs/<name> directory left behind")
	}
}

func TestDeployerPreHookFailureWritesNothing(t *testing.T) {
	dir := t.TempDir()
	a, b := traefikGrant(dir)
	a.Hooks = []agentproto.HookSpec{{ID: uuid.New(), Phase: "pre_deploy", Argv: []string{"/bin/sh", "-c", "exit 2"}, TimeoutSeconds: 5}}
	res, written := testDeployer("/bin/sh").Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "pre_deploy") || len(written) != 0 || len(res.HookRuns) != 1 || res.HookRuns[0].ExitCode != 2 {
		t.Fatalf("res %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "ssl", "web.pem")); !os.IsNotExist(err) {
		t.Fatal("file written despite a failed pre_deploy hook")
	}
}

func TestDeployerPostHookFailureKeepsFiles(t *testing.T) {
	dir := t.TempDir()
	a, b := traefikGrant(dir)
	a.Hooks = []agentproto.HookSpec{{ID: uuid.New(), Phase: "post_deploy", Argv: []string{"/bin/sh", "-c", "exit 1"}, TimeoutSeconds: 5}}
	res, written := testDeployer("/bin/sh").Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "post_deploy") || len(written) != 4 {
		t.Fatalf("res %+v", res)
	}
}

func TestDeployerTargetWithoutMaterialFails(t *testing.T) {
	a, b := traefikGrant(t.TempDir())
	b.Material = nil
	if res, _ := testDeployer().Deploy(context.Background(), a, b); res.State != agentproto.StateFailed {
		t.Fatalf("res %+v", res)
	}
}
