//go:build unix

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

func testDeployer(writeAllow []string, hookAllow ...string) *Deployer {
	return &Deployer{Files: &FileWriter{Log: discard, EUID: 1000, Lookup: lookupIDs}, Hooks: &HookRunner{Allow: hookAllow}, Log: discard, WriteAllow: writeAllow}
}

func traefikGrant(dir string) (agentproto.Assignment, agentproto.Bundle) {
	cfg, _ := json.Marshal(map[string]string{"dir": filepath.Join(dir, "traefik")})
	versionID := uuid.New()
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "Web", VersionID: &versionID, Target: &agentproto.Target{Type: "traefik", Config: cfg}}
	b := agentproto.Bundle{VersionID: versionID,
		Files:    []agentproto.BundleFile{{Path: filepath.Join(dir, "ssl", "web.pem"), Mode: "0644", Content: []byte("PEM")}},
		Material: &agentproto.Material{Fullchain: []byte("FULL"), Key: []byte("KEY")}}
	return a, b
}

func TestDeployerLayoutTraefikAndRemove(t *testing.T) {
	dir := t.TempDir()
	d := testDeployer([]string{dir})
	a, b := traefikGrant(dir)
	res, written, certsDir := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateOK || len(written) != 4 || len(res.Installed) != 4 || res.VersionID != *a.VersionID {
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
	if certsDir != filepath.Join(dir, "traefik", "certs", "web") {
		t.Fatalf("certsDir %q", certsDir)
	}
	removed, err := d.Remove(written, certsDir)
	if err != nil || removed[0] != yml {
		t.Fatalf("removal order %v %v", removed, err)
	}
	for _, f := range written {
		if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", f.Path)
		}
	}
	if _, err := os.Stat(certsDir); !os.IsNotExist(err) {
		t.Fatal("empty certs/<name> directory left behind")
	}
}

func TestDeployerPreHookFailureWritesNothing(t *testing.T) {
	dir := t.TempDir()
	a, b := traefikGrant(dir)
	a.Hooks = []agentproto.HookSpec{{ID: uuid.New(), Phase: "pre_deploy", Argv: []string{"/bin/sh", "-c", "exit 2"}, TimeoutSeconds: 5}}
	res, written, _ := testDeployer([]string{dir}, "/bin/sh").Deploy(context.Background(), a, b)
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
	res, written, _ := testDeployer([]string{dir}, "/bin/sh").Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "post_deploy") || len(written) != 4 {
		t.Fatalf("res %+v", res)
	}
}

// Review Focus (fix round 2, Minor): a versioned assignment (a.VersionID
// set) whose bundle has no material must fail outright, even when the
// target has acmeServiceUrl set — never silently write just the ACME file
// and report ok, which would make the server's own digest comparison mark
// it drift (the server's expected list for a versioned target always
// includes the certificate files too). The version-less case (C3) never
// reaches Deploy at all; see TestReconcileDeploysVersionlessACMEFileWithoutBundle.
func TestDeployerTargetWithoutMaterialFails(t *testing.T) {
	for name, acmeServiceURL := range map[string]string{"no acmeServiceUrl": "", "with acmeServiceUrl": "http://agent:8080"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg, _ := json.Marshal(delivery.TraefikConfig{Dir: filepath.Join(dir, "traefik"), AcmeServiceURL: acmeServiceURL})
			versionID := uuid.New()
			a := agentproto.Assignment{ID: uuid.New(), CertificateName: "Web", VersionID: &versionID, Target: &agentproto.Target{Type: "traefik", Config: cfg}}
			b := agentproto.Bundle{VersionID: versionID}
			res, written, _ := testDeployer([]string{dir}).Deploy(context.Background(), a, b)
			if res.State != agentproto.StateFailed || len(written) != 0 {
				t.Fatalf("res %+v written %d", res, len(written))
			}
		})
	}
}

// Review Focus: a mismatched bundle version is never installed.
func TestDeployerVersionMismatchFails(t *testing.T) {
	dir := t.TempDir()
	a, b := traefikGrant(dir)
	b.VersionID = uuid.New()
	res, written, _ := testDeployer([]string{dir}).Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "version") || len(written) != 0 {
		t.Fatalf("res %+v", res)
	}
}

// Review Focus: a world-writable mode is refused even if the server sent it.
func TestDeployerWorldWritableModeFails(t *testing.T) {
	dir := t.TempDir()
	a, b := traefikGrant(dir)
	b.Files[0].Mode = "0646"
	res, written, _ := testDeployer([]string{dir}).Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "world-writable") || len(written) != 0 {
		t.Fatalf("res %+v", res)
	}
}

// Review Focus: writes and removes are confined to CF_WRITE_ALLOW.
func TestDeployerWriteAllowConfinement(t *testing.T) {
	dir := t.TempDir()

	t.Run("empty allowlist refuses", func(t *testing.T) {
		a, b := traefikGrant(dir)
		res, written, _ := testDeployer(nil).Deploy(context.Background(), a, b)
		if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "CF_WRITE_ALLOW") || len(written) != 0 {
			t.Fatalf("res %+v", res)
		}
	})

	t.Run("path outside allowlist refused on deploy", func(t *testing.T) {
		a, b := traefikGrant(dir)
		res, written, _ := testDeployer([]string{filepath.Join(dir, "traefik")}).Deploy(context.Background(), a, b)
		if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "CF_WRITE_ALLOW") || len(written) != 0 {
			t.Fatalf("res %+v (layout file outside the allowlist should be refused)", res)
		}
	})

	t.Run("allowed path works", func(t *testing.T) {
		a, b := traefikGrant(dir)
		res, written, _ := testDeployer([]string{dir}).Deploy(context.Background(), a, b)
		if res.State != agentproto.StateOK || len(written) != 4 {
			t.Fatalf("res %+v", res)
		}
	})

	t.Run("path outside allowlist refused on remove", func(t *testing.T) {
		a, b := traefikGrant(dir)
		d := testDeployer([]string{dir})
		res, written, certsDir := d.Deploy(context.Background(), a, b)
		if res.State != agentproto.StateOK {
			t.Fatalf("setup deploy: %+v", res)
		}
		d.WriteAllow = []string{filepath.Join(dir, "traefik")} // no longer covers dir/ssl/web.pem
		if _, err := d.Remove(written, certsDir); err == nil || !strings.Contains(err.Error(), "CF_WRITE_ALLOW") {
			t.Fatalf("remove outside allowlist: err = %v", err)
		}
	})

	t.Run("symlinked parent pointing outside refused", func(t *testing.T) {
		root := t.TempDir()
		safe := filepath.Join(root, "safe")
		escape := filepath.Join(root, "escape")
		if err := os.Mkdir(safe, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(escape, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(escape, filepath.Join(safe, "link")); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(safe, "link", "evil.pem")
		if _, err := confine([]string{safe}, p); err == nil || !strings.Contains(err.Error(), "CF_WRITE_ALLOW") {
			t.Fatalf("confine via symlinked parent: err = %v", err)
		}
	})
}

// Review Focus: a pre_deploy hook runs arbitrary code between the first
// confinement check and the write; it must not be able to swap a symlink
// into an already-checked path to escape CF_WRITE_ALLOW.
func TestDeployerReConfinesAfterPreDeployHookSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	d := testDeployer([]string{dir}, "/bin/sh")
	versionID := uuid.New()
	p := filepath.Join(sub, "web.pem")
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "web", VersionID: &versionID,
		Hooks: []agentproto.HookSpec{{ID: uuid.New(), Phase: "pre_deploy",
			Argv:           []string{"/bin/sh", "-c", fmt.Sprintf("rm -rf %s && ln -s %s %s", sub, outside, sub)},
			TimeoutSeconds: 5}}}
	b := agentproto.Bundle{VersionID: versionID, Files: []agentproto.BundleFile{{Path: p, Mode: "0644", Content: []byte("PEM")}}}
	res, written, _ := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "CF_WRITE_ALLOW") || len(written) != 0 {
		t.Fatalf("res %+v", res)
	}
	if _, err := os.Stat(filepath.Join(outside, "web.pem")); !os.IsNotExist(err) {
		t.Fatal("file written outside CF_WRITE_ALLOW through a symlink a pre_deploy hook swapped in")
	}
}

// Review Focus: Remove refuses an unclean path before it ever reaches
// confine, the same as Deploy does.
func TestDeployerRemoveRejectsUncleanPath(t *testing.T) {
	dir := t.TempDir()
	d := testDeployer([]string{dir})
	_, err := d.Remove([]agentproto.FileSpec{{Path: dir + "/../evil"}}, "")
	if err == nil || strings.Contains(err.Error(), "CF_WRITE_ALLOW") {
		t.Fatalf("err = %v", err)
	}
}
