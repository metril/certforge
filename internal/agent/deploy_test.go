//go:build unix

package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/targetstest"
)

func testDeployer(writeAllow []string, hookAllow ...string) *Deployer {
	return testDeployerReg(NewTargetsRegistry(), writeAllow, hookAllow...)
}

// testDeployerReg is testDeployer with a caller-supplied registry, for a
// test that needs a target type NewTargetsRegistry does not carry (a
// non-file type, or a recordingFileTarget double).
func testDeployerReg(reg *targets.Registry, writeAllow []string, hookAllow ...string) *Deployer {
	return &Deployer{Files: &FileWriter{Log: discard, EUID: 1000, Lookup: lookupIDs}, Hooks: &HookRunner{Allow: hookAllow}, Log: discard,
		WriteAllow: writeAllow, Reg: reg, HTTP: targets.HTTPFactory{AllowLoopback: true}}
}

// testMaterial returns a real, self-signed leaf certificate and PKCS#8 key,
// canonically PEM-encoded (the same encoding render.PEM{}.Render produces:
// a bare CERTIFICATE/PRIVATE KEY block, no extra headers) so that a
// registry-dispatched Traefik target's targets.MaterialFromPEM ->
// delivery.TargetMaterial round trip reproduces these exact bytes —
// required now that Deploy renders Traefik through the same FileTarget
// path as every other target, rather than passing the bundle's PEM straight
// through unparsed. Computed once and reused: a fresh keypair per call
// would still work, but this suite calls it many times.
var testMaterial = sync.OnceValues(func() (fullchain, key []byte) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "web.example.test"},
		NotBefore: now, NotAfter: now.AddDate(0, 3, 0), DNSNames: []string{"web.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		panic(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
})

func traefikGrant(dir string) (agentproto.Assignment, agentproto.Bundle) {
	cfg, _ := json.Marshal(map[string]string{"dir": filepath.Join(dir, "traefik")})
	versionID := uuid.New()
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "Web", VersionID: &versionID, Target: &agentproto.Target{Type: "traefik", Config: cfg}}
	fullchain, key := testMaterial()
	b := agentproto.Bundle{VersionID: versionID,
		Files:    []agentproto.BundleFile{{Path: filepath.Join(dir, "ssl", "web.pem"), Mode: "0644", Content: []byte("PEM")}},
		Material: &agentproto.Material{Fullchain: fullchain, Key: key}}
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
	fullchain, key := testMaterial()
	want := delivery.RenderTraefik("Web", nil, delivery.TraefikConfig{Dir: filepath.Join(dir, "traefik")}, fullchain, key)
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

// TestDeployerUnknownTargetTypeFails covers the batch-1 review fix: a
// target whose config happens to decode as a valid TraefikConfig
// ({"dir":...}) is never rendered as Traefik unless its own Type actually
// says "traefik" — an unsupported type fails outright instead of being
// silently treated as one.
func TestDeployerUnknownTargetTypeFails(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := json.Marshal(map[string]string{"dir": filepath.Join(dir, "traefik")})
	versionID := uuid.New()
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "Web", VersionID: &versionID, Target: &agentproto.Target{Type: "vault-kv", Config: cfg}}
	b := agentproto.Bundle{VersionID: versionID, Material: &agentproto.Material{Fullchain: []byte("FULL"), Key: []byte("KEY")}}
	res, written, _ := testDeployer([]string{dir}).Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "vault-kv") || len(written) != 0 {
		t.Fatalf("res %+v written %d", res, len(written))
	}
	if _, err := os.Stat(filepath.Join(dir, "traefik")); !os.IsNotExist(err) {
		t.Fatal("files written for an unsupported target type")
	}
}

// TestDeployTargetOnlyUnknownTargetTypeFails is
// TestDeployerUnknownTargetTypeFails' DeployTargetOnly (C3, no version yet)
// counterpart.
func TestDeployTargetOnlyUnknownTargetTypeFails(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := json.Marshal(map[string]string{"dir": filepath.Join(dir, "traefik"), "acmeServiceUrl": "http://agent:8080"})
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "Web", Target: &agentproto.Target{Type: "vault-kv", Config: cfg}}
	res, written, _ := testDeployer([]string{dir}).DeployTargetOnly(a)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "vault-kv") || len(written) != 0 {
		t.Fatalf("res %+v written %d", res, len(written))
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

// recordingFileTarget is a package-local FileTarget+Reloader test double
// that records every Request it is given and can be made to fail on
// demand. targetstest.File (internal/targets/targetstest) has no room for
// that and is, deliberately, off limits to certforge-agent's own non-test
// build (TestAgentImports); this double keeps the test next to what it
// exercises instead. Its schema marks "token" secret, for
// TestAgentReportRedacted.
type recordingFileTarget struct {
	code        string
	dir         string
	filesCalls  []targets.Request
	filesErr    error
	reloadCalls []targets.Request
	reloadErr   error
}

func (r *recordingFileTarget) Type() string { return r.code }
func (r *recordingFileTarget) Name() string { return r.code }
func (r *recordingFileTarget) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"token":{"type":"string","secret":true,"description":"a secret"}}}`)
}
func (r *recordingFileTarget) RunsOn() targets.Mode         { return targets.Agent }
func (r *recordingFileTarget) KeyPolicy() targets.KeyPolicy { return targets.Always }

func (r *recordingFileTarget) Parse(raw json.RawMessage) (targets.Config, error) {
	pub, secrets, err := targets.Split(r.Schema(), raw)
	if err != nil {
		return targets.Config{}, err
	}
	return targets.Config{Public: pub, Secrets: secrets, NeedsKey: true}, nil
}

func (r *recordingFileTarget) Deploy(_ context.Context, req targets.Request) (targets.Result, error) {
	files, err := r.Files(req)
	if err != nil {
		return targets.Result{}, err
	}
	return targets.Result{Files: files}, nil
}

func (r *recordingFileTarget) Files(req targets.Request) ([]delivery.File, error) {
	r.filesCalls = append(r.filesCalls, req)
	if r.filesErr != nil {
		return nil, r.filesErr
	}
	if req.Material == nil {
		return nil, nil
	}
	return []delivery.File{{Path: filepath.Join(r.dir, "out.pem"), Mode: "0644", Data: []byte("data")}}, nil
}

func (r *recordingFileTarget) Paths(_ json.RawMessage, _ string) ([]string, error) {
	return []string{filepath.Join(r.dir, "out.pem")}, nil
}

func (r *recordingFileTarget) Reload(_ context.Context, req targets.Request) (string, error) {
	r.reloadCalls = append(r.reloadCalls, req)
	if r.reloadErr != nil {
		return "", r.reloadErr
	}
	return "reloaded", nil
}

// TestAgentFileTargetRequest asserts every field of the targets.Request a
// registry-dispatched FileTarget's Files receives, including GrantID =
// a.ID.String() and Fingerprint (contract details, task-6-brief.md).
func TestAgentFileTargetRequest(t *testing.T) {
	dir := t.TempDir()
	reg := targets.NewRegistry()
	ft := &recordingFileTarget{code: "rec", dir: dir}
	reg.Register(ft)
	d := testDeployerReg(reg, []string{dir})

	versionID := uuid.New()
	certID := uuid.New()
	cfg := json.RawMessage(`{"k":"v"}`)
	a := agentproto.Assignment{ID: uuid.New(), CertificateID: certID, CertificateName: "Web", CertificateNames: []string{"web.example.test"},
		VersionID: &versionID, Fingerprint: "abcd1234", Target: &agentproto.Target{Type: "rec", Config: cfg}}
	fullchain, key := testMaterial()
	b := agentproto.Bundle{VersionID: versionID, Material: &agentproto.Material{Fullchain: fullchain, Key: key}}

	res, written, _ := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateOK || len(written) != 1 {
		t.Fatalf("res %+v written %d", res, len(written))
	}
	if len(ft.filesCalls) != 1 {
		t.Fatalf("Files called %d times, want 1", len(ft.filesCalls))
	}
	req := ft.filesCalls[0]
	if req.GrantID != a.ID.String() {
		t.Errorf("GrantID = %q, want %q", req.GrantID, a.ID.String())
	}
	if req.CertID != certID.String() {
		t.Errorf("CertID = %q, want %q", req.CertID, certID.String())
	}
	if req.CertName != "Web" {
		t.Errorf("CertName = %q, want Web", req.CertName)
	}
	if len(req.Names) != 1 || req.Names[0] != "web.example.test" {
		t.Errorf("Names = %v, want [web.example.test]", req.Names)
	}
	if req.Fingerprint != "abcd1234" {
		t.Errorf("Fingerprint = %q, want abcd1234", req.Fingerprint)
	}
	if req.Side != targets.Agent {
		t.Errorf("Side = %v, want Agent", req.Side)
	}
	if string(req.Config) != string(cfg) {
		t.Errorf("Config = %s, want %s", req.Config, cfg)
	}
	if req.Material == nil || len(req.Material.LeafDER) == 0 {
		t.Errorf("Material not set from the bundle's PEM")
	}
}

// TestAgentFileTargetReload: a Reloader is reloaded once, after every file
// is written, and a reload failure fails the grant while keeping the
// already-written files (Deployer.Deploy's contract).
func TestAgentFileTargetReload(t *testing.T) {
	dir := t.TempDir()
	reg := targets.NewRegistry()
	ft := &recordingFileTarget{code: "rec", dir: dir}
	reg.Register(ft)
	d := testDeployerReg(reg, []string{dir})

	versionID := uuid.New()
	a := agentproto.Assignment{ID: uuid.New(), CertificateID: uuid.New(), CertificateName: "Web", VersionID: &versionID,
		Target: &agentproto.Target{Type: "rec", Config: json.RawMessage(`{}`)}}
	fullchain, key := testMaterial()
	b := agentproto.Bundle{VersionID: versionID, Material: &agentproto.Material{Fullchain: fullchain, Key: key}}

	res, written, _ := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateOK || len(written) != 1 || len(ft.reloadCalls) != 1 {
		t.Fatalf("res %+v written %d reloads %d", res, len(written), len(ft.reloadCalls))
	}

	ft.reloadErr = fmt.Errorf("systemctl reload failed")
	res2, written2, _ := d.Deploy(context.Background(), a, b)
	if res2.State != agentproto.StateFailed || !strings.Contains(res2.Error, "files installed; reload:") || len(written2) != 1 {
		t.Fatalf("res %+v written %d", res2, len(written2))
	}
}

// TestAgentReportRedacted: an error a target's own Files raises, echoing
// back one of the target's own secret config values, never reaches
// GrantResult.Error unredacted (Global Constraints, Secrets row).
func TestAgentReportRedacted(t *testing.T) {
	dir := t.TempDir()
	reg := targets.NewRegistry()
	ft := &recordingFileTarget{code: "rec", dir: dir}
	reg.Register(ft)
	d := testDeployerReg(reg, []string{dir})

	versionID := uuid.New()
	cfg, _ := json.Marshal(map[string]string{"token": "super-secret-value"})
	a := agentproto.Assignment{ID: uuid.New(), CertificateID: uuid.New(), CertificateName: "Web", VersionID: &versionID,
		Target: &agentproto.Target{Type: "rec", Config: cfg}}
	fullchain, key := testMaterial()
	b := agentproto.Bundle{VersionID: versionID, Material: &agentproto.Material{Fullchain: fullchain, Key: key}}

	ft.filesErr = fmt.Errorf("upstream rejected token super-secret-value")
	res, _, _ := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed {
		t.Fatalf("res %+v, want StateFailed", res)
	}
	if strings.Contains(res.Error, "super-secret-value") {
		t.Fatalf("res.Error leaked the secret: %q", res.Error)
	}
	if !strings.Contains(res.Error, "[redacted]") {
		t.Fatalf("res.Error not redacted: %q", res.Error)
	}
}

// TestAgentNonFileTypeRefused: a target type the registry knows but that
// does not implement targets.FileTarget (a server-run-only type such as
// vault-kv/targetstest.Secret) is refused the same way an unknown type is.
func TestAgentNonFileTypeRefused(t *testing.T) {
	dir := t.TempDir()
	reg := targets.NewRegistry()
	reg.Register(&targetstest.Secret{Code: "secret-test", Mode: targets.Agent, Policy: targets.Never})
	d := testDeployerReg(reg, []string{dir})

	versionID := uuid.New()
	cfg, _ := json.Marshal(map[string]string{"url": "https://example.test", "token": "tok"})
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "Web", VersionID: &versionID,
		Target: &agentproto.Target{Type: "secret-test", Config: cfg}}
	fullchain, key := testMaterial()
	b := agentproto.Bundle{VersionID: versionID, Material: &agentproto.Material{Fullchain: fullchain, Key: key}}

	res, written, _ := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "secret-test") || len(written) != 0 {
		t.Fatalf("res %+v written %d", res, len(written))
	}

	res2, written2, _ := d.DeployTargetOnly(a)
	if res2.State != agentproto.StateFailed || !strings.Contains(res2.Error, "secret-test") || len(written2) != 0 {
		t.Fatalf("DeployTargetOnly res %+v written %d", res2, len(written2))
	}
}

// TestAgentNilGrantIDRefused covers batch 2 review finding 4: the old
// `req.GrantID == ""` check could never fire, since a.ID.String() of a
// uuid.UUID is never empty — a zero-value (never-set) grant ID must be
// refused by comparing a.ID itself against uuid.Nil.
func TestAgentNilGrantIDRefused(t *testing.T) {
	dir := t.TempDir()
	d := testDeployer([]string{dir})
	cfg, _ := json.Marshal(map[string]string{"dir": filepath.Join(dir, "traefik")})
	versionID := uuid.New()
	a := agentproto.Assignment{CertificateName: "Web", VersionID: &versionID, Target: &agentproto.Target{Type: "traefik", Config: cfg}}
	fullchain, key := testMaterial()
	b := agentproto.Bundle{VersionID: versionID, Material: &agentproto.Material{Fullchain: fullchain, Key: key}}

	if a.ID != uuid.Nil {
		t.Fatal("setup: a.ID is not the zero value")
	}
	res, written, _ := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "grant id is required") || len(written) != 0 {
		t.Fatalf("Deploy res %+v written %d", res, len(written))
	}

	res2, written2, _ := d.DeployTargetOnly(a)
	if res2.State != agentproto.StateFailed || !strings.Contains(res2.Error, "grant id is required") || len(written2) != 0 {
		t.Fatalf("DeployTargetOnly res %+v written %d", res2, len(written2))
	}
}
