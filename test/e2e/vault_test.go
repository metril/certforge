//go:build e2e

package e2e

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// vaultHostAddr is where the host-side test itself reaches Vault directly
// (to read the KV document a vault-kv deploy wrote, and Vault's own PKI CA
// certificate), published by deploy/compose.test.yaml's vault service.
func vaultHostAddr() string { return envOr("CF_E2E_VAULT", "http://localhost:8200") }

// vaultToken is the dev-mode root token, also VAULT_DEV_ROOT_TOKEN_ID for
// the compose vault service and the input deploy/e2e/vault-init.sh's
// custom-secret-id call uses as the AppRole's fixed secret_id.
func vaultToken() string { return envOr("CF_E2E_VAULT_TOKEN", "certforge-e2e-root") }

// vaultCompose returns the two invocations TestVaultAgainstCompose needs:
// the ordinary two-file one (shared with every other e2e test, for
// pause/unpause/restart against services compose.test.yaml already
// defines) and that same one with compose.vault.yaml layered on top (only
// for the second certforge boot, which is the one thing that file
// changes).
func vaultCompose(t *testing.T) (base, withVaultOverride string) {
	t.Helper()
	base = os.Getenv("CF_E2E_COMPOSE")
	if base == "" {
		t.Fatal("CF_E2E_COMPOSE is not set (run through make e2e)")
	}
	vaultFile := os.Getenv("CF_E2E_COMPOSE_VAULT_FILE")
	if vaultFile == "" {
		t.Fatal("CF_E2E_COMPOSE_VAULT_FILE is not set (run through make e2e)")
	}
	return base, base + " -f " + vaultFile
}

func runSh(ctx context.Context, t *testing.T, extraEnv []string, command string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", command, err, out)
	}
}

type readyzOut struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// getReadyz returns (0, zero value) on a connection error instead of
// failing the test: called from bounded waitFor loops right after a
// certforge restart, where the process being briefly unreachable is the
// condition being waited out, not a failure.
func getReadyz(ctx context.Context, t *testing.T) (int, readyzOut) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL()+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, readyzOut{}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, readyzOut{}
	}
	var out readyzOut
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

// getBody GETs url unauthenticated and returns its body, failing the test
// on any error or non-200 status.
func getBody(ctx context.Context, t *testing.T, url string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", url, resp.StatusCode, b)
	}
	return b
}

// keysStatusOut mirrors the KeysStatus/RewrapStatus schemas (Shared
// contract) — only the fields this test asserts on.
type keysStatusOut struct {
	Kind     string `json:"kind"`
	KekID    string `json:"kekId"`
	Previous []struct {
		Kind  string `json:"kind"`
		KekID string `json:"kekId"`
	} `json:"previous"`
	CanaryOk bool `json:"canaryOk"`
	Rewrap   *struct {
		Running    bool    `json:"running"`
		FinishedAt *string `json:"finishedAt"`
		Remaining  int64   `json:"remaining"`
		Error      *string `json:"error"`
	} `json:"rewrap"`
}

// caCreatedOut is the subset of CA this test reads back.
type caCreatedOut struct {
	ID             string `json:"id"`
	TrustBundlePem string `json:"trustBundlePem"`
}

type vaultTestResultOut struct {
	Ok    bool    `json:"ok"`
	Error *string `json:"error"`
}

type deployTargetOut struct {
	ID string `json:"id"`
}

type grantOut struct {
	ID               string `json:"id"`
	ServerDeployment *struct {
		Status    string  `json:"status"`
		LastError *string `json:"lastError"`
	} `json:"serverDeployment"`
}

type revokedVersionOut struct {
	ID        string  `json:"id"`
	Serial    string  `json:"serial"`
	RevokedAt *string `json:"revokedAt"`
}

// verifyAuditChain fails the test unless GET /audit/verify reports the
// chain valid; used before and after the static-to-Transit boot so a break
// there is caught immediately instead of surfacing as a mysterious later
// failure.
func verifyAuditChain(ctx context.Context, t *testing.T, c *apiClient) {
	t.Helper()
	var chain struct {
		Ok bool `json:"ok"`
	}
	c.call(ctx, t, http.MethodGet, "/api/v1/audit/verify", nil, &chain)
	if !chain.Ok {
		t.Fatal("audit chain broken")
	}
}

// TestVaultAgainstCompose (Task 14, R11's proofs) exercises everything
// Phase 5A built against a real Vault: the compose stack boots certforge on
// the static KEK like every other e2e test (deploy/compose.yaml's own
// secret), and this test only then restarts it with Transit active and the
// static key kept as previous (deploy/compose.vault.yaml), so the rewrap
// step has real sealed rows to move and the audit chain proof spans the
// boundary. It shares the running stack with the rest of the suite
// (CF_E2E_COMPOSE) rather than bringing up its own, and is run as its own
// `go test -run` invocation by `make e2e` after that suite passes, so nothing
// here races another test's use of the same server.
func TestVaultAgainstCompose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	base, withVaultOverride := vaultCompose(t)

	// The AppRole role_id/secret_id deploy/e2e/vault-init.sh writes are not
	// secret-shaped the same way (role_id isn't secret; secret_id is kept
	// out of the environment via a file mount instead), but both still
	// need to exist before the second boot can use them. vault-init runs
	// early in the same `up --wait` that started this whole stack, well
	// before this test's own suite-ordered invocation, but wait anyway
	// (bounded) so a standalone `-run TestVaultAgainstCompose` rerun during
	// development never races it.
	dir := envOr("CF_E2E_AGENT_DIR", "../../.e2e")
	roleIDPath := filepath.Join(dir, "vault", "role_id")
	secretIDPath := filepath.Join(dir, "vault", "secret_id")
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	waitFor(waitCtx, t, "vault-init AppRole files", func() (bool, bool) {
		_, err1 := os.Stat(roleIDPath)
		_, err2 := os.Stat(secretIDPath)
		return err1 == nil && err2 == nil, err1 == nil && err2 == nil
	})
	roleIDBytes, err := os.ReadFile(roleIDPath)
	if err != nil {
		t.Fatal(err)
	}
	roleID := strings.TrimSpace(string(roleIDBytes))
	if roleID == "" {
		t.Fatal("empty role_id")
	}

	c := newAPIClient(t)
	orgID := c.authenticate(ctx, t)

	// 1. Restart with Transit active, static KEK as previous; audit chain
	// still verifies across the boundary.
	// --profile e2e: compose.vault.yaml's certforge service depends on
	// vault-init (profile e2e); without the flag here too, that service is
	// excluded from the project and the reference is "undefined".
	runSh(ctx, t, []string{"CF_KEK_VAULT_ROLE_ID=" + roleID},
		withVaultOverride+" --profile e2e up -d --no-deps --force-recreate certforge")
	readyCtx, readyCancel := context.WithTimeout(ctx, 60*time.Second)
	defer readyCancel()
	waitFor(readyCtx, t, "readyz after Transit restart", func() (int, bool) {
		code, _ := getReadyz(readyCtx, t)
		return code, code == http.StatusOK
	})
	// The session store is Postgres-backed, so c's cookie is still good
	// against the restarted process (TestAgentAgainstCompose's own server
	// restart step relies on the same thing) — no need to log in again.
	verifyAuditChain(ctx, t, c)

	// 2. Rewrap: start it, then poll /keys/status to completion.
	c.call(ctx, t, http.MethodPost, "/api/v1/keys/rewrap", nil, nil)
	rewrapCtx, rewrapCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer rewrapCancel()
	status := waitFor(rewrapCtx, t, "rewrap finished", func() (keysStatusOut, bool) {
		var st keysStatusOut
		c.call(ctx, t, http.MethodGet, "/api/v1/keys/status", nil, &st)
		done := st.Rewrap != nil && st.Rewrap.FinishedAt != nil && st.Rewrap.Remaining == 0
		return st, done
	})
	if status.Kind != "vault-transit" {
		t.Fatalf("kind = %q, want vault-transit", status.Kind)
	}
	if !status.CanaryOk {
		t.Fatal("canaryOk = false after rewrap")
	}
	foundStatic := false
	for _, p := range status.Previous {
		if p.Kind == "static" {
			foundStatic = true
		}
	}
	if !foundStatic {
		t.Fatalf("previous = %+v, want a static entry", status.Previous)
	}
	if status.Rewrap.Error != nil {
		t.Fatalf("rewrap error: %s", *status.Rewrap.Error)
	}

	// 3. localca: create, issue, renew, download, verify chain, CRL,
	// revoke, CRL lists the serial.
	var ca caCreatedOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/cas", map[string]any{
		"name": "E2E Local CA", "type": "localca",
		"config": map[string]any{"subject": map[string]any{"commonName": "E2E Local Root"}},
	}, &ca)

	var localCert certOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
		"name": "local-e2e", "commonName": "local.e2e", "sans": []string{"10.0.0.1"},
		"overrides": map[string]any{"caId": ca.ID},
	}, &localCert)
	localCertPath := "/api/v1/orgs/" + orgID + "/certificates/" + localCert.ID
	// Shared by every "active" poll below (localca issue, localca renew,
	// vaultpki issue): none of them wait on an external CA the way ACME
	// issuance does, so 3 minutes is generous for all three combined.
	activeCtx, activeCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer activeCancel()
	localCert = waitFor(activeCtx, t, "localca cert active", func() (certOut, bool) {
		var cur certOut
		c.call(ctx, t, http.MethodGet, localCertPath, nil, &cur)
		return cur, cur.Status == "active" || cur.FailureCount > 0
	})
	if localCert.Status != "active" {
		t.Fatalf("localca issuance failed: %s", localCert.LastError)
	}

	c.call(ctx, t, http.MethodPost, localCertPath+"/renew", nil, nil)
	waitFor(ctx, t, "localca renewed", func() (int, bool) {
		var versions []versionOut
		c.call(ctx, t, http.MethodGet, localCertPath+"/versions", nil, &versions)
		return len(versions), len(versions) == 2
	})
	localCert = waitFor(activeCtx, t, "localca active after renewal", func() (certOut, bool) {
		var cur certOut
		c.call(ctx, t, http.MethodGet, localCertPath, nil, &cur)
		return cur, cur.Status == "active"
	})
	if localCert.CurrentVersion == nil {
		t.Fatal("localca certificate has no current version after renewal")
	}
	versionID := localCert.CurrentVersion.ID

	fullchain := c.download(ctx, t, localCertPath+"/versions/"+versionID+"/download?format=pem&parts=fullchain")
	chain := parsePEMCerts(t, fullchain)
	if len(chain) == 0 {
		t.Fatal("localca fullchain is empty")
	}
	leaf := chain[0]
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ca.TrustBundlePem)) {
		t.Fatal("could not parse localca trustBundlePem")
	}
	inters := x509.NewCertPool()
	for _, ic := range chain[1:] {
		inters.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("localca chain verify: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.1" {
		t.Fatalf("leaf IP SANs = %v, want [10.0.0.1]", leaf.IPAddresses)
	}

	crlDER := getBody(ctx, t, baseURL()+"/crl/"+ca.ID+".crl")
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("fresh CRL already lists %d entries", len(crl.RevokedCertificateEntries))
	}

	var revoked revokedVersionOut
	c.call(ctx, t, http.MethodPost, localCertPath+"/versions/"+versionID+"/revoke", map[string]any{}, &revoked)
	if revoked.RevokedAt == nil {
		t.Fatal("revoke response has no revokedAt")
	}
	serial, ok := new(big.Int).SetString(revoked.Serial, 16)
	if !ok {
		t.Fatalf("could not parse serial %q as hex", revoked.Serial)
	}
	waitFor(ctx, t, "CRL lists the revoked serial", func() ([]byte, bool) {
		der := getBody(ctx, t, baseURL()+"/crl/"+ca.ID+".crl")
		list, perr := x509.ParseRevocationList(der)
		if perr != nil {
			t.Fatal(perr)
		}
		for _, e := range list.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(serial) == 0 {
				return der, true
			}
		}
		return der, false
	})

	// 4. vaultpki: configure Settings -> Integrations -> Vault, test it,
	// create a vaultpki CA, issue, chain root equals Vault's own PKI CA.
	vaultSettings := map[string]any{
		"address": "http://vault:8200", "authMethod": "token", "token": vaultToken(),
	}
	c.call(ctx, t, http.MethodPut, "/api/v1/settings/vault", vaultSettings, nil)
	var testResult vaultTestResultOut
	c.call(ctx, t, http.MethodPost, "/api/v1/settings/vault/test", vaultSettings, &testResult)
	if !testResult.Ok {
		msg := ""
		if testResult.Error != nil {
			msg = *testResult.Error
		}
		t.Fatalf("testVaultSettings: ok=false, error=%q", msg)
	}

	var pkiCA caCreatedOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/cas", map[string]any{
		"name": "E2E Vault PKI", "type": "vaultpki",
		"config": map[string]any{"role": "certforge"},
	}, &pkiCA)

	var pkiCert certOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
		"name": "pki-e2e", "commonName": "pki.e2e",
		"overrides": map[string]any{"caId": pkiCA.ID},
	}, &pkiCert)
	pkiCertPath := "/api/v1/orgs/" + orgID + "/certificates/" + pkiCert.ID
	pkiCert = waitFor(activeCtx, t, "vaultpki cert active", func() (certOut, bool) {
		var cur certOut
		c.call(ctx, t, http.MethodGet, pkiCertPath, nil, &cur)
		return cur, cur.Status == "active" || cur.FailureCount > 0
	})
	if pkiCert.Status != "active" {
		t.Fatalf("vaultpki issuance failed: %s", pkiCert.LastError)
	}

	// GET pki/cert/ca is JSON-wrapped like every other Vault read (matching
	// internal/vault.Client.PKIReadCA), not a raw PEM body.
	var vaultCAResp struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getBody(ctx, t, vaultHostAddr()+"/v1/pki/cert/ca"), &vaultCAResp); err != nil {
		t.Fatalf("decode pki/cert/ca: %v", err)
	}
	vaultCABlk, _ := pem.Decode([]byte(vaultCAResp.Data.Certificate))
	if vaultCABlk == nil {
		t.Fatal("could not parse Vault's pki/cert/ca response as PEM")
	}
	vaultCACert, err := x509.ParseCertificate(vaultCABlk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pkiRootsFromResp := parsePEMCerts(t, []byte(pkiCA.TrustBundlePem))
	if len(pkiRootsFromResp) != 1 || !pkiRootsFromResp[0].Equal(vaultCACert) {
		t.Fatalf("vaultpki trustBundlePem does not equal Vault's own pki/cert/ca")
	}

	// 5. vault-kv: a server-side deploy target plus a server grant on the
	// localca certificate; wait for it to deploy, then read the KV
	// document directly with the root token.
	var target deployTargetOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets", map[string]any{
		"name": "E2E Vault KV", "type": "vault-kv",
		"config": map[string]any{"path": "certforge/{org}/{name}"},
	}, &target)

	var grant grantOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets/"+target.ID+"/grants",
		map[string]any{"certificateId": localCert.ID}, &grant)
	grant = waitFor(ctx, t, "server grant deployed", func() (grantOut, bool) {
		var items []grantOut
		c.call(ctx, t, http.MethodGet, "/api/v1/orgs/"+orgID+"/deploy-targets/"+target.ID+"/grants", nil, &items)
		for _, g := range items {
			if g.ID == grant.ID {
				return g, g.ServerDeployment != nil && g.ServerDeployment.Status == "deployed"
			}
		}
		return grantOut{}, false
	})
	if grant.ServerDeployment == nil || grant.ServerDeployment.Status != "deployed" {
		lastErr := ""
		if grant.ServerDeployment != nil && grant.ServerDeployment.LastError != nil {
			lastErr = *grant.ServerDeployment.LastError
		}
		t.Fatalf("server grant did not deploy: %s", lastErr)
	}

	kvURL := vaultHostAddr() + "/v1/secret/data/certforge/e2e/local-e2e"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kvURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", vaultToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	kvBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", kvURL, resp.StatusCode, kvBody)
	}
	var kv struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(kvBody, &kv); err != nil {
		t.Fatalf("decode KV response: %v: %s", err, kvBody)
	}
	gotFullchain, ok := kv.Data.Data["fullchain.pem"]
	if !ok || gotFullchain == "" {
		t.Fatalf("KV document missing fullchain.pem: keys=%v", kv.Data.Data)
	}
	if !strings.Contains(gotFullchain, string(fullchain[:64])) {
		// A loose but meaningful check: the KV document's fullchain must
		// start the same way the version downloaded via the API did (both
		// are the same version's rendered fullchain.pem).
		t.Fatalf("KV fullchain.pem does not match the certificate's own fullchain")
	}
	if _, ok := kv.Data.Data["privkey.pem"]; ok {
		t.Fatal("KV document has privkey.pem, but includeKey was never set")
	}

	// 6. Vault down: pause (never stop — dev mode is in-memory), /readyz
	// goes 503 with checks.vault = failed, then recovers on unpause.
	runSh(ctx, t, nil, base+" pause vault")
	pauseCtx, pauseCancel := context.WithTimeout(ctx, 60*time.Second)
	defer pauseCancel()
	waitFor(pauseCtx, t, "readyz reports vault failed", func() (readyzOut, bool) {
		code, out := getReadyz(pauseCtx, t)
		return out, code == http.StatusServiceUnavailable && out.Checks["vault"] == "failed"
	})
	runSh(ctx, t, nil, base+" unpause vault")
	unpauseCtx, unpauseCancel := context.WithTimeout(ctx, 60*time.Second)
	defer unpauseCancel()
	waitFor(unpauseCtx, t, "readyz ready again", func() (int, bool) {
		code, _ := getReadyz(unpauseCtx, t)
		return code, code == http.StatusOK
	})
}
