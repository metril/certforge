//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type agentCertOut struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	FailureCount   int    `json:"failureCount"`
	LastError      string `json:"lastError"`
	CurrentVersion *struct {
		ID                string `json:"id"`
		Sha256Fingerprint string `json:"sha256Fingerprint"`
	} `json:"currentVersion"`
}

type clientOut struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Connected bool   `json:"connected"`
}

type grantListOut struct {
	Items []struct {
		ID         string `json:"id"`
		Deployment struct {
			State string `json:"state"`
		} `json:"deployment"`
	} `json:"items"`
}

// issueForAgent issues a Pebble certificate with its own CA, credential and
// account, so it does not collide with TestIssuanceAgainstPebble's names.
func issueForAgent(ctx context.Context, t *testing.T, c *apiClient, orgID, name string) agentCertOut {
	t.Helper()
	trust, err := os.ReadFile("testdata/pebble.minica.pem")
	if err != nil {
		t.Fatal(err)
	}
	var ca, cred, acct struct {
		ID string `json:"id"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/cas", map[string]any{"name": "Pebble " + name, "preset": "custom",
		"directoryUrl": "https://pebble:14000/dir", "trustBundlePem": string(trust), "resolvers": []string{"challtestsrv:8053"}}, &ca)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/dns-credentials", map[string]any{"name": "challtestsrv " + name,
		"providerCode": "e2e-challtestsrv", "config": map[string]string{"CHALLTESTSRV_URL": "http://challtestsrv:8055"}}, &cred)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/acme-accounts", map[string]any{"caId": ca.ID, "email": name + "@example.test"}, &acct)
	var cert agentCertOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
		"name": name, "commonName": name + ".example.test",
		"verificationRules": []map[string]any{{"match": name + ".example.test", "method": "dns-01", "dnsCredentialId": cred.ID}},
		"overrides":         map[string]any{"caId": ca.ID, "accountId": acct.ID, "keyType": "ec256"},
	}, &cert)
	path := "/api/v1/orgs/" + orgID + "/certificates/" + cert.ID
	cert = waitFor(ctx, t, "agent certificate active", func() (agentCertOut, bool) {
		var cur agentCertOut
		c.call(ctx, t, http.MethodGet, path, nil, &cur)
		return cur, cur.Status == "active" || cur.FailureCount > 0
	})
	if cert.Status != "active" || cert.CurrentVersion == nil {
		t.Fatalf("issuance failed: %s", cert.LastError)
	}
	return cert
}

func readOrEmpty(p string) []byte {
	b, _ := os.ReadFile(p)
	return b
}

func TestAgentAgainstCompose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	dir := envOr("CF_E2E_AGENT_DIR", "../../.e2e")
	trust, _ := os.ReadFile("testdata/pebble.minica.pem")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(trust)
	waitForPebbleReady(ctx, t, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}})

	c := newAPIClient(t)
	orgID := c.authenticate(ctx, t)
	// Agents reach the server as certforge:8443 on the compose network; the
	// listener certificate gains that name when the section is saved.
	c.call(ctx, t, http.MethodPut, "/api/v1/settings/agents", map[string]any{
		"agentUrl": "https://certforge:8443", "heartbeatSeconds": 15, "offlineAfterSeconds": 60}, nil)
	cert := issueForAgent(ctx, t, c, orgID, "agent-e2e")

	// 1. Token → active and connected.
	var created struct {
		Client clientOut `json:"client"`
		Token  string    `json:"token"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/clients", map[string]any{"name": "e2e-agent"}, &created)
	if err := os.WriteFile(filepath.Join(dir, "agent-data", "token"), []byte(created.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	clientPath := "/api/v1/orgs/" + orgID + "/clients/" + created.Client.ID
	connected := func(what string) {
		waitFor(ctx, t, what, func() (clientOut, bool) {
			var cl clientOut
			c.call(ctx, t, http.MethodGet, clientPath, nil, &cl)
			return cl, cl.Status == "active" && cl.Connected
		})
	}
	connected("client active and connected")

	// 2. Grant → files on disk with the issued fingerprint and the Traefik YAML.
	var layout, target, grant struct {
		ID string `json:"id"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/layouts", map[string]any{"name": "e2e", "files": []map[string]any{
		{"path": "/etc/ssl/certforge/agent-e2e.pem", "format": "pem", "parts": []string{"fullchain"}, "owner": "", "group": "", "mode": "0644"}}}, &layout)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets", map[string]any{"name": "traefik", "type": "traefik",
		"config": map[string]any{"dir": "/etc/traefik/dynamic"}}, &target)
	c.call(ctx, t, http.MethodPost, clientPath+"/grants", map[string]any{"certificateId": cert.ID, "delivery": "push",
		"layoutId": layout.ID, "deployTargetId": target.ID, "autoRemediate": true}, &grant)
	deploymentOK := func(what string) {
		waitFor(ctx, t, what, func() (string, bool) {
			var gl grantListOut
			c.call(ctx, t, http.MethodGet, clientPath+"/grants", nil, &gl)
			if len(gl.Items) != 1 {
				return "no grant", false
			}
			return gl.Items[0].Deployment.State, gl.Items[0].Deployment.State == "ok"
		})
	}
	deploymentOK("deployment ok")
	pemPath := filepath.Join(dir, "ssl", "agent-e2e.pem")
	original := readOrEmpty(pemPath)
	leaf := parsePEMCerts(t, original)[0]
	if sum := sha256.Sum256(leaf.Raw); hex.EncodeToString(sum[:]) != cert.CurrentVersion.Sha256Fingerprint {
		t.Fatal("installed certificate is not the issued version")
	}
	yml := filepath.Join(dir, "traefik", "certforge-agent-e2e.yml")
	wantYAML := "# Managed by CertForge. Do not edit; changes are overwritten.\ntls:\n  certificates:\n" +
		"    - certFile: \"/etc/traefik/dynamic/certs/agent-e2e/fullchain.pem\"\n" +
		"      keyFile: \"/etc/traefik/dynamic/certs/agent-e2e/privkey.pem\"\n      stores:\n        - \"default\"\n"
	if got := string(readOrEmpty(yml)); got != wantYAML {
		t.Fatalf("traefik yml:\n%s", got)
	}
	if string(readOrEmpty(filepath.Join(dir, "traefik", "certs", "agent-e2e", "fullchain.pem"))) != string(original) {
		t.Fatal("traefik fullchain differs from the layout fullchain")
	}

	// 3. Tamper → drift → auto-remediation restores the file.
	if err := os.WriteFile(pemPath, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(ctx, t, "file restored", func() (int, bool) {
		b := readOrEmpty(pemPath)
		return len(b), string(b) == string(original)
	})
	var drift struct {
		Items []map[string]any `json:"items"`
	}
	c.call(ctx, t, http.MethodGet, "/api/v1/audit?action=deployment.drift", nil, &drift)
	if len(drift.Items) == 0 {
		t.Fatal("drift was not audited")
	}
	deploymentOK("deployment ok after remediation")

	// 4. Server restart → the agent reconnects and reconciles.
	compose := os.Getenv("CF_E2E_COMPOSE")
	if compose == "" {
		t.Fatal("CF_E2E_COMPOSE is not set (run through make e2e)")
	}
	if out, err := exec.CommandContext(ctx, "sh", "-c", compose+" restart certforge").CombinedOutput(); err != nil {
		t.Fatalf("restart: %v\n%s", err, out)
	}
	waitFor(ctx, t, "server healthy", func() (int, bool) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL()+"/healthz", nil)
		if err != nil {
			return 0, false
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, false
		}
		resp.Body.Close()
		return resp.StatusCode, resp.StatusCode == http.StatusOK
	})
	connected("agent reconnected after restart")
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/grants/"+grant.ID+"/redeploy", nil, nil)
	deploymentOK("redeploy after restart")

	// 5. Delete the grant → the agent removes the YAML and the files.
	c.call(ctx, t, http.MethodDelete, "/api/v1/orgs/"+orgID+"/grants/"+grant.ID, nil, nil)
	waitFor(ctx, t, "files removed", func() (string, bool) {
		for _, p := range []string{yml, pemPath} {
			if _, err := os.Stat(p); err == nil {
				return p, false
			}
		}
		return "", true
	})
	if _, err := os.Stat(filepath.Join(dir, "traefik", "certs", "agent-e2e")); err == nil {
		t.Fatal("traefik certs/agent-e2e directory left behind")
	}
}
