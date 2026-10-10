//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
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
	Name      string `json:"name"`
	Status    string `json:"status"`
	Connected bool   `json:"connected"`
}

// agentOnce and agentClientID share the one compose agent container across
// every e2e test that needs it (TestAgentAgainstCompose,
// TestIssuanceBreadthAgainstCompose): the container enrols once, with
// CF_AGENT_TOKEN_FILE pointed at .e2e/agent-data/token, and a second
// enrolment attempt would just orphan an unused client.
var (
	agentOnce     sync.Once
	agentClientID uuid.UUID
)

// enrolledAgent points the compose agent's settings at this server, enrols
// it (or reuses an already-enrolled "e2e-agent" client, for a rerun against
// a stack that was not torn down), and waits for it to report active and
// connected. Safe to call from multiple tests: the actual enrolment work
// runs at most once per test binary run.
func enrolledAgent(ctx context.Context, t *testing.T, c *apiClient, orgID string) uuid.UUID {
	t.Helper()
	agentOnce.Do(func() {
		// Agents reach the server through Caddy, a TLS-terminating proxy in
		// front of the HTTP port (deploy/e2e/Caddyfile), not the agent port.
		c.call(ctx, t, http.MethodPut, "/api/v1/settings/agents", map[string]any{
			"agentUrl": "https://caddy:9443", "heartbeatSeconds": 15, "offlineAfterSeconds": 60}, nil)

		var existing struct {
			Items []clientOut `json:"items"`
		}
		c.call(ctx, t, http.MethodGet, "/api/v1/orgs/"+orgID+"/clients", nil, &existing)
		for _, cl := range existing.Items {
			if cl.Name == "e2e-agent" {
				agentClientID = uuid.MustParse(cl.ID)
				return
			}
		}

		dir := envOr("CF_E2E_AGENT_DIR", "../../.e2e")
		var created struct {
			Client clientOut `json:"client"`
			Token  string    `json:"token"`
		}
		c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/clients", map[string]any{"name": "e2e-agent"}, &created)
		if err := os.WriteFile(filepath.Join(dir, "agent-data", "token"), []byte(created.Token), 0o600); err != nil {
			t.Fatal(err)
		}
		agentClientID = uuid.MustParse(created.Client.ID)
	})
	// sync.Once.Do still marks itself done even if the closure above
	// exited early via t.Fatal (its deferred done-store runs on that
	// unwind same as a normal return), so a later caller in a different
	// test whose own enrolment attempt already failed would otherwise
	// silently proceed with the zero UUID and poll a nonexistent client
	// until it times out. Fail fast instead, on the caller's own t,
	// pointing at the real cause.
	if agentClientID == uuid.Nil {
		t.Fatal("enrolledAgent: the one-time agent enrolment already failed in an earlier test; see that test's own failure for the cause")
	}
	clientPath := "/api/v1/orgs/" + orgID + "/clients/" + agentClientID.String()
	waitFor(ctx, t, "client active and connected", func() (clientOut, bool) {
		// The agent enrols, then waits for an administrator: approve its
		// request as soon as it appears (requireApproval defaults to on).
		var reqs struct {
			Items []struct {
				ID       string `json:"id"`
				ClientID string `json:"clientId"`
			} `json:"items"`
		}
		c.call(ctx, t, http.MethodGet, "/api/v1/orgs/"+orgID+"/enrollment-requests", nil, &reqs)
		for _, r := range reqs.Items {
			if r.ClientID == agentClientID.String() {
				c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/enrollment-requests/"+r.ID+"/approve", nil, nil)
			}
		}
		var cl clientOut
		c.call(ctx, t, http.MethodGet, clientPath, nil, &cl)
		return cl, cl.Status == "active" && cl.Connected
	})
	return agentClientID
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
	trust, err := os.ReadFile("testdata/pebble.minica.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(trust)
	waitForPebbleReady(ctx, t, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}})

	c := newAPIClient(t)
	orgID := c.authenticate(ctx, t)
	cert := issueForAgent(ctx, t, c, orgID, "agent-e2e")

	// 1. Enrol (or reuse) the compose agent → active and connected.
	clientID := enrolledAgent(ctx, t, c, orgID)
	clientPath := "/api/v1/orgs/" + orgID + "/clients/" + clientID.String()
	connected := func(what string) {
		waitFor(ctx, t, what, func() (clientOut, bool) {
			var cl clientOut
			c.call(ctx, t, http.MethodGet, clientPath, nil, &cl)
			return cl, cl.Status == "active" && cl.Connected
		})
	}

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

	assertAgentViaCaddy(t, dir)

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
	c.call(ctx, t, http.MethodGet, "/api/v1/audit?action=deployment.drift&resourceId="+grant.ID, nil, &drift)
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
	var redeployed struct {
		Items []map[string]any `json:"items"`
	}
	c.call(ctx, t, http.MethodGet, "/api/v1/audit?action=grant.redeploy&resourceId="+grant.ID, nil, &redeployed)
	if len(redeployed.Items) == 0 {
		t.Fatal("redeploy was not audited")
	}

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

// assertAgentViaCaddy proves the agent's protocol traffic crossed the
// terminating proxy: Caddy's access log holds the handshake, enrolment and
// signed REST calls. (The WebSocket is logged only when it closes; that the
// agent is "connected" with an agentUrl that names only Caddy shows it too.)
func assertAgentViaCaddy(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "caddy", "access.log"))
	if err != nil {
		t.Fatalf("caddy access log: %v", err)
	}
	for _, want := range []string{"/agent/v1/enroll/hello", "/agent/v1/session", "/agent/v1/assignments"} {
		if !bytes.Contains(b, []byte(`"uri":"`+want)) {
			t.Fatalf("no %s request in Caddy's access log: the agent bypassed the proxy", want)
		}
	}
}
