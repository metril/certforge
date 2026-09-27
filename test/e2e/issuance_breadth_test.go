//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// breadthAttemptStep/breadthAttempt mirror gen.AttemptStep/gen.IssuanceAttempt
// (newest attempt first, per GET .../attempts).
type breadthAttemptStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type breadthAttempt struct {
	Outcome string               `json:"outcome"`
	Steps   []breadthAttemptStep `json:"steps"`
}

type ariWindowOut struct {
	Start     string `json:"start"`
	End       string `json:"end"`
	CheckedAt string `json:"checkedAt"`
}

// breadthCertOut is certOut plus the Phase 4A fields (managed, ariWindow)
// TestIssuanceAgainstPebble's own certOut does not need.
type breadthCertOut struct {
	ID             string  `json:"id"`
	Status         string  `json:"status"`
	Managed        bool    `json:"managed"`
	FailureCount   int     `json:"failureCount"`
	LastError      string  `json:"lastError"`
	NextRenewAt    *string `json:"nextRenewAt"`
	CurrentVersion *struct {
		ID                string `json:"id"`
		SHA256Fingerprint string `json:"sha256Fingerprint"`
	} `json:"currentVersion"`
	AriWindow *ariWindowOut `json:"ariWindow"`
}

// containerIP resolves the compose-network IP address of service's single
// running container (docker compose ps -q, then docker inspect), so
// pebble-challtestsrv's /add-a can point a test domain at it exactly the
// way a real DNS answer would.
func containerIP(ctx context.Context, t *testing.T, service string) string {
	t.Helper()
	compose := os.Getenv("CF_E2E_COMPOSE")
	if compose == "" {
		t.Fatal("CF_E2E_COMPOSE is not set (run through make e2e)")
	}
	idOut, err := exec.CommandContext(ctx, "sh", "-c", compose+" ps -q "+service).CombinedOutput()
	if err != nil {
		t.Fatalf("compose ps -q %s: %v\n%s", service, err, idOut)
	}
	id := strings.TrimSpace(string(idOut))
	if id == "" {
		t.Fatalf("no running container for service %s", service)
	}
	ipOut, err := exec.CommandContext(ctx, "docker", "inspect", "-f",
		`{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`, id).CombinedOutput()
	if err != nil {
		t.Fatalf("docker inspect %s (%s): %v\n%s", service, id, err, ipOut)
	}
	ip := strings.TrimSpace(string(ipOut))
	if ip == "" {
		t.Fatalf("service %s has no compose-network IP", service)
	}
	return ip
}

// challtestsrvMgmt is pebble-challtestsrv's management API, published to
// the host by deploy/compose.test.yaml so this test can add the A records
// Pebble's http-01/tls-alpn-01 validation resolves against (its own
// dns-01/set-txt calls go through the compose-server-side "e2e-challtestsrv"
// provider instead, over the compose network).
var challtestsrvMgmt = envOr("CF_E2E_CHALLTESTSRV", "http://localhost:18055")

// addA adds a pebble-challtestsrv A record for host → ip.
func addA(ctx context.Context, t *testing.T, host, ip string) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"host": host, "addresses": []string{ip}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, challtestsrvMgmt+"/add-a", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("challtestsrv /add-a %s -> %s: %v", host, ip, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challtestsrv /add-a %s -> %s: HTTP %d", host, ip, resp.StatusCode)
	}
}

// postBinary POSTs body as JSON and returns a non-JSON 200 response body
// (an export download), the POST counterpart to apiClient.download.
func (c *apiClient) postBinary(ctx context.Context, t *testing.T, path string, body any) []byte {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL()+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: %d %s", path, resp.StatusCode, data)
	}
	return data
}

// waitActive polls certPath until the certificate is active or a failed
// attempt raised failureCount, failing the test in the latter case.
func waitActive(ctx context.Context, t *testing.T, c *apiClient, certPath string) breadthCertOut {
	t.Helper()
	cert := waitFor(ctx, t, certPath+" active", func() (breadthCertOut, bool) {
		var cur breadthCertOut
		c.call(ctx, t, http.MethodGet, certPath, nil, &cur)
		return cur, cur.Status == "active" || cur.FailureCount > 0
	})
	if cert.Status != "active" {
		t.Fatalf("%s: issuance failed: %s", certPath, cert.LastError)
	}
	return cert
}

// waitActiveRetrying polls certPath and renews it again every time a new
// failure appears, until it goes active. Unlike waitActive, more than one
// failure is expected and tolerated: agent-http01's certificate creation
// fires an automatic attempt with no grant/ACME router yet (guaranteed to
// fail), and even once the router file exists on disk, Traefik's
// file-provider watcher reloading it across a cross-container bind mount
// is not instantaneous, so a renew straight after the file appears can
// still race a Traefik that has not picked it up yet. Bounded only by ctx.
func waitActiveRetrying(ctx context.Context, t *testing.T, c *apiClient, certPath string) breadthCertOut {
	t.Helper()
	renewedAt := -1
	cert := waitFor(ctx, t, certPath+" active (retrying past expected early failures)", func() (breadthCertOut, bool) {
		var cur breadthCertOut
		c.call(ctx, t, http.MethodGet, certPath, nil, &cur)
		if cur.Status == "active" {
			return cur, true
		}
		if cur.FailureCount != renewedAt {
			renewedAt = cur.FailureCount
			c.call(ctx, t, http.MethodPost, certPath+"/renew", nil, nil)
		}
		return cur, false
	})
	if cert.Status != "active" {
		t.Fatalf("%s: issuance failed: %s", certPath, cert.LastError)
	}
	return cert
}

// assertStepsSucceeded fetches the newest attempt for certPath and fails
// the test unless every named step succeeded.
func assertStepsSucceeded(ctx context.Context, t *testing.T, c *apiClient, certPath string, names ...string) {
	t.Helper()
	var attempts []breadthAttempt
	c.call(ctx, t, http.MethodGet, certPath+"/attempts", nil, &attempts)
	if len(attempts) == 0 {
		t.Fatalf("%s: no attempts", certPath)
	}
	steps := attempts[0].Steps
	status := func(name string) (string, bool) {
		for _, s := range steps {
			if s.Name == name {
				return s.Status, true
			}
		}
		return "", false
	}
	for _, name := range names {
		got, ok := status(name)
		if !ok || got != "success" {
			t.Fatalf("%s: step %q = %q (found=%v), want success; steps=%+v", certPath, name, got, ok, steps)
		}
	}
}

// TestIssuanceBreadthAgainstCompose proves Phase 4A's issuance breadth end
// to end through the running compose stack: server http-01, agent http-01
// served through Traefik's per-grant ACME router with no pre-existing
// certificate version, agent tls-alpn-01, a mixed dns-01 + http-01
// certificate, PKCS#12 export, and a populated ARI window.
func TestIssuanceBreadthAgainstCompose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	trust, err := os.ReadFile("testdata/pebble.minica.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(trust)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	waitForPebbleReady(ctx, t, hc)

	c := newAPIClient(t)
	orgID := c.authenticate(ctx, t)

	// 1. Custom directories (Pebble) enforce rate limits; raise them so the
	// rate_ledger step succeeds "within limits", not "recorded only".
	c.call(ctx, t, http.MethodPut, "/api/v1/settings/issuance", map[string]any{
		"rateLimits": map[string]int{
			"certsPerRegisteredDomainPerWeek": 100000, "duplicateCertsPerWeek": 100000,
			"failedValidationsPerHour": 100000, "newOrdersPer3Hours": 100000,
		},
	}, nil)

	var ca, acct, cred struct {
		ID string `json:"id"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/cas", map[string]any{"name": "Pebble breadth", "preset": "custom",
		"directoryUrl": "https://pebble:14000/dir", "trustBundlePem": string(trust), "resolvers": []string{"challtestsrv:8053"}}, &ca)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/acme-accounts", map[string]any{"caId": ca.ID, "email": "breadth@example.test"}, &acct)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/dns-credentials", map[string]any{"name": "challtestsrv breadth",
		"providerCode": "e2e-challtestsrv", "config": map[string]string{"CHALLTESTSRV_URL": "http://challtestsrv:8055"}}, &cred)
	overrides := map[string]any{"caId": ca.ID, "accountId": acct.ID, "keyType": "ec256"}

	// 2. Container IPs, then the A records Pebble's http-01/tls-alpn-01
	// validation resolves against: api.e2e straight to the server,
	// agent.e2e to Traefik only (the agent's own http-01 listener is
	// reached only through the per-grant ACME router, never directly), and
	// alpn.e2e straight to the agent (tls-alpn-01 needs no router).
	addA(ctx, t, "api.e2e", containerIP(ctx, t, "certforge"))
	addA(ctx, t, "agent.e2e", containerIP(ctx, t, "traefik"))
	addA(ctx, t, "alpn.e2e", containerIP(ctx, t, "agent"))

	agentClientID := enrolledAgent(ctx, t, c, orgID)
	agentClientPath := "/api/v1/orgs/" + orgID + "/clients/" + agentClientID.String()
	dir := envOr("CF_E2E_AGENT_DIR", "../../.e2e")

	// Captured by server-http01, read back by export-p12.
	var exportCertPath, exportVersionID string

	t.Run("server-http01", func(t *testing.T) {
		var cert struct {
			ID string `json:"id"`
		}
		c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
			"name": "server-http01", "commonName": "api.e2e",
			"verificationRules": []map[string]any{{"match": "api.e2e", "method": "http-01"}},
			"overrides":         overrides,
		}, &cert)
		certPath := "/api/v1/orgs/" + orgID + "/certificates/" + cert.ID
		active := waitActive(ctx, t, c, certPath)
		assertStepsSucceeded(ctx, t, c, certPath, "caa", "rate_ledger")
		exportCertPath, exportVersionID = certPath, active.CurrentVersion.ID
	})

	t.Run("agent-http01", func(t *testing.T) {
		var target struct {
			ID string `json:"id"`
		}
		c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets", map[string]any{
			"name": "traefik-agent-http01", "type": "traefik",
			"config": map[string]any{"dir": "/etc/traefik/dynamic", "acmeServiceUrl": "http://agent:8080"},
		}, &target)
		var cert struct {
			ID string `json:"id"`
		}
		c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
			"name": "agent-http01", "commonName": "agent.e2e",
			"verificationRules": []map[string]any{{"match": "agent.e2e", "method": "http-01", "via": "agent", "clientId": agentClientID.String()}},
			"overrides":         overrides,
		}, &cert)
		certPath := "/api/v1/orgs/" + orgID + "/certificates/" + cert.ID
		// The automatic issuance attempt certificate creation just
		// triggered has no grant yet, so its http-01 validation has
		// nothing to route through and is expected to fail.
		c.call(ctx, t, http.MethodPost, agentClientPath+"/grants", map[string]any{
			"certificateId": cert.ID, "delivery": "push", "deployTargetId": target.ID,
		}, nil)
		routerFile := filepath.Join(dir, "traefik", "certforge-acme-agent-http01.yml")
		waitFor(ctx, t, "traefik ACME router file", func() (int64, bool) {
			fi, err := os.Stat(routerFile)
			if err != nil {
				return 0, false
			}
			return fi.Size(), fi.Size() > 0
		})
		// waitActiveRetrying renews again on every new failure: the
		// automatic attempt above, and (the file existing is not the same
		// as Traefik's watcher having reloaded it yet) possibly one or more
		// renews right after, until Traefik actually routes the challenge
		// to the agent.
		waitActiveRetrying(ctx, t, c, certPath)
		assertStepsSucceeded(ctx, t, c, certPath, "caa", "rate_ledger")
	})

	t.Run("agent-tlsalpn", func(t *testing.T) {
		var cert struct {
			ID string `json:"id"`
		}
		c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
			"name": "agent-tlsalpn", "commonName": "alpn.e2e",
			"verificationRules": []map[string]any{{"match": "alpn.e2e", "method": "tls-alpn-01", "clientId": agentClientID.String()}},
			"overrides":         overrides,
		}, &cert)
		certPath := "/api/v1/orgs/" + orgID + "/certificates/" + cert.ID
		waitActive(ctx, t, c, certPath)
		assertStepsSucceeded(ctx, t, c, certPath, "caa", "rate_ledger")
	})

	t.Run("mixed", func(t *testing.T) {
		var cert struct {
			ID string `json:"id"`
		}
		c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
			"name": "mixed", "commonName": "mixed.e2e", "sans": []string{"api.e2e"},
			"verificationRules": []map[string]any{
				{"match": "mixed.e2e", "method": "dns-01", "dnsCredentialId": cred.ID},
				{"match": "api.e2e", "method": "http-01"},
			},
			"overrides": overrides,
		}, &cert)
		certPath := "/api/v1/orgs/" + orgID + "/certificates/" + cert.ID
		waitActive(ctx, t, c, certPath)
		assertStepsSucceeded(ctx, t, c, certPath, "caa", "rate_ledger", "challenge mixed.e2e", "challenge api.e2e")
	})

	t.Run("export-p12", func(t *testing.T) {
		if exportCertPath == "" || exportVersionID == "" {
			t.Fatal("server-http01 did not record a version to export")
		}
		const password = "CertForge-E2E-Export-Pw1"
		data := c.postBinary(ctx, t, exportCertPath+"/versions/"+exportVersionID+"/export",
			map[string]any{"format": "p12", "password": password})
		// DecodeChain, not Decode: render.PKCS12 always includes the chain
		// as CA bags alongside the leaf and key, and Decode only accepts
		// exactly one certificate bag.
		_, got, _, err := pkcs12.DecodeChain(data, password)
		if err != nil {
			t.Fatalf("pkcs12 decode: %v", err)
		}
		wantPEM := c.download(ctx, t, exportCertPath+"/versions/"+exportVersionID+"/download?format=pem&parts=cert")
		blk, _ := pem.Decode(wantPEM)
		if blk == nil {
			t.Fatal("cert download: no PEM")
		}
		want, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Raw, want.Raw) {
			t.Fatal("exported p12 leaf does not match the current version")
		}
	})

	t.Run("ari", func(t *testing.T) {
		var cert struct {
			ID string `json:"id"`
		}
		c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
			"name": "ari", "commonName": "ari.e2e",
			"verificationRules": []map[string]any{{"match": "ari.e2e", "method": "dns-01", "dnsCredentialId": cred.ID}},
			"overrides": map[string]any{"caId": ca.ID, "accountId": acct.ID, "keyType": "ec256",
				"renewPolicy": map[string]any{"mode": "percent", "value": 33, "useAri": true}},
		}, &cert)
		certPath := "/api/v1/orgs/" + orgID + "/certificates/" + cert.ID
		active := waitActive(ctx, t, c, certPath)
		if active.NextRenewAt == nil {
			t.Fatal("nextRenewAt missing right after issuance")
		}
		policyNextRenew, err := time.Parse(time.RFC3339, *active.NextRenewAt)
		if err != nil {
			t.Fatal(err)
		}
		// The 6h periodic ARI poll has RunOnStart false; only the
		// post-issuance best-effort poll (IssueWorker.succeed) fills the
		// window here.
		withWindow := waitFor(ctx, t, "ari window populated", func() (breadthCertOut, bool) {
			var cur breadthCertOut
			c.call(ctx, t, http.MethodGet, certPath, nil, &cur)
			return cur, cur.AriWindow != nil
		})
		start, err := time.Parse(time.RFC3339, withWindow.AriWindow.Start)
		if err != nil {
			t.Fatal(err)
		}
		end, err := time.Parse(time.RFC3339, withWindow.AriWindow.End)
		if err != nil {
			t.Fatal(err)
		}
		if !start.Before(end) {
			t.Fatalf("ariWindow.start %s is not before end %s", start, end)
		}
		if withWindow.NextRenewAt == nil {
			t.Fatal("nextRenewAt missing after the ARI poll")
		}
		finalNextRenew, err := time.Parse(time.RFC3339, *withWindow.NextRenewAt)
		if err != nil {
			t.Fatal(err)
		}
		if finalNextRenew.After(policyNextRenew) {
			t.Fatalf("nextRenewAt %s is after the renewal-policy date %s; ARI must only lower it", finalNextRenew, policyNextRenew)
		}
	})
}
