//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto"
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
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
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

// expectedUnrouted is the acme error substring a http-01 validation fails
// with when Traefik (or the agent) has nothing to route the challenge
// through yet: an "unauthorized" ACME problem whose detail names a
// non-200 (typically 404) response. agent-http01's retry loop uses it to
// tell that expected, transient race apart from a genuine regression.
const expectedUnrouted = "urn:ietf:params:acme:error:unauthorized"

// waitTraefikRouterEnabled polls Traefik's own API (docker exec + wget
// over the container's own localhost; the API entrypoint is not published
// to the host) until routerName's file-provider router reports
// "enabled". The router file existing on disk (deploy/compose.test.yaml's
// bind mount) is not the same as Traefik's file-provider watcher having
// actually reloaded it, so relying on the file's mtime alone can still
// race a Traefik that has not picked the route up yet.
func waitTraefikRouterEnabled(ctx context.Context, t *testing.T, routerName string) {
	t.Helper()
	compose := os.Getenv("CF_E2E_COMPOSE")
	if compose == "" {
		t.Fatal("CF_E2E_COMPOSE is not set (run through make e2e)")
	}
	idOut, err := exec.CommandContext(ctx, "sh", "-c", compose+" ps -q traefik").CombinedOutput()
	if err != nil {
		t.Fatalf("compose ps -q traefik: %v\n%s", err, idOut)
	}
	id := strings.TrimSpace(string(idOut))
	if id == "" {
		t.Fatal("no running container for service traefik")
	}
	url := "http://localhost:8081/api/http/routers/" + routerName + "@file"
	waitFor(ctx, t, "traefik router "+routerName+" enabled", func() (string, bool) {
		out, _ := exec.CommandContext(ctx, "docker", "exec", id, "wget", "-qO-", url).CombinedOutput()
		s := string(out)
		return s, strings.Contains(s, `"status":"enabled"`)
	})
}

// attemptSteps fetches certPath's newest attempt's steps.
func attemptSteps(ctx context.Context, t *testing.T, c *apiClient, certPath string) []breadthAttemptStep {
	t.Helper()
	var attempts []breadthAttempt
	c.call(ctx, t, http.MethodGet, certPath+"/attempts", nil, &attempts)
	if len(attempts) == 0 {
		t.Fatalf("%s: no attempts", certPath)
	}
	return attempts[0].Steps
}

// stepMessage returns the message of the named step, or "" if absent.
func stepMessage(steps []breadthAttemptStep, name string) string {
	for _, s := range steps {
		if s.Name == name {
			return s.Message
		}
	}
	return ""
}

// assertStepsSucceeded fetches the newest attempt for certPath, fails the
// test unless every named step succeeded, and returns the full step list
// so a caller can make further assertions (message content, for example)
// without a second fetch.
func assertStepsSucceeded(ctx context.Context, t *testing.T, c *apiClient, certPath string, names ...string) []breadthAttemptStep {
	t.Helper()
	steps := attemptSteps(ctx, t, c, certPath)
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
	return steps
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

		// No pre-existing version: this really is the certificate's first
		// issuance, routed entirely through Traefik, the way Task 8's
		// version-less-grant delivery is meant to be proven.
		var atFile breadthCertOut
		c.call(ctx, t, http.MethodGet, certPath, nil, &atFile)
		if atFile.CurrentVersion != nil {
			t.Fatalf("%s: already has a current version when the router file appeared; not a first-issuance case", certPath)
		}

		// The router file existing on disk (above) is not the same as
		// Traefik's file-provider watcher having reloaded it across the
		// cross-container bind mount; confirm the router itself is live
		// before relying on it to route anything.
		waitTraefikRouterEnabled(ctx, t, "certforge-acme-agent-http01")

		// The automatic attempt certificate creation fired had nothing to
		// route through yet and is expected to fail with the challenge
		// unauthorized (not some other, unrelated problem).
		cur := waitFor(ctx, t, certPath+" automatic attempt fails (no route existed yet)", func() (breadthCertOut, bool) {
			var v breadthCertOut
			c.call(ctx, t, http.MethodGet, certPath, nil, &v)
			return v, v.FailureCount > 0
		})
		if !strings.Contains(cur.LastError, expectedUnrouted) {
			t.Fatalf("%s: automatic attempt failed unexpectedly (not the pre-routing race): %s", certPath, cur.LastError)
		}

		// Retry now that Traefik is confirmed to route the challenge to
		// the agent: exactly one renew is expected to succeed, but a
		// couple of retries are tolerated (each must still fail the same,
		// expected way) in case that renew itself still raced something.
		const maxRetries = 3
		for retry := 0; cur.Status != "active"; retry++ {
			if retry >= maxRetries {
				t.Fatalf("%s: still failing after %d retries: %s", certPath, retry, cur.LastError)
			}
			waitFor(ctx, t, certPath+" renewal enqueued", func() (bool, bool) {
				var res struct {
					Enqueued bool `json:"enqueued"`
				}
				c.call(ctx, t, http.MethodPost, certPath+"/renew", nil, &res)
				return res.Enqueued, res.Enqueued
			})
			prevFailures := cur.FailureCount
			cur = waitFor(ctx, t, certPath+" retry finished", func() (breadthCertOut, bool) {
				var v breadthCertOut
				c.call(ctx, t, http.MethodGet, certPath, nil, &v)
				return v, v.Status == "active" || v.FailureCount > prevFailures
			})
			if cur.Status != "active" && !strings.Contains(cur.LastError, expectedUnrouted) {
				t.Fatalf("%s: retry failed unexpectedly (not the pre-routing race): %s", certPath, cur.LastError)
			}
		}
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
		steps := assertStepsSucceeded(ctx, t, c, certPath, "caa", "rate_ledger", "challenge mixed.e2e", "challenge api.e2e")
		// Both rules succeeding is not proof they used different methods
		// (a regression could route both through the same one); the step
		// message names the actual challenge type presented, per
		// internal/challenge/router.go's doneMessage.
		if got := stepMessage(steps, "challenge mixed.e2e"); !strings.Contains(got, "TXT") {
			t.Fatalf("%s: challenge mixed.e2e step message %q does not show dns-01 (TXT)", certPath, got)
		}
		if got := stepMessage(steps, "challenge api.e2e"); !strings.Contains(got, "http-01") {
			t.Fatalf("%s: challenge api.e2e step message %q does not show http-01", certPath, got)
		}
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
		privAny, got, _, err := pkcs12.DecodeChain(data, password)
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
		if privAny == nil {
			t.Fatal("exported p12 has no private key")
		}
		signer, ok := privAny.(crypto.Signer)
		if !ok {
			t.Fatalf("exported p12 private key is %T, not a crypto.Signer", privAny)
		}
		pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok {
			t.Fatalf("exported p12 private key's public key %T has no Equal method", signer.Public())
		}
		if !pub.Equal(got.PublicKey) {
			t.Fatal("exported p12 private key does not match the leaf's public key")
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
		if active.CurrentVersion == nil {
			t.Fatal("no current version right after issuance")
		}
		var versions []struct {
			NotBefore string `json:"notBefore"`
			NotAfter  string `json:"notAfter"`
		}
		c.call(ctx, t, http.MethodGet, certPath+"/versions", nil, &versions)
		if len(versions) == 0 {
			t.Fatal("no versions")
		}
		notBefore, err := time.Parse(time.RFC3339, versions[0].NotBefore)
		if err != nil {
			t.Fatal(err)
		}
		notAfter, err := time.Parse(time.RFC3339, versions[0].NotAfter)
		if err != nil {
			t.Fatal(err)
		}
		// Independently computed from the version's own validity, not read
		// off the certificate's own nextRenewAt: the post-issuance ARI poll
		// (below) runs synchronously right after the same commit that sets
		// status active, so a GET landing after it has already run would
		// read nextRenewAt already lowered by ARI, making a "final ≤
		// before" comparison against the certificate's own value
		// tautological. internal/issuance/policy.go's NextRenewAt, percent
		// mode: notAfter - 33% of the lifetime (the two floors it also
		// applies — half the lifetime, now+1h — never bind for Pebble's
		// 90-day default profile, so they are not replicated here).
		life := notAfter.Sub(notBefore)
		policyNextRenew := notAfter.Add(-(life / 100 * 33))
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
