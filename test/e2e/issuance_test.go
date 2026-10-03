//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// pebbleMgt is Pebble's management API, published to the host by
// deploy/compose.test.yaml so this test can independently verify the issued
// chain against Pebble's own roots/intermediates.
var pebbleMgt = envOr("CF_E2E_PEBBLE_MGMT", "https://localhost:15000")

// e2ePassword is the local admin password this test sets on first-run setup
// (or logs in with, if setup was already completed against this stack).
const e2ePassword = "CertForge-E2E-Test-Pw1"

// apiClient drives the running certforge server's HTTP API: a session
// cookie (via its jar) plus the X-CSRF-Token header on every mutating
// request, exactly as a real client must.
type apiClient struct {
	hc   *http.Client
	csrf string
}

func newAPIClient(t *testing.T) *apiClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &apiClient{hc: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

// call sends body (nil for none) as JSON and, on a 2xx response, decodes the
// body into out (nil to discard it). It fails the test otherwise.
func (c *apiClient) call(ctx context.Context, t *testing.T, method, path string, body, out any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL()+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: decode %v: %s", method, path, err, b)
		}
	}
}

// download fetches a non-JSON response body (a certificate version's PEM).
func (c *apiClient) download(ctx context.Context, t *testing.T, path string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	return b
}

type meResponse struct {
	CsrfToken string `json:"csrfToken"`
	Orgs      []struct {
		ID string `json:"id"`
	} `json:"orgs"`
}

// authenticate completes first-run setup on a fresh compose stack, or logs
// in if setup was already completed against it, and returns the org id.
func (c *apiClient) authenticate(ctx context.Context, t *testing.T) string {
	t.Helper()
	var status struct {
		NeedsSetup bool `json:"needsSetup"`
	}
	c.call(ctx, t, http.MethodGet, "/api/v1/setup/status", nil, &status)
	var me meResponse
	if status.NeedsSetup {
		c.call(ctx, t, http.MethodPost, "/api/v1/setup/complete", map[string]string{
			"adminPassword": e2ePassword, "orgName": "E2E", "orgSlug": "e2e", "baseUrl": baseURL(),
		}, &me)
	} else {
		c.call(ctx, t, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": e2ePassword}, &me)
	}
	c.csrf = me.CsrfToken
	if len(me.Orgs) == 0 {
		t.Fatal("no orgs after authenticating")
	}
	return me.Orgs[0].ID
}

func waitFor[T any](ctx context.Context, t *testing.T, what string, poll func() (T, bool)) T {
	t.Helper()
	for {
		v, done := poll()
		if done {
			return v
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s: last %+v", what, v)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// waitForPebbleReady polls Pebble's management API (bounded 60s) before the
// test drives any issuance through it: compose `--wait` only checks each
// service's own healthcheck, which can report healthy slightly before
// Pebble's management listener actually answers, and a cold Pebble would
// otherwise fail the very first ACME call the server makes on our behalf.
func waitForPebbleReady(ctx context.Context, t *testing.T, hc *http.Client) {
	t.Helper()
	readyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(readyCtx, http.MethodGet, pebbleMgt+"/roots/0", nil)
		if err == nil {
			if resp, doErr := hc.Do(req); doErr == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
			}
		}
		select {
		case <-readyCtx.Done():
			t.Fatalf("Pebble management API not ready at %s/roots/0 within 60s", pebbleMgt)
		case <-time.After(time.Second):
		}
	}
}

func fetchCert(ctx context.Context, t *testing.T, hc *http.Client, u string) *x509.Certificate {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s: no PEM", u)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func parsePEMCerts(t *testing.T, b []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

type certOut struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	CurrentVersion *struct {
		ID string `json:"id"`
	} `json:"currentVersion"`
	FailureCount int     `json:"failureCount"`
	LastError    string  `json:"lastError"`
	NextRenewAt  *string `json:"nextRenewAt"`
}

// versionOut is one entry of GET .../certificates/{id}/versions, newest
// first.
type versionOut struct {
	ID                string `json:"id"`
	SHA256Fingerprint string `json:"sha256Fingerprint"`
}

// TestIssuanceAgainstPebble drives the running certforge server (deploy/
// compose.test.yaml, built with GO_TAGS=e2e) through its HTTP API: log in
// (or complete first-run setup), create a CA, DNS credential and ACME
// account, issue a multi-SAN wildcard certificate, verify the chain, force
// a renewal, then break the credential and verify the resulting failure and
// backoff — end to end through the same API a real client uses, not the
// issuance engine in process.
func TestIssuanceAgainstPebble(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
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

	var ca struct {
		ID string `json:"id"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/cas", map[string]any{
		"name": "Pebble", "preset": "custom", "directoryUrl": "https://pebble:14000/dir",
		"trustBundlePem": string(trust), "resolvers": []string{"challtestsrv:8053"},
	}, &ca)

	var cred struct {
		ID string `json:"id"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/dns-credentials", map[string]any{
		"name": "challtestsrv", "providerCode": "e2e-challtestsrv",
		"config": map[string]string{"CHALLTESTSRV_URL": "http://challtestsrv:8055"},
	}, &cred)

	var acct struct {
		ID string `json:"id"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/acme-accounts", map[string]any{
		"caId": ca.ID, "email": "e2e@example.test",
	}, &acct)

	var cert certOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
		"name": "e2e", "commonName": "example.test", "sans": []string{"*.example.test"},
		"verificationRules": []map[string]any{{"match": "example.test", "method": "dns-01", "dnsCredentialId": cred.ID}},
		"overrides":         map[string]any{"caId": ca.ID, "accountId": acct.ID, "keyType": "ec256"},
	}, &cert)
	certPath := "/api/v1/orgs/" + orgID + "/certificates/" + cert.ID

	// 1. Issued and active (bounded independently of the overall test
	// timeout, so a stuck issuance fails fast with a useful message).
	activeCtx, activeCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer activeCancel()
	cert = waitFor(activeCtx, t, "active", func() (certOut, bool) {
		var cur certOut
		c.call(ctx, t, http.MethodGet, certPath, nil, &cur)
		return cur, cur.Status == "active" || cur.FailureCount > 0
	})
	if cert.Status != "active" {
		var attempts []map[string]any
		c.call(ctx, t, http.MethodGet, certPath+"/attempts", nil, &attempts)
		t.Fatalf("issuance failed: %s\n%v", cert.LastError, attempts)
	}
	if cert.CurrentVersion == nil {
		t.Fatal("active certificate has no current version")
	}

	// 2. Chain verifies against Pebble's root and intermediate; downloaded
	// through the API, not read out of the store directly.
	fullchain := c.download(ctx, t, certPath+"/versions/"+cert.CurrentVersion.ID+"/download?format=pem&parts=fullchain")
	chain := parsePEMCerts(t, fullchain)
	if len(chain) < 2 {
		t.Fatalf("fullchain has %d certs, want leaf + at least one intermediate", len(chain))
	}
	leaf := chain[0]

	inter := fetchCert(ctx, t, hc, pebbleMgt+"/intermediates/0")
	if !slices.Equal(chain[1].Raw, inter.Raw) {
		t.Fatal("downloaded chain does not start with Pebble intermediate 0")
	}
	root := fetchCert(ctx, t, hc, pebbleMgt+"/roots/0")
	rp, ip := x509.NewCertPool(), x509.NewCertPool()
	rp.AddCert(root)
	for _, ic := range chain[1:] {
		ip.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "foo.example.test", Roots: rp, Intermediates: ip}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}

	// 3. SANs.
	sans := slices.Clone(leaf.DNSNames)
	slices.Sort(sans)
	if !slices.Equal(sans, []string{"*.example.test", "example.test"}) {
		t.Fatalf("SANs = %v", sans)
	}

	// 4. Key type EC P-256, and the downloaded private key (parts=key needs
	// keys:export; the e2e admin has every permission) matches the leaf.
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("key = %T", leaf.PublicKey)
	}
	keyPEM := c.download(ctx, t, certPath+"/versions/"+cert.CurrentVersion.ID+"/download?format=pem&parts=key")
	keyBlk, _ := pem.Decode(keyPEM)
	if keyBlk == nil {
		t.Fatal("key download: no PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(keyBlk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privEC, ok := priv.(*ecdsa.PrivateKey)
	if !ok || !privEC.PublicKey.Equal(pub) {
		t.Fatalf("downloaded private key (%T) does not match the leaf's public key", priv)
	}

	// 5. Forced renewal creates a second version with a different
	// fingerprint, which becomes the certificate's current version.
	var versionsBefore []versionOut
	c.call(ctx, t, http.MethodGet, certPath+"/versions", nil, &versionsBefore)
	if len(versionsBefore) != 1 {
		t.Fatalf("expected exactly 1 version before renewal, got %d", len(versionsBefore))
	}
	firstFingerprint := versionsBefore[0].SHA256Fingerprint

	c.call(ctx, t, http.MethodPost, certPath+"/renew", nil, new(struct {
		Enqueued bool `json:"enqueued"`
	}))
	versionsAfter := waitFor(ctx, t, "second version", func() ([]versionOut, bool) {
		var versions []versionOut
		c.call(ctx, t, http.MethodGet, certPath+"/versions", nil, &versions)
		if len(versions) > 2 {
			t.Fatalf("more than 2 versions appeared: %d", len(versions))
		}
		return versions, len(versions) == 2
	})
	newest := versionsAfter[0] // newest first, per GET .../versions
	if newest.SHA256Fingerprint == firstFingerprint {
		t.Fatalf("second version has the same fingerprint as the first: %s", newest.SHA256Fingerprint)
	}

	var afterRenewal certOut
	c.call(ctx, t, http.MethodGet, certPath, nil, &afterRenewal)
	if afterRenewal.CurrentVersion == nil || afterRenewal.CurrentVersion.ID != newest.ID {
		t.Fatalf("currentVersion %v does not match the newest version %s", afterRenewal.CurrentVersion, newest.ID)
	}
	if afterRenewal.NextRenewAt == nil {
		t.Fatal("nextRenewAt missing after a successful renewal")
	}
	prevNextRenew, err := time.Parse(time.RFC3339, *afterRenewal.NextRenewAt)
	if err != nil {
		t.Fatal(err)
	}

	// 6. Broken credential: failure recorded, with a bounded backoff
	// strictly earlier than the healthy renewal's own schedule.
	const brokenURL = "http://challtestsrv:1" // unreachable port; loopback is refused at save time
	c.call(ctx, t, http.MethodPut, "/api/v1/orgs/"+orgID+"/dns-credentials/"+cred.ID, map[string]any{
		"name": "challtestsrv", "config": map[string]string{"CHALLTESTSRV_URL": brokenURL},
	}, nil)
	beforeBreak := time.Now()
	waitFor(ctx, t, "renewal to be enqueued", func() (bool, bool) {
		var res struct {
			Enqueued bool `json:"enqueued"`
		}
		c.call(ctx, t, http.MethodPost, certPath+"/renew", nil, &res)
		return res.Enqueued, res.Enqueued
	})
	cert = waitFor(ctx, t, "failure", func() (certOut, bool) {
		var cur certOut
		c.call(ctx, t, http.MethodGet, certPath, nil, &cur)
		return cur, cur.FailureCount == 1
	})
	if cert.FailureCount != 1 {
		t.Fatalf("failureCount = %d, want 1", cert.FailureCount)
	}
	if cert.LastError == "" {
		t.Fatal("lastError is empty after a failed renewal")
	}
	if strings.Contains(cert.LastError, brokenURL) {
		t.Fatalf("lastError leaks the broken credential value: %s", cert.LastError)
	}
	if cert.NextRenewAt == nil {
		t.Fatal("nextRenewAt missing after a failed renewal")
	}
	nextRenew, err := time.Parse(time.RFC3339, *cert.NextRenewAt)
	if err != nil {
		t.Fatal(err)
	}
	if !nextRenew.Before(prevNextRenew) {
		t.Fatalf("nextRenewAt %s is not earlier than the healthy renewal's schedule %s", nextRenew, prevNextRenew)
	}
	lo, hi := beforeBreak.Add(4*time.Minute), beforeBreak.Add(6*time.Minute)
	if nextRenew.Before(lo) || nextRenew.After(hi) {
		t.Fatalf("nextRenewAt %s outside the first-backoff window [%s, %s] (5m +/-20%%)", nextRenew, lo, hi)
	}
	if cert.Status != "active" {
		t.Fatalf("a failed renewal must keep a valid cert active, got %s", cert.Status)
	}
	var attempts []struct {
		Outcome string `json:"outcome"`
	}
	c.call(ctx, t, http.MethodGet, certPath+"/attempts", nil, &attempts)
	if len(attempts) == 0 || attempts[0].Outcome != "failed" {
		t.Fatalf("newest attempt = %+v", attempts)
	}
}
