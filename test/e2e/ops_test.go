//go:build e2e

package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// opsBackupFormat/opsBackupMagic mirror internal/backup's own Format/Magic
// constants (Shared contract): this test parses a .cfbak header the same
// way any outside tool would — by the documented framing (a 7-byte magic,
// a 4-byte big-endian length, then the header JSON) — rather than
// importing internal/backup, keeping every e2e test's proof at arm's
// length from the server's own implementation.
const (
	opsBackupFormat = "certforge-backup-v1"
	opsBackupMagic  = "CFBAK1\n"
)

type opsBackupHeader struct {
	Format           string `json:"format"`
	CreatedAt        string `json:"createdAt"`
	MigrationVersion int64  `json:"migrationVersion"`
}

// parseOpsBackupHeader reads and validates a .cfbak archive's plaintext
// header without decrypting anything, proving cfctl backup create wrote a
// well-formed archive (task-15-brief: "produces a file whose header
// parses").
func parseOpsBackupHeader(t *testing.T, path string) opsBackupHeader {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	magic := make([]byte, len(opsBackupMagic))
	if _, err := io.ReadFull(f, magic); err != nil {
		t.Fatalf("%s: read magic: %v", path, err)
	}
	if string(magic) != opsBackupMagic {
		t.Fatalf("%s: bad magic %q", path, magic)
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
		t.Fatalf("%s: read header length: %v", path, err)
	}
	raw := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
	if _, err := io.ReadFull(f, raw); err != nil {
		t.Fatalf("%s: read header: %v", path, err)
	}
	var h opsBackupHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("%s: decode header: %v", path, err)
	}
	if h.Format != opsBackupFormat {
		t.Fatalf("%s: format = %q, want %q", path, h.Format, opsBackupFormat)
	}
	return h
}

// opsSinkDelivery is one POST the webhook sink received.
type opsSinkDelivery struct {
	Event     string
	Signature string
	Body      []byte
}

// opsWebhookSink is a plain HTTP server the host-side test itself runs, on
// 0.0.0.0:CF_E2E_SINK_PORT (task-15-brief step 2), reached by the compose
// server as http://host.docker.internal:<port>/hook (deploy/compose.test.
// yaml's extra_hosts on the certforge service).
type opsWebhookSink struct {
	mu         sync.Mutex
	deliveries []opsSinkDelivery
	srv        *http.Server
}

func startOpsWebhookSink(t *testing.T, port string) *opsWebhookSink {
	t.Helper()
	sink := &opsWebhookSink{}
	mux := http.NewServeMux()
	mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sink.mu.Lock()
		sink.deliveries = append(sink.deliveries, opsSinkDelivery{
			Event:     r.Header.Get("X-CertForge-Event"),
			Signature: r.Header.Get("X-CertForge-Signature"),
			Body:      body,
		})
		sink.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		t.Fatalf("webhook sink listen on 0.0.0.0:%s: %v", port, err)
	}
	sink.srv = &http.Server{Handler: mux}
	go func() { _ = sink.srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sink.srv.Shutdown(ctx)
	})
	return sink
}

// deliveryFor returns the most recent delivery whose X-CertForge-Event
// header equals kind, so a stray "test" delivery from another channel
// action can never be mistaken for the cert.issued one this test waits on.
func (s *opsWebhookSink) deliveryFor(kind string) (opsSinkDelivery, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.deliveries) - 1; i >= 0; i-- {
		if s.deliveries[i].Event == kind {
			return s.deliveries[i], true
		}
	}
	return opsSinkDelivery{}, false
}

// opsMailpitMessage/opsMailpitList mirror mailpit's own GET /api/v1/messages
// response shape (only the fields this test reads).
type opsMailpitMessage struct {
	ID      string `json:"ID"`
	Subject string `json:"Subject"`
}

type opsMailpitList struct {
	Messages []opsMailpitMessage `json:"messages"`
}

// opsMailpitFull mirrors GET /api/v1/message/{ID}.
type opsMailpitFull struct {
	Text string `json:"Text"`
}

// waitForMailpitReady polls mailpit's own HTTP API (bounded 60s), the same
// convention as waitForPebbleReady: compose --wait has no healthcheck for
// mailpit (Task 15's compose comment), so the very first email send must
// not race the API listener coming up.
func waitForMailpitReady(ctx context.Context, t *testing.T, mailpitURL string) {
	t.Helper()
	readyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(readyCtx, http.MethodGet, mailpitURL+"/api/v1/messages", nil)
		if err == nil {
			if resp, doErr := http.DefaultClient.Do(req); doErr == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
			}
		}
		select {
		case <-readyCtx.Done():
			t.Fatalf("mailpit API not ready at %s within 60s", mailpitURL)
		case <-time.After(time.Second):
		}
	}
}

func opsMailpitMessages(ctx context.Context, t *testing.T, mailpitURL string) opsMailpitList {
	t.Helper()
	var out opsMailpitList
	b := getBody(ctx, t, mailpitURL+"/api/v1/messages")
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode mailpit messages: %v: %s", err, b)
	}
	return out
}

// opsEventDelivery/opsEvent/opsEventPage mirror the EventDelivery/Event/
// EventPage schemas (Shared contract).
type opsEventDelivery struct {
	ChannelID   string  `json:"channelId"`
	ChannelName string  `json:"channelName"`
	Status      string  `json:"status"`
	LastError   *string `json:"lastError"`
}

type opsEvent struct {
	ID         string             `json:"id"`
	Kind       string             `json:"kind"`
	Summary    string             `json:"summary"`
	Deliveries []opsEventDelivery `json:"deliveries"`
}

type opsEventPage struct {
	Items      []opsEvent `json:"items"`
	NextCursor *string    `json:"nextCursor"`
}

// opsMonitorOut mirrors the Monitor schema (only the fields checked here).
type opsMonitorOut struct {
	ID              string  `json:"id"`
	State           string  `json:"state"`
	LastFingerprint *string `json:"lastFingerprint"`
	LastError       *string `json:"lastError"`
}

// runCfctl execs the compiled cfctl binary (built by the Makefile's e2e
// target, `.e2e/cfctl`) with a --url/--token prefix, returning combined
// stdout+stderr. It never logs token: only the caller ever sees args.
func runCfctl(ctx context.Context, t *testing.T, cfctlPath, url, token string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"--url", url, "--token", token}, args...)
	cmd := exec.CommandContext(ctx, cfctlPath, full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// cfctlCertIDs decodes one or more concatenated `{items:[{id}], nextCursor}`
// JSON pages (cfctl certs list --json prints one per page under --all) and
// returns every item's id, so a comparison across a restore does not
// depend on the certificate count fitting a single page.
func cfctlCertIDs(t *testing.T, output string) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(output))
	var ids []string
	for {
		var page struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err := dec.Decode(&page); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode cfctl certs list --json output: %v: %s", err, output)
		}
		for _, it := range page.Items {
			ids = append(ids, it.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// TestOpsAgainstCompose (Task 15, R11's proofs) exercises Phase 6A end to
// end against the running compose stack: an issued certificate's
// cert.issued event delivered by webhook (HMAC verified at a host-side
// sink) and by SMTP (read back from mailpit), an external monitor reaching
// ok against Traefik's own e2e-only TLS entrypoint with the deployed
// certificate's fingerprint, /metrics gated by its bearer token, cfctl
// against the generated API client, and an on-demand backup restored into
// a recreated database with the audit chain and certificate list intact
// across the boundary. Run as its own `go test -run` invocation by `make
// e2e`, between the main suite and TestVaultAgainstCompose, since its own
// last step stops and restarts the certforge service out from under the
// rest of the stack.
func TestOpsAgainstCompose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	trust, err := os.ReadFile("testdata/pebble.minica.pem")
	if err != nil {
		t.Fatal(err)
	}
	pebbleRoots := x509.NewCertPool()
	pebbleRoots.AppendCertsFromPEM(trust)
	waitForPebbleReady(ctx, t, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pebbleRoots}}})

	mailpitURL := "http://localhost:" + envOr("CF_MAILPIT_PORT", "18025")
	waitForMailpitReady(ctx, t, mailpitURL)

	sinkPort := envOr("CF_E2E_SINK_PORT", "18090")
	sink := startOpsWebhookSink(t, sinkPort)

	dir := envOr("CF_E2E_AGENT_DIR", "../../.e2e")
	compose := os.Getenv("CF_E2E_COMPOSE")
	if compose == "" {
		t.Fatal("CF_E2E_COMPOSE is not set (run through make e2e)")
	}
	cfctlPath := filepath.Join(dir, "cfctl")

	c := newAPIClient(t)
	orgID := c.authenticate(ctx, t)

	// 1. smtp/prometheus/backup settings, and an admin-scoped API key for
	// cfctl (created now, before the backup this test takes later, so its
	// hash round-trips through the restore the same way the channels and
	// settings below do).
	c.call(ctx, t, http.MethodPut, "/api/v1/settings/smtp", map[string]any{
		"host": "mailpit", "port": 1025, "security": "none", "from": "certforge@e2e.test",
	}, nil)
	const promToken = "ops-e2e-prometheus-scrape-token-01"
	c.call(ctx, t, http.MethodPut, "/api/v1/settings/prometheus", map[string]any{
		"enabled": true, "bearerToken": promToken,
	}, nil)
	c.call(ctx, t, http.MethodPut, "/api/v1/settings/backup", map[string]any{
		"kekEscrowConfirmed": true,
	}, nil)

	var apiKey struct {
		APIKey struct {
			ID string `json:"id"`
		} `json:"apiKey"`
		Token string `json:"token"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/api-keys", map[string]any{
		"name": "ops-e2e-cfctl", "scopes": []string{"admin"},
	}, &apiKey)
	cfctlToken := apiKey.Token

	// 2. Webhook + SMTP channels, both filtered to cert.issued and test.
	const webhookSigningSecret = "ops-e2e-webhook-signing-secret-0123456789"
	var webhookChannel, smtpChannel struct {
		ID string `json:"id"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/channels", map[string]any{
		"name": "ops-webhook", "type": "webhook",
		"config": map[string]any{
			"url":           "http://host.docker.internal:" + sinkPort + "/hook",
			"signingSecret": webhookSigningSecret,
		},
		"events": []string{"cert.issued", "test"},
	}, &webhookChannel)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/channels", map[string]any{
		"name": "ops-smtp", "type": "smtp",
		"config": map[string]any{"to": []string{"ops@e2e.test"}},
		"events": []string{"cert.issued", "test"},
	}, &smtpChannel)

	// 3. Issue a certificate through Pebble; both channels deliver
	// cert.issued.
	var ca, cred, acct struct {
		ID string `json:"id"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/cas", map[string]any{
		"name": "Pebble ops", "preset": "custom", "directoryUrl": "https://pebble:14000/dir",
		"trustBundlePem": string(trust), "resolvers": []string{"challtestsrv:8053"},
	}, &ca)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/dns-credentials", map[string]any{
		"name": "challtestsrv ops", "providerCode": "e2e-challtestsrv",
		"config": map[string]string{"CHALLTESTSRV_URL": "http://challtestsrv:8055"},
	}, &cred)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/acme-accounts", map[string]any{
		"caId": ca.ID, "email": "ops@example.test",
	}, &acct)

	var cert certOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/certificates", map[string]any{
		"name": "ops-e2e", "commonName": "ops.e2e.test",
		"verificationRules": []map[string]any{{"match": "ops.e2e.test", "method": "dns-01", "dnsCredentialId": cred.ID}},
		"overrides":         map[string]any{"caId": ca.ID, "accountId": acct.ID, "keyType": "ec256"},
	}, &cert)
	certPath := "/api/v1/orgs/" + orgID + "/certificates/" + cert.ID
	// 3 minutes, not waitFor60: real ACME issuance through Pebble
	// legitimately exceeds the 60 s wait-loop bound (batch-5 review
	// ruling; same exemption issuance_test.go's own "active" wait takes).
	activeCtx, activeCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer activeCancel()
	cert = waitFor(activeCtx, t, "active", func() (certOut, bool) {
		var cur certOut
		c.call(ctx, t, http.MethodGet, certPath, nil, &cur)
		return cur, cur.Status == "active" || cur.FailureCount > 0
	})
	if cert.Status != "active" {
		t.Fatalf("issuance failed: %s", cert.LastError)
	}
	if cert.CurrentVersion == nil {
		t.Fatal("active certificate has no current version")
	}
	versionID := cert.CurrentVersion.ID

	var versions []versionOut
	c.call(ctx, t, http.MethodGet, certPath+"/versions", nil, &versions)
	if len(versions) == 0 {
		t.Fatal("no versions after issuance")
	}
	versionFP := versions[0].SHA256Fingerprint

	// The sink's HMAC-verified delivery.
	del := waitFor60(ctx, t, "webhook delivery of cert.issued", func() (opsSinkDelivery, bool) {
		return sink.deliveryFor("cert.issued")
	})
	mac := hmac.New(sha256.New, []byte(webhookSigningSecret))
	mac.Write(del.Body)
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if del.Signature != wantSig {
		t.Fatalf("webhook signature = %q, want %q", del.Signature, wantSig)
	}

	// Mailpit's own view: subject and body.
	waitFor60(ctx, t, "mailpit has a message", func() (int, bool) {
		list := opsMailpitMessages(ctx, t, mailpitURL)
		return len(list.Messages), len(list.Messages) > 0
	})
	msgs := opsMailpitMessages(ctx, t, mailpitURL)
	if len(msgs.Messages) == 0 || msgs.Messages[0].Subject == "" {
		t.Fatalf("mailpit message has no subject: %+v", msgs)
	}
	var full opsMailpitFull
	fb := getBody(ctx, t, mailpitURL+"/api/v1/message/"+msgs.Messages[0].ID)
	if err := json.Unmarshal(fb, &full); err != nil {
		t.Fatalf("decode mailpit message: %v: %s", err, fb)
	}
	if !strings.Contains(full.Text, "ops-e2e") {
		t.Fatalf("mailpit message body does not contain the certificate name %q:\n%s", "ops-e2e", full.Text)
	}

	// listEvents: the cert.issued event shows both deliveries delivered.
	ev := waitFor60(ctx, t, "cert.issued event has 2 delivered deliveries", func() (opsEvent, bool) {
		var page opsEventPage
		c.call(ctx, t, http.MethodGet, "/api/v1/orgs/"+orgID+"/events?kind=cert.issued", nil, &page)
		for _, e := range page.Items {
			if e.Kind != "cert.issued" || !strings.Contains(e.Summary, "ops.e2e.test") {
				continue
			}
			delivered := 0
			for _, d := range e.Deliveries {
				if d.Status == "delivered" {
					delivered++
				}
			}
			return e, len(e.Deliveries) == 2 && delivered == 2
		}
		return opsEvent{}, false
	})
	if len(ev.Deliveries) != 2 {
		t.Fatalf("cert.issued event deliveries = %+v, want 2 delivered", ev.Deliveries)
	}

	// 4. Traefik dynamic file: the issued leaf+key as the default
	// certificate on the websecure entrypoint, plus a catch-all router to
	// noop@internal (Deviations R11).
	fullchain := c.download(ctx, t, certPath+"/versions/"+versionID+"/download?format=pem&parts=fullchain")
	key := c.download(ctx, t, certPath+"/versions/"+versionID+"/download?format=pem&parts=key")
	if err := os.MkdirAll(filepath.Join(dir, "traefik", "ops"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "traefik", "ops", "fullchain.pem"), fullchain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "traefik", "ops", "privkey.pem"), key, 0o644); err != nil {
		t.Fatal(err)
	}
	opsYAML := `# Managed by TestOpsAgainstCompose. Do not edit; changes are overwritten.
tls:
  certificates:
    - certFile: "/etc/traefik/dynamic/ops/fullchain.pem"
      keyFile: "/etc/traefik/dynamic/ops/privkey.pem"
      stores:
        - "default"
  stores:
    default:
      defaultCertificate:
        certFile: "/etc/traefik/dynamic/ops/fullchain.pem"
        keyFile: "/etc/traefik/dynamic/ops/privkey.pem"
http:
  routers:
    ops-catchall:
      rule: "PathPrefix(` + "`" + `/` + "`" + `)"
      entryPoints:
        - websecure
      service: noop@internal
`
	if err := os.WriteFile(filepath.Join(dir, "traefik", "certforge-ops.yml"), []byte(opsYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	var monitor opsMonitorOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/monitors", map[string]any{
		"name": "ops-traefik", "host": "traefik", "port": 8443, "expectedCertificateId": cert.ID,
	}, &monitor)
	monitor = waitFor60(ctx, t, "monitor reaches ok with the deployed fingerprint", func() (opsMonitorOut, bool) {
		var m opsMonitorOut
		c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/monitors/"+monitor.ID+"/check", nil, &m)
		return m, m.State == "ok" && m.LastFingerprint != nil && *m.LastFingerprint == versionFP
	})
	if monitor.State != "ok" {
		lastErr := ""
		if monitor.LastError != nil {
			lastErr = *monitor.LastError
		}
		t.Fatalf("monitor state = %s, want ok: %s", monitor.State, lastErr)
	}

	// 5. /metrics: 401 empty body without a token, 200 with certforge_
	// certificates{ with it.
	unauthedReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL()+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	unauthedResp, err := http.DefaultClient.Do(unauthedReq)
	if err != nil {
		t.Fatal(err)
	}
	unauthedBody, _ := io.ReadAll(unauthedResp.Body)
	unauthedResp.Body.Close()
	if unauthedResp.StatusCode != http.StatusUnauthorized || len(unauthedBody) != 0 {
		t.Fatalf("GET /metrics without a token: %d %q, want 401 empty", unauthedResp.StatusCode, unauthedBody)
	}

	authedReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL()+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	authedReq.Header.Set("Authorization", "Bearer "+promToken)
	authedResp, err := http.DefaultClient.Do(authedReq)
	if err != nil {
		t.Fatal(err)
	}
	authedBody, _ := io.ReadAll(authedResp.Body)
	authedResp.Body.Close()
	if authedResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics with a token: %d", authedResp.StatusCode)
	}
	if !strings.Contains(string(authedBody), "certforge_certificates{") {
		t.Fatalf("/metrics body has no certforge_certificates{ series:\n%s", authedBody)
	}

	// 6. cfctl: status, certs list, backup create.
	if out, err := runCfctl(ctx, t, cfctlPath, baseURL(), cfctlToken, "status"); err != nil {
		t.Fatalf("cfctl status: %v\n%s", err, out)
	}

	certsOut, err := runCfctl(ctx, t, cfctlPath, baseURL(), cfctlToken, "--org", orgID, "--json", "certs", "list", "--all")
	if err != nil {
		t.Fatalf("cfctl certs list: %v\n%s", err, certsOut)
	}
	idsBeforeRestore := cfctlCertIDs(t, certsOut)
	if len(idsBeforeRestore) == 0 {
		t.Fatal("cfctl certs list --json returned no certificates")
	}

	backupPath := filepath.Join(dir, "ops.cfbak")
	if out, err := runCfctl(ctx, t, cfctlPath, baseURL(), cfctlToken, "backup", "create", "--out", backupPath); err != nil {
		t.Fatalf("cfctl backup create: %v\n%s", err, out)
	}
	parseOpsBackupHeader(t, backupPath)

	// 7. Stop certforge, drop and recreate the database, restore, restart,
	// and check the certificate list and the audit chain match.
	runSh(ctx, t, nil, compose+" stop certforge")

	dbPassword := envOr("CF_DB_PASSWORD", "certforge")
	dropRecreate := compose + ` exec -T postgres psql -U certforge -d postgres -c "DROP DATABASE certforge;" -c "CREATE DATABASE certforge;"`
	runSh(ctx, t, []string{"PGPASSWORD=" + dbPassword}, dropRecreate)

	restoreIn, err := os.Open(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	restoreCmd := exec.CommandContext(ctx, "sh", "-c", compose+" run --rm -T certforge restore --in - --yes")
	restoreCmd.Stdin = restoreIn
	restoreOut, restoreErr := restoreCmd.CombinedOutput()
	restoreIn.Close()
	if restoreErr != nil {
		t.Fatalf("restore: %v\n%s", restoreErr, restoreOut)
	}
	if !strings.Contains(string(restoreOut), "restore complete") {
		t.Fatalf("restore did not report completion:\n%s", restoreOut)
	}

	runSh(ctx, t, nil, compose+" start certforge")
	waitFor60(ctx, t, "readyz after restore", func() (int, bool) {
		code, _ := getReadyz(ctx, t)
		return code, code == http.StatusOK
	})

	certsAfterOut, err := runCfctl(ctx, t, cfctlPath, baseURL(), cfctlToken, "--org", orgID, "--json", "certs", "list", "--all")
	if err != nil {
		t.Fatalf("cfctl certs list after restore: %v\n%s", err, certsAfterOut)
	}
	idsAfterRestore := cfctlCertIDs(t, certsAfterOut)
	if fmt.Sprint(idsAfterRestore) != fmt.Sprint(idsBeforeRestore) {
		t.Fatalf("certificate ids after restore = %v, want %v", idsAfterRestore, idsBeforeRestore)
	}

	verifyAuditChain(ctx, t, c)
}
