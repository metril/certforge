package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/client"
)

var (
	testOrgID = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	testCert  = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	testVer   = uuid.MustParse("33333333-3333-3333-3333-333333333333")
)

// ok404 writes a minimal RFC 9457 problem+json body.
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	d := detail
	_ = json.NewEncoder(w).Encode(client.Problem{Type: "about:blank", Title: title, Status: status, Detail: &d})
}

// --- version ---

// TestVersionCommand asserts "version" bypasses commandTable (no
// --url/--token, so no server contact) like "help", and prints the
// stamped build version.
func TestVersionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	old := version
	version = "v1.2.3"
	defer func() { version = old }()
	code := run(context.Background(), []string{"version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if got := out.String(); got != "cfctl v1.2.3\n" {
		t.Fatalf("out = %q, want %q", got, "cfctl v1.2.3\n")
	}
}

// --- status ---

func TestStatusCommand(t *testing.T) {
	srv := newFakeAPI(t, "tok", route{"GET", "/server-info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, client.ServerInfo{Version: "1.2.3"})
	}})
	var out, errOut bytes.Buffer
	e := testEnv(t, srv, "tok", "", false, &out, &errOut)
	if code := cmdStatus(context.Background(), e, nil); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "1.2.3") {
		t.Fatalf("out = %q", out.String())
	}
}

// --- certs ---

func TestCertsListFollowsCursorWithAll(t *testing.T) {
	page1 := client.CertificateList{
		Items:      []client.Certificate{{Id: testCert, Name: "a", Status: "active"}},
		NextCursor: strPtr("page2"),
	}
	page2 := client.CertificateList{
		Items:      []client.Certificate{{Id: uuid.New(), Name: "b", Status: "pending"}},
		NextCursor: nil,
	}
	srv := newFakeAPI(t, "tok", route{"GET", "/orgs/" + testOrgID.String() + "/certificates", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "page2" {
			writeJSON(w, http.StatusOK, page2)
			return
		}
		writeJSON(w, http.StatusOK, page1)
	}})

	t.Run("without --all stops after the first page", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := certsList(context.Background(), e, nil); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if strings.Contains(out.String(), "pending") {
			t.Fatalf("expected only page 1, got %q", out.String())
		}
	})

	t.Run("--all follows every page", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := certsList(context.Background(), e, []string{"--all"}); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "active") || !strings.Contains(out.String(), "pending") {
			t.Fatalf("expected both pages, got %q", out.String())
		}
	})
}

func TestCertsListAllOrgsWithoutOrg(t *testing.T) {
	srv := newFakeAPI(t, "tok", route{"GET", "/certificates", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, client.CertificateList{Items: []client.Certificate{{Id: testCert, Name: "global-cert", Status: "active"}}})
	}})
	var out, errOut bytes.Buffer
	e := testEnv(t, srv, "tok", "", false, &out, &errOut)
	if code := certsList(context.Background(), e, nil); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "global-cert") {
		t.Fatalf("out = %q", out.String())
	}
}

func TestCertsGetRenew(t *testing.T) {
	base := "/orgs/" + testOrgID.String() + "/certificates/" + testCert.String()
	srv := newFakeAPI(t, "tok",
		route{"GET", base, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.Certificate{Id: testCert, Name: "www", CommonName: "www.example.com", Status: "active"})
		}},
		route{"POST", base + "/renew", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusAccepted, client.RenewResult{Enqueued: true})
		}},
	)

	t.Run("get", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := certsGet(context.Background(), e, []string{testCert.String()}); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "www.example.com") {
			t.Fatalf("out = %q", out.String())
		}
	})

	t.Run("renew", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := certsRenew(context.Background(), e, []string{testCert.String()}); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "enqueued=true") {
			t.Fatalf("out = %q", out.String())
		}
	})
}

func TestCertsDownloadWritesParts(t *testing.T) {
	base := "/orgs/" + testOrgID.String() + "/certificates/" + testCert.String()
	pemBody := "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
	srv := newFakeAPI(t, "tok",
		route{"GET", base, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.Certificate{
				Id: testCert, Name: "www", Status: "active",
				CurrentVersion: &client.CertificateVersion{Id: testVer, NotAfter: time.Now(), NotBefore: time.Now()},
			})
		}},
		route{"GET", base + "/versions/" + testVer.String() + "/download", func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("parts"); got != "fullchain,key" {
				t.Errorf("parts = %q, want fullchain,key", got)
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(pemBody))
		}},
	)

	dir := t.TempDir()
	out := filepath.Join(dir, "cert.pem")
	var stdout, stderr bytes.Buffer
	e := testEnv(t, srv, "tok", testOrgID.String(), false, &stdout, &stderr)
	if code := certsDownload(context.Background(), e, []string{"--out", out, testCert.String()}); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != pemBody {
		t.Fatalf("data = %q", data)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

// --- clients ---

func TestClientsListGet(t *testing.T) {
	clientID := uuid.New()
	srv := newFakeAPI(t, "tok",
		route{"GET", "/orgs/" + testOrgID.String() + "/clients", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.ClientList{Items: []client.Client{{Id: clientID, Name: "host1", Status: "active", Online: true}}})
		}},
		route{"GET", "/orgs/" + testOrgID.String() + "/clients/" + clientID.String(), func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.Client{Id: clientID, Name: "host1", Status: "active", Online: true, Hostname: "host1.local"})
		}},
	)

	t.Run("list", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := clientsList(context.Background(), e, nil); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "host1") {
			t.Fatalf("out = %q", out.String())
		}
	})

	t.Run("get", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := clientsGet(context.Background(), e, []string{clientID.String()}); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "host1.local") {
			t.Fatalf("out = %q", out.String())
		}
	})
}

// --- channels ---

func TestChannelsListTest(t *testing.T) {
	chanID := uuid.New()
	srv := newFakeAPI(t, "tok",
		route{"GET", "/orgs/" + testOrgID.String() + "/channels", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, []client.Channel{{Id: chanID, Name: "ops-webhook", Type: "webhook", Enabled: true, Summary: "hooks.example.com"}})
		}},
		route{"POST", "/orgs/" + testOrgID.String() + "/channels/" + chanID.String() + "/test", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.DeliveryResult{Status: "delivered", DurationMs: 42})
		}},
	)

	t.Run("list", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := channelsList(context.Background(), e, nil); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "ops-webhook") {
			t.Fatalf("out = %q", out.String())
		}
	})

	t.Run("test", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := channelsTest(context.Background(), e, []string{chanID.String()}); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "delivered") {
			t.Fatalf("out = %q", out.String())
		}
	})
}

// --- monitors ---

func TestMonitorsListCheck(t *testing.T) {
	monID := uuid.New()
	srv := newFakeAPI(t, "tok",
		route{"GET", "/orgs/" + testOrgID.String() + "/monitors", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, []client.Monitor{{Id: monID, Name: "edge", Host: "edge.example.com", Port: 443, State: "ok"}})
		}},
		route{"POST", "/orgs/" + testOrgID.String() + "/monitors/" + monID.String() + "/check", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.Monitor{Id: monID, Name: "edge", Host: "edge.example.com", Port: 443, State: "mismatch"})
		}},
	)

	t.Run("list", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := monitorsList(context.Background(), e, nil); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "edge") {
			t.Fatalf("out = %q", out.String())
		}
	})

	t.Run("check", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
		if code := monitorsCheck(context.Background(), e, []string{monID.String()}); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "mismatch") {
			t.Fatalf("out = %q", out.String())
		}
	})
}

// --- events ---

func TestEventsListFilters(t *testing.T) {
	srv := newFakeAPI(t, "tok", route{"GET", "/orgs/" + testOrgID.String() + "/events", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q["kind"]; len(got) != 2 || got[0] != "cert.issued" || got[1] != "monitor.mismatch" {
			t.Errorf("kind = %v, want [cert.issued monitor.mismatch]", got)
		}
		if got := q.Get("severity"); got != "warning" {
			t.Errorf("severity = %q, want warning", got)
		}
		if got := q.Get("since"); got == "" {
			t.Errorf("since missing")
		}
		writeJSON(w, http.StatusOK, client.EventPage{Items: []client.Event{{Id: uuid.New(), Kind: "cert.issued", Severity: "info", At: time.Now(), Summary: "issued"}}})
	}})
	var out, errOut bytes.Buffer
	e := testEnv(t, srv, "tok", testOrgID.String(), false, &out, &errOut)
	code := eventsList(context.Background(), e, []string{
		"--kind", "cert.issued", "--kind", "monitor.mismatch", "--severity", "warning", "--since", "2026-01-01T00:00:00Z",
	})
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "issued") {
		t.Fatalf("out = %q", out.String())
	}
}

// --- keys ---

func TestKeysStatusRewrap(t *testing.T) {
	srv := newFakeAPI(t, "tok",
		route{"GET", "/keys/status", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.KeysStatus{KekId: "kek-1", Kind: "static", CanaryOk: true})
		}},
		route{"POST", "/keys/rewrap", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusAccepted, client.KeysStatus{KekId: "kek-1", Kind: "static", CanaryOk: true,
				Rewrap: &client.RewrapStatus{ActiveKekId: "kek-1", Running: true, Remaining: 100, StartedAt: time.Now()}})
		}},
	)

	t.Run("status", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", "", false, &out, &errOut)
		if code := keysStatus(context.Background(), e, nil); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "kek-1") {
			t.Fatalf("out = %q", out.String())
		}
	})

	t.Run("rewrap", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, srv, "tok", "", false, &out, &errOut)
		if code := keysRewrap(context.Background(), e, nil); code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), "true") {
			t.Fatalf("out = %q", out.String())
		}
	})
}

// --- backup ---

func TestBackupCreateStreamsToFile(t *testing.T) {
	archiveBytes := []byte("CFBAK1\nfake-archive-contents")
	srv := newFakeAPI(t, "tok", route{"POST", "/backup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archiveBytes)
	}})
	dir := t.TempDir()
	out := filepath.Join(dir, "backup.cfbak")
	var stdout, stderr bytes.Buffer
	e := testEnv(t, srv, "tok", "", false, &stdout, &stderr)
	if code := backupCreate(context.Background(), e, []string{"--out", out}); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, archiveBytes) {
		t.Fatalf("data = %q", data)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the final file, got %v (no temp file should survive)", entries)
	}
}

// TestBackupCreateSlowBodySurvivesTimeout covers batch-5 review finding 1:
// --timeout must bound connecting and the wait for response headers, never
// the whole body — a real archive can legitimately take longer than
// --timeout to stream. The fake server writes and flushes one byte at a
// time with a delay between each, so the body alone takes several times
// longer than the tiny timeout given to newClients; backupCreate must
// still finish successfully.
func TestBackupCreateSlowBodySurvivesTimeout(t *testing.T) {
	archiveBytes := []byte("CFBAK1\nfake-archive-that-streams-slowly-past-the-timeout")
	srv := newFakeAPI(t, "tok", route{"POST", "/backup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, b := range archiveBytes {
			_, _ = w.Write([]byte{b})
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(5 * time.Millisecond)
		}
	}})
	dir := t.TempDir()
	out := filepath.Join(dir, "backup.cfbak")
	var stdout, stderr bytes.Buffer
	// len(archiveBytes) * 5ms is well over ten times this timeout: headers
	// arrive instantly (WriteHeader runs before the slow loop), so only a
	// whole-body cap would ever make this time out.
	e := testEnvTimeout(t, srv, "tok", "", false, 20*time.Millisecond, &stdout, &stderr)
	if code := backupCreate(context.Background(), e, []string{"--out", out}); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, archiveBytes) {
		t.Fatalf("data = %q, want %q", data, archiveBytes)
	}
}

// TestBackupCreateLeavesNoTempFileOnError covers the failure half of the
// same contract: a stream that breaks partway through must not leave a
// temp file behind either.
func TestBackupCreateLeavesNoTempFileOnError(t *testing.T) {
	srv := newFakeAPI(t, "tok", route{"POST", "/backup", func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, http.StatusConflict, "Conflict", "backup already running")
	}})
	dir := t.TempDir()
	out := filepath.Join(dir, "backup.cfbak")
	var stdout, stderr bytes.Buffer
	e := testEnv(t, srv, "tok", "", false, &stdout, &stderr)
	if code := backupCreate(context.Background(), e, []string{"--out", out}); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "backup already running") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files left behind, got %v", entries)
	}
}

// --- audit ---

func TestAuditList(t *testing.T) {
	srv := newFakeAPI(t, "tok", route{"GET", "/audit", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("action"); got != "session.login" {
			t.Errorf("action = %q, want session.login", got)
		}
		writeJSON(w, http.StatusOK, client.AuditEventList{Items: []client.AuditEvent{
			{Id: 1, Action: "session.login", ActorName: "alice", Ts: time.Now(), ResourceType: "session", ResourceId: "s1"},
		}})
	}})
	var out, errOut bytes.Buffer
	e := testEnv(t, srv, "tok", "", false, &out, &errOut)
	if code := auditList(context.Background(), e, []string{"--action", "session.login"}); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "alice") {
		t.Fatalf("out = %q", out.String())
	}
}

// --- org resolution ---

func TestOrgSlugResolves(t *testing.T) {
	srv := newFakeAPI(t, "tok",
		route{"GET", "/orgs", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.OrgList{Items: []client.Org{{Id: testOrgID, Name: "Acme", Slug: "acme"}}})
		}},
		route{"GET", "/orgs/" + testOrgID.String() + "/monitors", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, []client.Monitor{})
		}},
	)
	var out, errOut bytes.Buffer
	e := testEnv(t, srv, "tok", "acme", false, &out, &errOut)
	if code := monitorsList(context.Background(), e, nil); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
}

func TestOrgSlugUnknown(t *testing.T) {
	srv := newFakeAPI(t, "tok", route{"GET", "/orgs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, client.OrgList{Items: []client.Org{{Id: testOrgID, Name: "Acme", Slug: "acme"}}})
	}})
	var out, errOut bytes.Buffer
	e := testEnv(t, srv, "tok", "no-such-org", false, &out, &errOut)
	if code := monitorsList(context.Background(), e, nil); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "no-such-org") {
		t.Fatalf("errOut = %q", errOut.String())
	}
}

// --- --json raw output ---

func TestJSONOutput(t *testing.T) {
	raw := `{"version":"9.9.9"}`
	srv := newFakeAPI(t, "tok", route{"GET", "/server-info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(raw))
	}})
	var out, errOut bytes.Buffer
	e := testEnv(t, srv, "tok", "", true, &out, &errOut)
	if code := cmdStatus(context.Background(), e, nil); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != raw {
		t.Fatalf("out = %q, want the raw server body %q", out.String(), raw)
	}
}

// --- problem rendering end to end ---

func TestProblemRenderingEndToEnd(t *testing.T) {
	srv := newFakeAPI(t, "tok", route{"GET", "/server-info", func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, http.StatusForbidden, "Forbidden", "global admin only")
	}})
	var out, errOut bytes.Buffer
	e := testEnv(t, srv, "tok", "", false, &out, &errOut)
	if code := cmdStatus(context.Background(), e, nil); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if strings.TrimSpace(errOut.String()) != "error: Forbidden: global admin only" {
		t.Fatalf("errOut = %q", errOut.String())
	}
}

// --- token never leaks ---

// TestNeverPrintsToken drives several commands, on both success and
// server-error paths, and asserts the bearer token never appears in
// stdout or stderr — including inside a client-library error string,
// which is why the token here is deliberately unusual (unlikely to
// collide with any other test fixture).
func TestNeverPrintsToken(t *testing.T) {
	const token = "s3cr3t-token-xyz"
	monID := uuid.New()

	okSrv := newFakeAPI(t, token,
		route{"GET", "/server-info", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, client.ServerInfo{Version: "1.0.0"})
		}},
		route{"GET", "/orgs/" + testOrgID.String() + "/monitors", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, []client.Monitor{{Id: monID, Name: "edge", Host: "edge.example.com", Port: 443, State: "ok"}})
		}},
	)
	errSrv := newFakeAPI(t, token,
		route{"GET", "/server-info", func(w http.ResponseWriter, r *http.Request) {
			writeProblem(w, http.StatusUnauthorized, "Invalid API key", "the bearer token is malformed, unknown, expired, or revoked")
		}},
	)

	check := func(t *testing.T, out, errOut *bytes.Buffer) {
		t.Helper()
		if strings.Contains(out.String(), token) {
			t.Fatalf("token leaked into stdout: %q", out.String())
		}
		if strings.Contains(errOut.String(), token) {
			t.Fatalf("token leaked into stderr: %q", errOut.String())
		}
	}

	t.Run("status success", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, okSrv, token, "", false, &out, &errOut)
		cmdStatus(context.Background(), e, nil)
		check(t, &out, &errOut)
	})

	t.Run("status error", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, errSrv, token, "", false, &out, &errOut)
		cmdStatus(context.Background(), e, nil)
		check(t, &out, &errOut)
	})

	t.Run("monitors list success", func(t *testing.T) {
		var out, errOut bytes.Buffer
		e := testEnv(t, okSrv, token, testOrgID.String(), false, &out, &errOut)
		monitorsList(context.Background(), e, nil)
		check(t, &out, &errOut)
	})

	t.Run("bad server url never echoes a token that was never sent", func(t *testing.T) {
		var out, errOut bytes.Buffer
		cwr, raw, err := newClients(Config{URL: "http://127.0.0.1:1", Token: token}, 100*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		e := &env{cwr: cwr, raw: raw, stdout: &out, stderr: &errOut}
		cmdStatus(context.Background(), e, nil)
		check(t, &out, &errOut)
	})
}

// --- usage / exit codes ---

func TestUsageExit2(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"unknown command", []string{"--url", "http://x", "--token", "t", "bogus"}},
		{"bad global flag", []string{"--nope"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := runWithEnv(context.Background(), c.args, &out, &errOut, envMap(nil))
			if code != 2 {
				t.Fatalf("code = %d, want 2 (stderr %q)", code, errOut.String())
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runWithEnv(context.Background(), []string{"help"}, &out, &errOut, envMap(nil)); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out.String(), "certs") {
		t.Fatalf("usage missing commands: %q", out.String())
	}
}

func TestRunRequiresConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runWithEnv(context.Background(), []string{"status"}, &out, &errOut, envMap(map[string]string{"XDG_CONFIG_HOME": t.TempDir()}))
	if code != 2 {
		t.Fatalf("code = %d, want 2, stderr = %q", code, errOut.String())
	}
}

// TestRunEndToEnd covers run/runWithEnv actually dispatching through to a
// command against a fake server, config coming from flags.
func TestRunEndToEnd(t *testing.T) {
	srv := newFakeAPI(t, "tok", route{"GET", "/server-info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, client.ServerInfo{Version: "e2e"})
	}})
	var out, errOut bytes.Buffer
	code := runWithEnv(context.Background(), []string{"--url", srv.URL, "--token", "tok", "status"}, &out, &errOut, envMap(nil))
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "e2e") {
		t.Fatalf("out = %q", out.String())
	}
}

// TestNonJSONSuccessIsAnError asserts a 200 whose body the generated client
// did not decode (no JSON content type) is reported, not dereferenced.
func TestNonJSONSuccessIsAnError(t *testing.T) {
	plain := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>proxy</html>"))
	}
	srv := newFakeAPI(t, "tok",
		route{"GET", "/server-info", plain},
		route{"GET", "/keys/status", plain},
		route{"GET", "/orgs", plain},
	)
	for name, call := range map[string]func(e *env) int{
		"status":     func(e *env) int { return cmdStatus(context.Background(), e, nil) },
		"keysStatus": func(e *env) int { return keysStatus(context.Background(), e, nil) },
		"orgSlug":    func(e *env) int { return monitorsList(context.Background(), e, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			org := ""
			if name == "orgSlug" {
				org = "acme"
			}
			e := testEnv(t, srv, "tok", org, false, &out, &errOut)
			if code := call(e); code != 1 {
				t.Fatalf("code = %d, want 1", code)
			}
			if !strings.Contains(errOut.String(), "non-JSON") {
				t.Fatalf("stderr = %q", errOut.String())
			}
		})
	}
}

func TestInsecureURLWarning(t *testing.T) {
	for raw, warn := range map[string]bool{
		"https://certforge.example.com": false,
		"http://127.0.0.1:8080":         false,
		"http://localhost:8080":         false,
		"http://[::1]:8080":             false,
		"http://certforge.example.com":  true,
		"http://10.0.0.5":               true,
		"ftp://certforge.example.com":   true,
	} {
		if got := insecureURLWarning(raw) != ""; got != warn {
			t.Errorf("%s: warning = %v, want %v", raw, got, warn)
		}
	}
}
