package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
)

const akToken = "ak-secret-token-123"

type akCall struct {
	Method, Path, RawQuery, Auth string
	Body                         map[string]any
}

type fakeAuthentik struct {
	mu      sync.Mutex
	calls   []akCall
	results string // JSON array for GET results
	status  int    // forced status for every call when non-zero
}

func (f *fakeAuthentik) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c := akCall{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Auth: r.Header.Get("Authorization")}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &c.Body)
	}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, `{"detail":"nope"}`)
		return
	}
	switch r.Method {
	case http.MethodGet:
		_, _ = io.WriteString(w, `{"results":`+f.results+`}`)
	case http.MethodPost:
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"pk":"new-pk"}`)
	default:
		_, _ = io.WriteString(w, `{"pk":"x"}`)
	}
}

func akMaterial(t *testing.T) (*render.Material, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "web"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk8, _ := x509.MarshalPKCS8PrivateKey(key)
	sum := sha256.Sum256(der)
	return &render.Material{LeafDER: der, PrivateKeyPKCS8: pk8}, hex.EncodeToString(sum[:])
}

func akRequest(t *testing.T, url, caPem string, m *render.Material) targets.Request {
	t.Helper()
	cfg, _ := json.Marshal(map[string]any{"url": url, "token": akToken, "caPem": caPem, "timeoutSeconds": 5})
	return targets.Request{CertName: "web", Material: m, Config: cfg, HTTP: targets.HTTPFactory{AllowLoopback: true}}
}

func TestAuthentikCreate(t *testing.T) {
	f := &fakeAuthentik{results: `[]`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	res, err := Authentik{}.Deploy(context.Background(), akRequest(t, srv.URL, "", m))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "keypair new-pk created" {
		t.Fatalf("detail = %q", res.Detail)
	}
	if len(f.calls) != 2 || f.calls[1].Method != "POST" || f.calls[1].Path != "/api/v3/crypto/certificatekeypairs/" {
		t.Fatalf("calls = %+v", f.calls)
	}
	if f.calls[0].Auth != "Bearer "+akToken || f.calls[0].RawQuery != "name=web&page_size=2" {
		t.Fatalf("get = %+v", f.calls[0])
	}
	b := f.calls[1].Body
	if b["name"] != "web" || !strings.Contains(b["certificate_data"].(string), "BEGIN CERTIFICATE") || !strings.Contains(b["key_data"].(string), "PRIVATE KEY") {
		t.Fatalf("body = %+v", b)
	}
}

func TestAuthentikUpdateKeepsPK(t *testing.T) {
	f := &fakeAuthentik{results: `[{"pk":"abc","name":"web","fingerprint_sha256":"00"},{"pk":"zzz","name":"web2"}]`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	res, err := Authentik{}.Deploy(context.Background(), akRequest(t, srv.URL, "", m))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "keypair abc updated" {
		t.Fatalf("detail = %q", res.Detail)
	}
	if c := f.calls[1]; c.Method != "PATCH" || c.Path != "/api/v3/crypto/certificatekeypairs/abc/" {
		t.Fatalf("call = %+v", c)
	}
}

func TestAuthentikUnchangedSkips(t *testing.T) {
	m, fp := akMaterial(t)
	f := &fakeAuthentik{results: `[{"pk":"abc","name":"web","fingerprint_sha256":"` + strings.ToUpper(fp) + `"}]`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	res, err := Authentik{}.Deploy(context.Background(), akRequest(t, srv.URL, "", m))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "unchanged" || len(f.calls) != 1 {
		t.Fatalf("detail=%q calls=%d", res.Detail, len(f.calls))
	}
}

func TestAuthentikForbiddenHidesToken(t *testing.T) {
	f := &fakeAuthentik{status: 403}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	_, err := Authentik{}.Deploy(context.Background(), akRequest(t, srv.URL, "", m))
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), akToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthentikTwoMatches(t *testing.T) {
	f := &fakeAuthentik{results: `[{"pk":"a","name":"web"},{"pk":"b","name":"web"}]`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	if _, err := (Authentik{}).Deploy(context.Background(), akRequest(t, srv.URL, "", m)); err == nil || len(f.calls) != 1 {
		t.Fatalf("err=%v calls=%d", err, len(f.calls))
	}
}

func TestAuthentikCAPem(t *testing.T) {
	f := &fakeAuthentik{results: `[]`}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	if _, err := (Authentik{}).Deploy(context.Background(), akRequest(t, srv.URL, "", m)); err == nil {
		t.Fatal("untrusted server accepted")
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if _, err := (Authentik{}).Deploy(context.Background(), akRequest(t, srv.URL, ca, m)); err != nil {
		t.Fatal(err)
	}
}

func TestAuthentikParse(t *testing.T) {
	cfg, err := Authentik{}.Parse(json.RawMessage(`{"url":"https://ak.example.com/","token":"t"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NeedsKey || cfg.Secrets["token"] != "t" || len(cfg.URLs) != 1 || cfg.URLs[0] != "https://ak.example.com" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if strings.Contains(string(cfg.Public), `"token"`) || !strings.Contains(string(cfg.Public), `"timeoutSeconds":30`) {
		t.Fatalf("public = %s", cfg.Public)
	}
	for _, bad := range []string{
		`{"url":"http://ak.example.com","token":"t"}`,
		`{"url":"https://ak.example.com"}`,
		`{"url":"https://ak.example.com","token":"t","name":"a/b"}`,
		`{"url":"https://ak.example.com","token":"t","timeoutSeconds":1}`,
		`{"url":"https://ak.example.com","token":"t","x":1}`,
	} {
		if _, err := (Authentik{}).Parse(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
