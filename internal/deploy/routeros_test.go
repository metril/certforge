package deploy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
)

const roPass = "ro-secret-pass-123"

type roCall struct {
	Method, Path string
	Body         map[string]any
}

type fakeRO struct {
	mu      sync.Mutex
	calls   []roCall
	certs   []map[string]any
	fp      string // fingerprint given to the imported certificate
	noKey   bool   // imported certificate lacks its private key
	noAuth  bool
	removeF bool // cert remove fails
}

func (f *fakeRO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c := roCall{Method: r.Method, Path: r.URL.Path}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &c.Body)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	if u, p, ok := r.BasicAuth(); f.noAuth || !ok || u != "admin" || p != roPass {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":401,"message":"bad `+roPass+`"}`)
		return
	}
	switch r.URL.Path {
	case "/rest/certificate":
		_ = json.NewEncoder(w).Encode(f.certs)
	case "/rest/certificate/import":
		if strings.HasSuffix(c.Body["file-name"].(string), ".key") {
			pk := "true"
			if f.noKey {
				pk = "false"
			}
			f.certs = append(f.certs, map[string]any{".id": "*N", "name": "cf-x.crt_0", "fingerprint": strings.ToUpper(f.fp), "private-key": pk})
		}
		_, _ = io.WriteString(w, `{"certificates-imported":"1"}`)
	case "/rest/certificate/remove":
		if f.removeF {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"message":"in use"}`)
			return
		}
		_, _ = io.WriteString(w, `[]`)
	case "/rest/ip/service":
		_, _ = io.WriteString(w, `[{".id":"*1","name":"www"},{".id":"*2","name":"www-ssl"},{".id":"*3","name":"api-ssl"}]`)
	default:
		_, _ = io.WriteString(w, `[]`)
	}
}

func (f *fakeRO) paths() string {
	var p []string
	for _, c := range f.calls {
		p = append(p, c.Method+" "+strings.TrimPrefix(c.Path, "/rest"))
	}
	return strings.Join(p, ",")
}

func roReq(t *testing.T, srvURL string, ssh *sshxtest.Server, m *render.Material, mod func(map[string]any)) targets.Request {
	t.Helper()
	cfg := map[string]any{"url": srvURL, "username": "admin", "password": roPass, "sshPort": ssh.Port(t),
		"hostKey": ssh.HostLine(), "timeoutSeconds": 10}
	if mod != nil {
		mod(cfg)
	}
	raw, _ := json.Marshal(cfg)
	return targets.Request{CertName: "web", Material: m, Config: raw, HTTP: targets.HTTPFactory{AllowLoopback: true}}
}

func roSetup(t *testing.T) (*fakeRO, *httptest.Server, *sshxtest.Server, *render.Material) {
	t.Helper()
	m, fp := akMaterial(t)
	f := &fakeRO{fp: fp}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	ssh := sshxtest.Start(t, nil)
	ssh.Pass = roPass
	return f, srv, ssh, m
}

func TestRouterOSHappyPath(t *testing.T) {
	f, srv, ssh, m := roSetup(t)
	f.certs = []map[string]any{{".id": "*A", "name": "certforge-deadbeef", "fingerprint": "00", "private-key": "true"}, {".id": "*B", "name": "unrelated", "fingerprint": "11"}}
	res, err := RouterOS{}.Deploy(context.Background(), roReq(t, srv.URL, ssh, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	fp8 := f.fp[:8]
	if res.Detail != "certificate certforge-"+fp8+" imported; bound: www-ssl, api-ssl; 1 old removed" {
		t.Fatalf("detail = %q", res.Detail)
	}
	want := "GET /certificate,POST /certificate/import,POST /certificate/import,GET /certificate,POST /file/remove,POST /file/remove,POST /certificate/set,GET /ip/service,POST /ip/service/set,POST /ip/service/set,POST /certificate/remove"
	if got := f.paths(); got != want {
		t.Fatalf("calls = %s", got)
	}
	ssh.Mu.Lock()
	crt, key := string(ssh.Files["cf-"+fp8+".crt"]), string(ssh.Files["cf-"+fp8+".key"])
	ssh.Mu.Unlock()
	if !strings.Contains(crt, "BEGIN CERTIFICATE") || !strings.Contains(key, "PRIVATE KEY") {
		t.Fatalf("uploads crt=%q key=%q", crt, key)
	}
	if f.calls[1].Body["file-name"] != "cf-"+fp8+".crt" || f.calls[2].Body["file-name"] != "cf-"+fp8+".key" {
		t.Fatalf("import order: %+v %+v", f.calls[1].Body, f.calls[2].Body)
	}
	if b := f.calls[6].Body; b[".id"] != "*N" || b["name"] != "certforge-"+fp8 {
		t.Fatalf("set body = %+v", b)
	}
	if f.calls[8].Body[".id"] != "*2" || f.calls[9].Body[".id"] != "*3" || f.calls[8].Body["certificate"] != "certforge-"+fp8 {
		t.Fatalf("service sets = %+v %+v", f.calls[8].Body, f.calls[9].Body)
	}
	if f.calls[10].Body[".id"] != "*A" {
		t.Fatalf("removed = %+v", f.calls[10].Body)
	}
}

func TestRouterOSUnchangedSkipsUpload(t *testing.T) {
	f, srv, ssh, m := roSetup(t)
	name := "certforge-" + f.fp[:8]
	f.certs = []map[string]any{{".id": "*A", "name": name, "fingerprint": f.fp, "private-key": "true"}}
	res, err := RouterOS{}.Deploy(context.Background(), roReq(t, srv.URL, ssh, m, func(c map[string]any) {
		c["services"] = []string{"sstp", "ovpn"}
		c["sshPort"] = 1 // proves no SSH dial happens
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "certificate "+name+" unchanged; bound: sstp, ovpn; 0 old removed" {
		t.Fatalf("detail = %q", res.Detail)
	}
	if got := f.paths(); got != "GET /certificate,POST /interface/sstp-server/server/set,POST /interface/ovpn-server/server/set" {
		t.Fatalf("calls = %s", got)
	}
}

func TestRouterOSKeyMissing(t *testing.T) {
	f, srv, ssh, m := roSetup(t)
	f.noKey = true
	_, err := RouterOS{}.Deploy(context.Background(), roReq(t, srv.URL, ssh, m, nil))
	if err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(f.paths(), "/ip/service") {
		t.Fatalf("bound despite error: %s", f.paths())
	}
}

func TestRouterOSAuthFailureRedacted(t *testing.T) {
	f, srv, ssh, m := roSetup(t)
	f.noAuth = true
	_, err := RouterOS{}.Deploy(context.Background(), roReq(t, srv.URL, ssh, m, nil))
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), roPass) {
		t.Fatalf("err = %v", err)
	}
}

func TestRouterOSBadHostKeyBeforeWrites(t *testing.T) {
	f, srv, ssh, m := roSetup(t)
	other := sshxtest.Start(t, nil)
	_, err := RouterOS{}.Deploy(context.Background(), roReq(t, srv.URL, ssh, m, func(c map[string]any) { c["hostKey"] = other.HostLine() }))
	if err == nil {
		t.Fatal("want host key error")
	}
	if got := f.paths(); got != "GET /certificate" {
		t.Fatalf("calls = %s", got)
	}
	_, err = RouterOS{}.Deploy(context.Background(), roReq(t, srv.URL, ssh, m, func(c map[string]any) { c["hostKey"] = "garbage" }))
	if err == nil || len(f.calls) != 1 {
		t.Fatalf("garbage key: err=%v calls=%s", err, f.paths())
	}
}

func TestRouterOSCleanupFailureIsWarning(t *testing.T) {
	f, srv, ssh, m := roSetup(t)
	f.removeF = true
	f.certs = []map[string]any{{".id": "*A", "name": "certforge-deadbeef", "fingerprint": "00"}}
	res, err := RouterOS{}.Deploy(context.Background(), roReq(t, srv.URL, ssh, m, nil))
	if err != nil || !strings.Contains(res.Detail, "0 old removed; warnings: remove certforge-deadbeef") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRouterOSParse(t *testing.T) {
	ssh := sshxtest.Start(t, nil)
	base := func() map[string]any {
		return map[string]any{"url": "https://r.example.net", "username": "admin", "password": "p", "hostKey": ssh.HostLine()}
	}
	cases := []struct {
		name string
		mod  func(map[string]any)
		ok   bool
	}{
		{"minimal", nil, true},
		{"http url", func(c map[string]any) { c["url"] = "http://r" }, false},
		{"no username", func(c map[string]any) { delete(c, "username") }, false},
		{"no password", func(c map[string]any) { delete(c, "password") }, false},
		{"no hostKey", func(c map[string]any) { delete(c, "hostKey") }, false},
		{"bad hostKey", func(c map[string]any) { c["hostKey"] = "nope" }, false},
		{"bad port", func(c map[string]any) { c["sshPort"] = 70000 }, false},
		{"bad certName", func(c map[string]any) { c["certName"] = "a b" }, false},
		{"bad service", func(c map[string]any) { c["services"] = []string{"ftp"} }, false},
		{"dup service", func(c map[string]any) { c["services"] = []string{"sstp", "sstp"} }, false},
		{"low timeout", func(c map[string]any) { c["timeoutSeconds"] = 5 }, false},
		{"unknown field", func(c map[string]any) { c["x"] = 1 }, false},
		{"all services", func(c map[string]any) { c["services"] = []string{"www-ssl", "api-ssl", "sstp", "ovpn"} }, true},
	}
	for _, tc := range cases {
		c := base()
		if tc.mod != nil {
			tc.mod(c)
		}
		raw, _ := json.Marshal(c)
		_, err := RouterOS{}.Parse(raw)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	raw, _ := json.Marshal(base())
	cfg, err := RouterOS{}.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.URLs) != 2 || cfg.URLs[1] != "ssh://"+net.JoinHostPort("r.example.net", strconv.Itoa(22)) || !cfg.NeedsKey {
		t.Fatalf("cfg = %+v", cfg)
	}
	if strings.Contains(string(cfg.Public), `"p"`) || cfg.Secrets == nil {
		t.Fatalf("password leaked into public: %s", cfg.Public)
	}
}
