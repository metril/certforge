package deploy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
)

const pfPass = "pf-secret-pass-123"
const pfToken = "pf-token-xyz"

type pfCall struct {
	Method, Path, Auth string
	Body               map[string]any
}

type fakePF struct {
	mu       sync.Mutex
	calls    []pfCall
	list     string // JSON body for GET /system/certificates
	webRef   string // current sslcertref
	loginBad bool
	devices  string // JSON body for GET /mim/devices; default one device "d1"
	prefix   string // system path prefix; default /device/pfsense/d1/api
}

const pfOneDevice = `{"devices":[{"device_id":"d1","name":"fw1","alias":"edge","state":"active"}]}`

func (f *fakePF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c := pfCall{Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization")}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &c.Body)
	}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	prefix := f.prefix
	if prefix == "" {
		prefix = "/device/pfsense/d1/api"
	}
	prefix = "/api" + prefix
	if f.prefix == "none" {
		prefix = "/api"
	}
	switch {
	case r.URL.Path == "/api/login":
		var cr map[string]string
		_ = json.Unmarshal(b, &cr)
		u, _ := base64.StdEncoding.DecodeString(cr["username"])
		pw, _ := base64.StdEncoding.DecodeString(cr["password"])
		if string(u) != "admin" || string(pw) != pfPass {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"errcode":400,"errmsg":"[@login-L117] invalid input encoding"}`)
			return
		}
		if f.loginBad {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"message":"bad password `+pfPass+`"}`)
			return
		}
		_, _ = io.WriteString(w, `{"token":"`+pfToken+`","user":"admin"}`)
	case c.Auth != "Bearer "+pfToken:
		w.WriteHeader(401)
	case r.URL.Path == "/api/mim/devices" && r.Method == "GET":
		if f.devices == "" {
			_, _ = io.WriteString(w, pfOneDevice)
		} else {
			_, _ = io.WriteString(w, f.devices)
		}
	case r.URL.Path == prefix+"/system/certificates" && r.Method == "GET":
		_, _ = io.WriteString(w, f.list)
	case r.URL.Path == prefix+"/system/certificates" && r.Method == "PUT":
		_, _ = io.WriteString(w, `{"refid":"newref","descr":"web"}`)
	case strings.HasPrefix(r.URL.Path, prefix+"/system/certificates/") && r.Method == "POST":
		_, _ = io.WriteString(w, `{"refid":"ok"}`)
	case r.URL.Path == prefix+"/system/advanced/admin" && r.Method == "GET":
		_, _ = io.WriteString(w, `{"admin":{"webguiproto":"https","ssl_certref":"`+f.webRef+`"}}`)
	case r.URL.Path == prefix+"/system/advanced/admin" && r.Method == "POST":
		_, _ = io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
	}
}

func pfRequest(t *testing.T, url, ca string, web bool, m *render.Material) targets.Request {
	t.Helper()
	cfg, _ := json.Marshal(map[string]any{"url": url + "/api", "username": "admin", "password": pfPass, "caPem": ca, "setWebGuiCert": web, "timeoutSeconds": 5})
	return targets.Request{CertName: "web", Material: m, Config: cfg, HTTP: targets.HTTPFactory{AllowLoopback: true}}
}

func pfPaths(f *fakePF) []string {
	var p []string
	for _, c := range f.calls {
		p = append(p, c.Method+" "+strings.TrimPrefix(c.Path, "/api"))
	}
	return p
}

func TestPfSenseUpdateKeepsRefid(t *testing.T) {
	f := &fakePF{list: `{"certs":[{"refid":"r1","descr":"other"},{"refid":"abc","descr":"web","crt":"x"}]}`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	res, err := PfSense{}.Deploy(context.Background(), pfRequest(t, srv.URL, "", false, m))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "certificate abc updated" {
		t.Fatalf("detail = %q", res.Detail)
	}
	if got := strings.Join(pfPaths(f), ","); got != "POST /login,GET /mim/devices,GET /device/pfsense/d1/api/system/certificates,POST /device/pfsense/d1/api/system/certificates/abc" {
		t.Fatalf("calls = %s", got)
	}
	b := f.calls[3].Body
	me := b["method_existing_pem"].(map[string]any)
	if b["descr"] != "web" || b["name"] != "web" || !strings.Contains(me["cert"].(string), "BEGIN CERTIFICATE") || !strings.Contains(me["private_key"].(string), "PRIVATE KEY") {
		t.Fatalf("body = %+v", b)
	}
	if f.calls[1].Auth != "Bearer "+pfToken || f.calls[0].Body["password"] != base64.StdEncoding.EncodeToString([]byte(pfPass)) {
		t.Fatalf("auth wrong: %+v", f.calls[:2])
	}
}

func TestPfSenseCreate(t *testing.T) {
	f := &fakePF{list: `[{"refid":"r1","name":"other"}]`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	res, err := PfSense{}.Deploy(context.Background(), pfRequest(t, srv.URL, "", false, m))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "certificate newref created" || f.calls[3].Method != "PUT" {
		t.Fatalf("detail=%q calls=%v", res.Detail, pfPaths(f))
	}
}

func TestPfSenseUnchangedSkipsWrite(t *testing.T) {
	m, _ := akMaterial(t)
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.LeafDER}))
	f := &fakePF{list: `{"certs":[{"refid":"abc","descr":"web","crt":"` + base64.StdEncoding.EncodeToString([]byte(leaf)) + `"}]}`}
	srv := httptest.NewServer(f)
	defer srv.Close()
	res, err := PfSense{}.Deploy(context.Background(), pfRequest(t, srv.URL, "", false, m))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "certificate abc unchanged" || len(f.calls) != 3 {
		t.Fatalf("detail=%q calls=%v", res.Detail, pfPaths(f))
	}
}

func TestPfSenseWebGUI(t *testing.T) {
	f := &fakePF{list: `[{"refid":"abc","descr":"web"}]`, webRef: "old"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	res, err := PfSense{}.Deploy(context.Background(), pfRequest(t, srv.URL, "", true, m))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "certificate abc updated, webgui cert set" {
		t.Fatalf("detail = %q", res.Detail)
	}
	last := f.calls[len(f.calls)-1]
	if last.Method != "POST" || last.Body["admin"].(map[string]any)["ssl_certref"] != "abc" || last.Body["admin"].(map[string]any)["webguiproto"] != "https" {
		t.Fatalf("last = %+v", last)
	}
	// already set: no POST
	f2 := &fakePF{list: `[{"refid":"abc","descr":"web"}]`, webRef: "abc"}
	srv2 := httptest.NewServer(f2)
	defer srv2.Close()
	res, err = PfSense{}.Deploy(context.Background(), pfRequest(t, srv2.URL, "", true, m))
	if err != nil || res.Detail != "certificate abc updated" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestPfSenseLoginFailureHidesPassword(t *testing.T) {
	f := &fakePF{loginBad: true}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	_, err := PfSense{}.Deploy(context.Background(), pfRequest(t, srv.URL, "", false, m))
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), pfPass) {
		t.Fatalf("err = %v", err)
	}
}

func TestPfSenseCAPem(t *testing.T) {
	f := &fakePF{list: `[]`}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	if _, err := (PfSense{}).Deploy(context.Background(), pfRequest(t, srv.URL, "", false, m)); err == nil {
		t.Fatal("untrusted server accepted")
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if _, err := (PfSense{}).Deploy(context.Background(), pfRequest(t, srv.URL, ca, false, m)); err != nil {
		t.Fatal(err)
	}
}

func TestPfSenseParse(t *testing.T) {
	cfg, err := PfSense{}.Parse(json.RawMessage(`{"url":"https://fw.example.net/api/","username":"a","password":"p"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NeedsKey || cfg.Secrets["password"] != "p" || cfg.URLs[0] != "https://fw.example.net/api" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if strings.Contains(string(cfg.Public), `"password"`) || !strings.Contains(string(cfg.Public), `"timeoutSeconds":30`) {
		t.Fatalf("public = %s", cfg.Public)
	}
	for _, bad := range []string{
		`{"url":"http://fw","username":"a","password":"p"}`,
		`{"url":"https://fw","password":"p"}`,
		`{"url":"https://fw","username":"a"}`,
		`{"url":"https://fw","username":"a","password":"p","certName":"a/b"}`,
		`{"url":"https://fw","username":"a","password":"p","timeoutSeconds":1}`,
		`{"url":"https://fw","username":"a","password":"p","x":1}`,
	} {
		if _, err := (PfSense{}).Parse(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func pfDeployWith(t *testing.T, f *fakePF, device string) (string, error) {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	m, _ := akMaterial(t)
	req := pfRequest(t, srv.URL, "", false, m)
	if device != "" {
		var c map[string]any
		_ = json.Unmarshal(req.Config, &c)
		c["device"] = device
		req.Config, _ = json.Marshal(c)
	}
	res, err := PfSense{}.Deploy(context.Background(), req)
	return res.Detail, err
}

func TestPfSenseNamedDevice(t *testing.T) {
	devs := `{"devices":[{"device_id":"d1","name":"fw1","alias":"edge"},{"device_id":"d2","name":"fw2","alias":"Core"}]}`
	f := &fakePF{list: `{"certs":[]}`, devices: devs, prefix: "/device/pfsense/d2/api"}
	for _, want := range []string{"fw2", "CORE", "D2"} {
		if d, err := pfDeployWith(t, f, want); err != nil || d != "certificate newref created" {
			t.Fatalf("%s: %q %v", want, d, err)
		}
	}
	if _, err := pfDeployWith(t, f, "nope"); err == nil || !strings.Contains(err.Error(), "no Nexus device") {
		t.Fatalf("err = %v", err)
	}
}

func TestPfSenseSeveralDevicesNeedName(t *testing.T) {
	f := &fakePF{list: `{"certs":[]}`, devices: `{"devices":[{"device_id":"d1","name":"fw1"},{"device_id":"d2","name":"fw2"}]}`}
	_, err := pfDeployWith(t, f, "")
	if err == nil || !strings.Contains(err.Error(), "fw1, fw2") {
		t.Fatalf("err = %v", err)
	}
}

func TestPfSenseNoDevicesCallsBase(t *testing.T) {
	f := &fakePF{list: `{"certs":[]}`, devices: `{"devices":[]}`, prefix: "none"}
	if d, err := pfDeployWith(t, f, ""); err != nil || d != "certificate newref created" {
		t.Fatalf("%q %v", d, err)
	}
	if got := strings.Join(pfPaths(f), ","); got != "POST /login,GET /mim/devices,GET /system/certificates,PUT /system/certificates" {
		t.Fatalf("calls = %s", got)
	}
}
