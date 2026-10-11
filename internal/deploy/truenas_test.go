package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/targets"
)

const tnKey = "1-secretapikeyvalue"

type tnReq struct {
	ID     int               `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// fakeTrueNAS answers each request via handle(method, params) -> (result,
// rpcErr); handle returning closeConn=true drops the socket without a reply.
type fakeTrueNAS struct {
	mu     sync.Mutex
	calls  []string
	bodies map[string]string
	handle func(m string, p []json.RawMessage) (result string, errJSON string, closeConn bool)
}

func (f *fakeTrueNAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/current" {
		http.NotFound(w, r)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	for {
		_, b, err := c.Read(r.Context())
		if err != nil {
			return
		}
		var q tnReq
		_ = json.Unmarshal(b, &q)
		f.mu.Lock()
		f.calls = append(f.calls, q.Method)
		if f.bodies == nil {
			f.bodies = map[string]string{}
		}
		f.bodies[q.Method] = string(b)
		f.mu.Unlock()
		res, errJSON, drop := f.handle(q.Method, q.Params)
		if drop {
			return
		}
		// A notification the client must skip.
		_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"jsonrpc":"2.0","method":"collection_update","params":{}}`))
		out := map[string]any{"jsonrpc": "2.0", "id": q.ID}
		if errJSON != "" {
			out["error"] = json.RawMessage(errJSON)
		} else {
			out["result"] = json.RawMessage(res)
		}
		ob, _ := json.Marshal(out)
		_ = c.Write(r.Context(), websocket.MessageText, ob)
	}
}

func (f *fakeTrueNAS) called(m string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == m {
			return true
		}
	}
	return false
}

func tnRequest(t *testing.T, srv *httptest.Server, extra map[string]any) (targets.Request, string) {
	t.Helper()
	m, _ := akMaterial(t)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	cfgMap := map[string]any{"url": srv.URL, "apiKey": tnKey, "caPem": caPEM, "timeoutSeconds": 10}
	for k, v := range extra {
		cfgMap[k] = v
	}
	cfg, _ := json.Marshal(cfgMap)
	return targets.Request{CertName: "web", Material: m, Config: cfg, HTTP: targets.HTTPFactory{AllowLoopback: true}}, caPEM
}

func baseHandle(overrides map[string]func(p []json.RawMessage) (string, string, bool)) func(string, []json.RawMessage) (string, string, bool) {
	return func(m string, p []json.RawMessage) (string, string, bool) {
		if h, ok := overrides[m]; ok {
			return h(p)
		}
		switch m {
		case "auth.login_ex":
			return `{"response_type":"SUCCESS"}`, "", false
		case "certificate.query":
			return `[]`, "", false
		case "certificate.create":
			return `11`, "", false
		case "core.job_wait":
			return `{"id":42}`, "", false
		case "system.general.config":
			return `{"ui_certificate":{"id":1}}`, "", false
		case "system.general.update":
			return `{}`, "", false
		case "system.general.ui_restart":
			return `null`, "", false
		}
		return `null`, `{"code":-32601,"message":"Method not found"}`, false
	}
}

func TestTrueNASHappyPath(t *testing.T) {
	f := &fakeTrueNAS{}
	f.handle = baseHandle(map[string]func([]json.RawMessage) (string, string, bool){
		"certificate.query": func([]json.RawMessage) (string, string, bool) {
			return `[{"id":5,"name":"certforge-deadbeef"},{"id":6,"name":"other"}]`, "", false
		},
		"certificate.delete": func([]json.RawMessage) (string, string, bool) { return `12`, "", false },
	})
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	req, _ := tnRequest(t, srv, nil)
	res, err := TrueNAS{}.Deploy(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "certificate 42 imported, ui cert set, 1 old removed" {
		t.Fatalf("detail = %q", res.Detail)
	}
	for _, m := range []string{"certificate.create", "system.general.update", "system.general.ui_restart", "certificate.delete"} {
		if !f.called(m) {
			t.Fatalf("%s not called: %v", m, f.calls)
		}
	}
	if !strings.Contains(f.bodies["certificate.create"], "CERTIFICATE_CREATE_IMPORTED") || !strings.Contains(f.bodies["certificate.create"], "certforge-") {
		t.Fatalf("create body = %s", f.bodies["certificate.create"])
	}
}

func TestTrueNASUnchangedSkipsImport(t *testing.T) {
	f := &fakeTrueNAS{}
	var name string
	f.handle = baseHandle(map[string]func([]json.RawMessage) (string, string, bool){
		"certificate.query": func([]json.RawMessage) (string, string, bool) {
			return `[{"id":7,"name":"` + name + `"}]`, "", false
		},
		"system.general.config": func([]json.RawMessage) (string, string, bool) {
			return `{"ui_certificate":{"id":7}}`, "", false
		},
	})
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	req, _ := tnRequest(t, srv, nil)
	// Recompute the name from the request's own material.
	name = "certforge-" + leafFP8(req)
	res, err := TrueNAS{}.Deploy(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "certificate 7 unchanged" || f.called("certificate.create") || f.called("system.general.update") {
		t.Fatalf("detail=%q calls=%v", res.Detail, f.calls)
	}
}

func TestTrueNASLoginFailureHidesKey(t *testing.T) {
	f := &fakeTrueNAS{}
	f.handle = baseHandle(map[string]func([]json.RawMessage) (string, string, bool){
		"auth.login_ex": func([]json.RawMessage) (string, string, bool) {
			return ``, `{"code":-32001,"message":"bad key ` + tnKey + `"}`, false
		},
	})
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	req, _ := tnRequest(t, srv, nil)
	_, err := TrueNAS{}.Deploy(context.Background(), req)
	if err == nil || strings.Contains(err.Error(), tnKey) || !strings.Contains(err.Error(), "login failed") {
		t.Fatalf("err = %v", err)
	}
}

func TestTrueNASLoginFallback(t *testing.T) {
	f := &fakeTrueNAS{}
	f.handle = baseHandle(map[string]func([]json.RawMessage) (string, string, bool){
		"auth.login_ex": func([]json.RawMessage) (string, string, bool) {
			return ``, `{"code":-32601,"message":"Method not found"}`, false
		},
		"auth.login_with_api_key": func([]json.RawMessage) (string, string, bool) { return `true`, "", false },
	})
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	req, _ := tnRequest(t, srv, map[string]any{"setUiCert": false})
	res, err := TrueNAS{}.Deploy(context.Background(), req)
	if err != nil || res.Detail != "certificate 42 imported" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestTrueNASJobFailedViaPolling(t *testing.T) {
	f := &fakeTrueNAS{}
	f.handle = baseHandle(map[string]func([]json.RawMessage) (string, string, bool){
		"core.job_wait": func([]json.RawMessage) (string, string, bool) {
			return ``, `{"code":-32601,"message":"Method not found"}`, false
		},
		"core.get_jobs": func([]json.RawMessage) (string, string, bool) {
			return `[{"state":"FAILED","error":"bad key pair ` + tnKey + `"}]`, "", false
		},
	})
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	req, _ := tnRequest(t, srv, nil)
	_, err := TrueNAS{}.Deploy(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "failed") || !strings.Contains(err.Error(), "bad key pair") || strings.Contains(err.Error(), tnKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestTrueNASUIRestartClosingSocketIsSuccess(t *testing.T) {
	f := &fakeTrueNAS{}
	f.handle = baseHandle(map[string]func([]json.RawMessage) (string, string, bool){
		"system.general.ui_restart": func([]json.RawMessage) (string, string, bool) { return ``, "", true },
	})
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	req, _ := tnRequest(t, srv, nil)
	res, err := TrueNAS{}.Deploy(context.Background(), req)
	if err != nil || res.Detail != "certificate 42 imported, ui cert set" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestTrueNASDeleteInUseIgnored(t *testing.T) {
	f := &fakeTrueNAS{}
	f.handle = baseHandle(map[string]func([]json.RawMessage) (string, string, bool){
		"certificate.query": func([]json.RawMessage) (string, string, bool) {
			return `[{"id":5,"name":"certforge-aaaaaaaa"},{"id":6,"name":"certforge-bbbbbbbb"}]`, "", false
		},
		"certificate.delete": func(p []json.RawMessage) (string, string, bool) {
			if string(p[0]) == "5" {
				return ``, `{"code":-32000,"message":"Certificate is in use by the UI"}`, false
			}
			return ``, `{"code":-32000,"message":"boom"}`, false
		},
	})
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	req, _ := tnRequest(t, srv, map[string]any{"setUiCert": false})
	res, err := TrueNAS{}.Deploy(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Detail, "certificate 42 imported (warning: could not remove certforge-bbbbbbbb") || strings.Contains(res.Detail, "aaaaaaaa") {
		t.Fatalf("detail = %q", res.Detail)
	}
}

func TestTrueNASParse(t *testing.T) {
	c, err := TrueNAS{}.Parse(json.RawMessage(`{"url":"https://nas.lan/","apiKey":"k"}`))
	if err != nil || !c.NeedsKey || len(c.URLs) != 1 || c.URLs[0] != "https://nas.lan" {
		t.Fatalf("c=%+v err=%v", c, err)
	}
	if strings.Contains(string(c.Public), `"k"`) {
		t.Fatalf("secret in public: %s", c.Public)
	}
	for _, bad := range []string{
		`{"url":"http://nas","apiKey":"k"}`,
		`{"url":"https://nas"}`,
		`{"url":"https://nas","apiKey":"k","certPrefix":"a b"}`,
		`{"url":"https://nas","apiKey":"k","timeoutSeconds":5}`,
		`{"url":"https://nas","apiKey":"k","x":1}`,
	} {
		if _, err := (TrueNAS{}).Parse(json.RawMessage(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func leafFP8(req targets.Request) string {
	sum := sha256.Sum256(req.Material.LeafDER)
	return hex.EncodeToString(sum[:])[:8]
}
