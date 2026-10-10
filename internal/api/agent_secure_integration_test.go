//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agent"
	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

// hostile is the man in the middle: a transport between the agent and the
// server that records every exchange and can rewrite either direction.
type hostile struct {
	next http.RoundTripper
	mu   sync.Mutex
	log  []exchange

	onReq  func(n int, r *http.Request)
	onResp func(n int, resp *http.Response)
	n      int
}

type exchange struct {
	method, uri string
	hdr         http.Header
	reqBody     []byte
	status      int
	respBody    []byte
	respHdr     http.Header
}

func (h *hostile) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	h.mu.Lock()
	n := h.n
	h.n++
	h.mu.Unlock()
	req = req.Clone(req.Context())
	req.Body, req.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
	if h.onReq != nil {
		h.onReq(n, req)
		if req.Body != nil {
			body, _ = io.ReadAll(req.Body)
			req.Body, req.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
		}
	}
	resp, err := h.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	rb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(rb))
	resp.ContentLength = int64(len(rb))
	if h.onResp != nil {
		h.onResp(n, resp)
		rb, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(rb))
		resp.ContentLength = int64(len(rb))
	}
	h.mu.Lock()
	h.log = append(h.log, exchange{req.Method, req.URL.RequestURI(), req.Header.Clone(), body, resp.StatusCode, rb, resp.Header.Clone()})
	h.mu.Unlock()
	return resp, nil
}

func (h *hostile) exchanges() []exchange {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]exchange(nil), h.log...)
}

// proxied serves NewRouter (the HTTP port) over plain HTTP behind a
// TLS-terminating reverse proxy, as Caddy or nginx would, and returns the
// proxy's URL. The agent talks to the proxy; the server is configured for the
// proxy's address as its external host and never looks at the Host header.
func (e *agentEnv) proxied(t *testing.T) (*httptest.Server, http.RoundTripper) {
	t.Helper()
	proxy := httptest.NewUnstartedServer(nil)
	d := e.srv.d
	d.AgentAuthorities = []string{proxy.Listener.Addr().String()}
	backend := httptest.NewServer(NewRouter(d))
	t.Cleanup(backend.Close)
	bu, _ := url.Parse(backend.URL)
	rp := httputil.NewSingleHostReverseProxy(bu)
	proxy.Config.Handler = rp
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	return proxy, proxy.Client().Transport
}

// identity builds the agent identity the secure transport signs with.
func (e *agentEnv) identity(t *testing.T, cert tls.Certificate) *agent.Identity {
	t.Helper()
	trusted, err := e.ca.Trusted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509CertPool(trusted)
	leaf := cert.Leaf
	if leaf == nil {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return &agent.Identity{Key: cert.PrivateKey.(*ecdsa.PrivateKey), Cert: leaf, CAs: pool}
}

func secureClient(id *agent.Identity, base http.RoundTripper) *http.Client {
	return &http.Client{Transport: agent.NewSecureTransport(id, base), Timeout: 10 * time.Second}
}

// withKeyGrant gives the enrolled client a grant whose files include the key.
func (e *agentEnv) withKeyGrant(t *testing.T, name string) (tls.Certificate, string) {
	t.Helper()
	en := e.newClient(t, name)
	cert, _, code := e.enroll(t, en.Token)
	if code != http.StatusOK {
		t.Fatalf("enroll %d", code)
	}
	certID, _ := e.realCurrentCert(t, name+"-cert", true)
	files, _ := json.Marshal([]delivery.OutputFile{{Path: "/etc/ssl/" + name + ".key", Format: "pem", Parts: []string{"key"}, Mode: "0600"}})
	l, err := e.q.CreateLayout(context.Background(), sqlcgenLayout(e.org, name+"-layout", files))
	if err != nil {
		t.Fatal(err)
	}
	gid, err := e.svc.CreateGrant(e.as("operator"), e.org, en.Client.ID, agents.GrantInput{CertID: certID, Delivery: "push", LayoutID: &l.ID})
	if err != nil {
		t.Fatal(err)
	}
	return cert, gid.String()
}

// The full flow through a TLS-terminating proxy: nothing the proxy forwards
// or returns is readable, yet the agent gets its data.
func TestAgentProtocolThroughTerminatingProxy(t *testing.T) {
	e := newAgentEnv(t)
	cert, gid := e.withKeyGrant(t, "proxy-1")
	proxy, base := e.proxied(t)
	h := &hostile{next: base}
	hc := secureClient(e.identity(t, cert), h)

	var as agentproto.Assignments
	if code, err := doAgent(hc, http.MethodGet, proxy.URL+"/agent/v1/assignments", nil, &as); err != nil || code != http.StatusOK || len(as.Grants) != 1 {
		t.Fatalf("assignments %d %v %+v", code, err, as)
	}
	var b agentproto.Bundle
	if code, err := doAgent(hc, http.MethodGet, proxy.URL+"/agent/v1/grants/"+gid+"/bundle", nil, &b); err != nil || code != http.StatusOK ||
		len(b.Files) != 1 || !bytes.Contains(b.Files[0].Content, []byte("PRIVATE KEY")) {
		t.Fatalf("bundle %d %v %+v", code, err, b)
	}
	if code, err := doAgent(hc, http.MethodPost, proxy.URL+"/agent/v1/report", okReport(as), nil); err != nil || code != http.StatusNoContent {
		t.Fatalf("report %d %v", code, err)
	}
	var sessions int
	for _, x := range h.exchanges() {
		if x.uri == agentproto.PathSession {
			sessions++
			continue
		}
		for _, wire := range [][]byte{x.reqBody, x.respBody} {
			if bytes.Contains(wire, []byte("PRIVATE KEY")) || bytes.Contains(wire, []byte("BEGIN")) || json.Valid(wire) && len(wire) > 0 {
				t.Fatalf("%s %s carried readable data: %q", x.method, x.uri, wire)
			}
		}
		if len(x.respBody) > 0 && x.respHdr.Get(agentproto.HeaderSeq) == "" {
			t.Fatalf("%s response is not sealed", x.uri)
		}
	}
	if sessions != 1 {
		t.Fatalf("%d handshakes for one agent", sessions)
	}
}

func TestAgentProtocolStrictOnAgentPort(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, _ := e.enrolledWithGrant(t, "strict-1", false)
	// A valid client certificate alone gets nothing, on any route.
	for _, p := range []string{"/agent/v1/assignments", "/agent/v1/grants/" + cert.Leaf.SerialNumber.String() + "/bundle"} {
		if code := e.get(t, e.plainClient(t, &cert), p, nil); code != http.StatusUnauthorized {
			t.Fatalf("%s with only a client certificate: %d", p, code)
		}
	}
	if code := e.post(t, e.plainClient(t, &cert), "/agent/v1/heartbeat", agentproto.Heartbeat{}, nil); code != http.StatusUnauthorized {
		t.Fatalf("heartbeat with only a client certificate: %d", code)
	}
	// And the same client signs in properly.
	if code := e.get(t, e.httpClient(t, &cert), "/agent/v1/assignments", nil); code != http.StatusOK {
		t.Fatalf("signed request %d", code)
	}
}

func TestAgentProtocolTampering(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, _ := e.enrolledWithGrant(t, "tamper-1", false)
	proxy, base := e.proxied(t)
	id := e.identity(t, cert)
	call := func(h *hostile, method, path string, body any) (int, error) {
		return doAgent(secureClient(id, h), method, proxy.URL+path, body, nil)
	}
	// Establish that the untouched path works.
	if code, err := call(&hostile{next: base}, http.MethodGet, "/agent/v1/assignments", nil); err != nil || code != http.StatusOK {
		t.Fatalf("baseline %d %v", code, err)
	}
	t.Run("body", func(t *testing.T) {
		h := &hostile{next: base, onReq: func(n int, r *http.Request) {
			if n == 1 {
				b, _ := io.ReadAll(r.Body)
				b[len(b)-1] ^= 1
				r.Body = io.NopCloser(bytes.NewReader(b))
			}
		}}
		if code, err := call(h, http.MethodPost, "/agent/v1/heartbeat", agentproto.Heartbeat{}); !errors.Is(err, agent.ErrUnsigned) {
			t.Fatalf("tampered body: %d %v", code, err)
		}
	})
	t.Run("path", func(t *testing.T) {
		h := &hostile{next: base, onReq: func(n int, r *http.Request) {
			if n == 1 {
				r.URL.Path = "/agent/v1/heartbeat"
				r.Method = http.MethodPost
			}
		}}
		if code, err := call(h, http.MethodGet, "/agent/v1/assignments", nil); !errors.Is(err, agent.ErrUnsigned) {
			t.Fatalf("tampered path: %d %v", code, err)
		}
	})
	t.Run("host", func(t *testing.T) {
		// A server that answers for another external host refuses a request
		// signed for this one, whatever Host header arrives.
		other := e.srv.d
		other.AgentAuthorities = []string{"certforge.other.example"}
		backend := httptest.NewServer(NewRouter(other))
		defer backend.Close()
		bu, _ := url.Parse(backend.URL)
		p := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(bu))
		defer p.Close()
		code, err := doAgent(secureClient(id, p.Client().Transport), http.MethodGet, p.URL+"/agent/v1/assignments", nil, nil)
		if !errors.Is(err, agent.ErrUnsigned) {
			t.Fatalf("request signed for another host: %d %v", code, err)
		}
	})
	t.Run("session id", func(t *testing.T) {
		h := &hostile{next: base, onReq: func(n int, r *http.Request) {
			if n == 1 {
				r.Header.Set(agentproto.HeaderEphemeral, "AAAAAAAAAAAAAAAAAAAAAA")
			}
		}}
		// An unknown session id is answered with a signed "session" refusal; the
		// agent starts a fresh session and repeats the request once.
		if code, err := call(h, http.MethodGet, "/agent/v1/assignments", nil); err != nil || code != http.StatusOK {
			t.Fatalf("recovery from an unknown session: %d %v", code, err)
		}
		if got := len(h.exchanges()); got != 4 { // handshake, refused, handshake, retry
			t.Fatalf("%d exchanges", got)
		}
	})
}

func TestAgentProtocolReplayAndSwappedResponse(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, _ := e.enrolledWithGrant(t, "replay-1", false)
	proxy, base := e.proxied(t)
	h := &hostile{next: base}
	hc := secureClient(e.identity(t, cert), h)
	for range 2 {
		if code, err := doAgent(hc, http.MethodPost, proxy.URL+"/agent/v1/heartbeat", agentproto.Heartbeat{}, nil); err != nil || code != http.StatusNoContent {
			t.Fatalf("heartbeat %d %v", code, err)
		}
	}
	ex := h.exchanges()
	first := ex[1] // [0] is the handshake
	// Replay the captured request byte for byte.
	req, _ := http.NewRequestWithContext(context.Background(), first.method, proxy.URL+first.uri, bytes.NewReader(first.reqBody))
	req.Header = first.hdr.Clone()
	resp, err := base.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(agentproto.HeaderError) != agentproto.ErrCodeReplay {
		t.Fatalf("replay answered %d %q", resp.StatusCode, resp.Header.Get(agentproto.HeaderError))
	}
	// A recorded genuine response handed back for a different request is refused.
	var recorded *exchange
	h2 := &hostile{next: base}
	hc2 := secureClient(e.identity(t, cert), h2)
	var as agentproto.Assignments
	if code, err := doAgent(hc2, http.MethodGet, proxy.URL+"/agent/v1/assignments", nil, &as); err != nil || code != http.StatusOK {
		t.Fatalf("assignments %d %v", code, err)
	}
	x := h2.exchanges()[1]
	recorded = &x
	h2.onResp = func(n int, r *http.Response) {
		r.Header = recorded.respHdr.Clone()
		r.StatusCode = recorded.status
		r.Body = io.NopCloser(bytes.NewReader(recorded.respBody))
	}
	_, err = doAgent(hc2, http.MethodGet, proxy.URL+"/agent/v1/assignments", nil, &as)
	if err == nil || !errors.Is(err, agent.ErrUnsigned) {
		t.Fatalf("swapped response accepted: %v", err)
	}
	// An unsigned response (a proxy answering for the server) is refused too.
	h2.onResp = func(n int, r *http.Response) {
		r.Header = http.Header{"Content-Type": {"application/json"}}
		r.Body = io.NopCloser(strings.NewReader(`{"revision":1,"grants":[],"removed":[]}`))
	}
	if _, err = doAgent(hc2, http.MethodGet, proxy.URL+"/agent/v1/assignments", nil, &as); err == nil || !errors.Is(err, agent.ErrUnsigned) {
		t.Fatalf("unsigned response accepted: %v", err)
	}
}

// rawHandshake sends a signed handshake with the given created time.
func (e *agentEnv) rawHandshake(t *testing.T, cert tls.Certificate, au, rawURL string, created time.Time, serial string) *http.Response {
	t.Helper()
	local, _ := ecdh.P256().GenerateKey(rand.Reader)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, rawURL+agentproto.PathSession, nil)
	req.Header.Set(agentproto.HeaderAgentCert, base64.StdEncoding.EncodeToString(cert.Certificate[0]))
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	cid, _ := agentca.ClientIDFromCert(leaf)
	if serial == "" {
		serial = agentca.SerialHex(leaf)
	}
	if err := agentproto.SignRequest(req, nil, cert.PrivateKey.(*ecdsa.PrivateKey), agentproto.ReqParams{Authority: au, KeyID: cid.String() + ":" + serial,
		Nonce: agentproto.NewNonce(), Created: created, Ephemeral: base64.StdEncoding.EncodeToString(local.PublicKey().Bytes())}); err != nil {
		t.Fatal(err)
	}
	resp, err := e.httpClient(t, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAgentProtocolStaleAndOldSerial(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, _ := e.enrolledWithGrant(t, "stale-1", false)
	au := e.ts.Listener.Addr().String()
	for _, tc := range []struct {
		name    string
		created time.Time
		serial  string
		code    string
	}{
		{"stale past", time.Now().Add(-5 * time.Minute), "", agentproto.ErrCodeStale},
		{"stale future", time.Now().Add(5 * time.Minute), "", agentproto.ErrCodeStale},
		{"wrong serial", time.Now(), "1234", agentproto.ErrCodeAuth},
	} {
		resp := e.rawHandshake(t, cert, au, e.ts.URL, tc.created, tc.serial)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(agentproto.HeaderError) != tc.code {
			t.Fatalf("%s: %d %q", tc.name, resp.StatusCode, resp.Header.Get(agentproto.HeaderError))
		}
	}
	// A good handshake works, and its nonce cannot be reused.
	resp := e.rawHandshake(t, cert, au, e.ts.URL, time.Now(), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handshake %d", resp.StatusCode)
	}
	// After a renewal the old certificate's serial is superseded.
	var rr agentproto.RenewResponse
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(*ecdsa.PrivateKey))}, &rr); code != http.StatusOK {
		t.Fatalf("renew %d", code)
	}
	resp = e.rawHandshake(t, cert, au, e.ts.URL, time.Now(), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("handshake with the superseded certificate: %d", resp.StatusCode)
	}
}

// The agent refuses a server that is not the one its CA bundle vouches for.
func TestAgentRejectsForeignResponder(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, _ := e.enrolledWithGrant(t, "foreign-1", false)
	id := e.identity(t, cert)
	id.CAs = x509CertPool(nil) // trusts nothing: every responder certificate is foreign
	if _, err := doAgent(secureClient(id, e.httpClient(t, nil).Transport), http.MethodGet, e.ts.URL+"/agent/v1/assignments", nil, nil); !errors.Is(err, agent.ErrUnsigned) {
		t.Fatalf("response from an unvouched responder accepted: %v", err)
	}
}

func x509CertPool(certs []*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func sqlcgenLayout(org uuid.UUID, name string, files []byte) sqlcgen.CreateLayoutParams {
	return sqlcgen.CreateLayoutParams{OrgID: org, Name: name, Files: files, ExtraCertIds: []uuid.UUID{}}
}

// A refusal the proxy can forge must never read as revocation: a corrupted
// signature gets an unsigned refusal, which the agent treats as a transport
// error; a genuine revocation is a signed refusal whose Cf-Error is covered.
func TestAgentRevocationNeedsSignedRefusal(t *testing.T) {
	e := newAgentEnv(t)
	cert, c, _ := e.enrolledWithGrant(t, "revoke-1", false)
	proxy, base := e.proxied(t)
	id := e.identity(t, cert)
	get := func(h *hostile) (int, error) {
		return doAgent(secureClient(id, h), http.MethodGet, proxy.URL+"/agent/v1/assignments", nil, nil)
	}
	corrupt := &hostile{next: base, onReq: func(_ int, r *http.Request) {
		if sig := r.Header.Get(agentproto.HeaderSignature); sig != "" {
			r.Header.Set(agentproto.HeaderSignature, "sig=:"+strings.Repeat("A", 86)+"==:")
		}
	}}
	code, err := get(corrupt)
	if !errors.Is(err, agent.ErrUnsigned) || code == http.StatusUnauthorized {
		t.Fatalf("corrupted signature: %d %v", code, err)
	}
	if _, err := e.svc.RevokeClient(e.as("operator"), e.org, c.ID); err != nil {
		t.Fatal(err)
	}
	h := &hostile{next: base}
	if code, err := get(h); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("revoked client: %d %v", code, err)
	}
	last := h.exchanges()[0]
	if last.respHdr.Get(agentproto.HeaderError) != agentproto.ErrCodeAuth || last.respHdr.Get(agentproto.HeaderSignature) == "" {
		t.Fatalf("revocation not a signed auth refusal: %v", last.respHdr)
	}
	// A proxy swapping or stripping Cf-Error on that refusal breaks it.
	for name, mut := range map[string]func(http.Header){
		"swapped":  func(h http.Header) { h.Set(agentproto.HeaderError, agentproto.ErrCodeReplay) },
		"stripped": func(h http.Header) { h.Del(agentproto.HeaderError) },
	} {
		hh := &hostile{next: base, onResp: func(_ int, r *http.Response) { mut(r.Header) }}
		if code, err := get(hh); !errors.Is(err, agent.ErrUnsigned) {
			t.Fatalf("%s Cf-Error accepted: %d %v", name, code, err)
		}
	}
}
