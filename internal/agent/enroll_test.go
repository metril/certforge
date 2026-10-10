package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
)

type staticSource struct{ ca *agentca.CA }

func (s staticSource) Oldest(context.Context) (*agentca.CA, error) { return s.ca, nil }
func (s staticSource) Trusted(context.Context) ([]*x509.Certificate, error) {
	return []*x509.Certificate{s.ca.Cert}, nil
}

// fakeServer is a minimal agent listener: real TLS from the agent CA,
// enrol, renew, assignments, report, heartbeat and the WebSocket. The
// fields below mu are shared with the handlers: use with.
type fakeServer struct {
	srv      *httptest.Server
	ca       *agentca.CA
	clientID uuid.UUID
	proto    *fakeProtocol

	mu         sync.Mutex
	bundle     string // trust bundle returned by enrol and renew
	agentURL   string // non-empty: AgentURL returned by enrol instead of the listener's
	renewals   int
	reports    []agentproto.Report
	heartbeats int
	wsConns    int
	wsUnsigned bool                                 // wsStatus 401 is answered without a signature
	wsStatus   int                                  // non-zero: refuse the upgrade with this status
	onWS       func(ctx context.Context, c *fakeWS) // runs after the agent's hello
	assignGate chan struct{}                        // non-nil: GET assignments blocks until it is closed
	assignHits int                                  // GET assignments requests served or blocked
	deny       bool                                 // GET assignments answers 401 "no client certificate"

	tokens      map[string][]byte // lookup id -> token hash, for tokens f.token issued
	hellos      map[string]*ecdh.PrivateKey
	reqs        map[string]*fakeEnrolReq
	pendingFor  int    // polls answered "pending" before approval
	outcome     string // non-empty: the status every poll reports (rejected, expired)
	wrongCode   bool   // answer enrolment with a verification code the agent will not recognise
	unsignedHel bool   // answer hello without a signature
}

type fakeEnrolReq struct {
	pub    *ecdsa.PublicKey
	csr    string
	secret string
	polls  int
}

// with runs fn under the server's lock.
func (f *fakeServer) with(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// sendAndWait writes m and keeps the socket open until the agent closes it.
//
//nolint:unused // used by a later task's WebSocket tests in this package
func sendAndWait(m agentproto.Message) func(context.Context, *fakeWS) {
	return func(ctx context.Context, c *fakeWS) {
		b, _ := agentproto.Marshal(m)
		_ = c.Write(ctx, websocket.MessageText, b)
		for {
			if _, _, err := c.Read(ctx); err != nil {
				return
			}
		}
	}
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	caCert, caKey, err := agentca.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{ca: &agentca.CA{ID: uuid.New(), Cert: caCert, Key: caKey}, clientID: uuid.New(), bundle: string(agentca.CertPEM(caCert.Raw)),
		tokens: map[string][]byte{}, hellos: map[string]*ecdh.PrivateKey{}, reqs: map[string]*fakeEnrolReq{}}
	l := &agentca.Listener{Source: staticSource{f.ca}, Names: func(context.Context) ([]string, error) { return []string{"127.0.0.1"}, nil }}
	if err := l.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	sign := func(w http.ResponseWriter, csrPEM string) *x509.Certificate {
		csr, err := agentca.ParseCSR([]byte(csrPEM))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return nil
		}
		cert, _ := agentca.SignClient(f.ca, csr, f.clientID, 90*24*time.Hour, time.Now())
		return cert
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/renew", func(w http.ResponseWriter, r *http.Request) {
		var req agentproto.RenewRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if cert := sign(w, req.CSR); cert != nil {
			var bundle string
			f.with(func() { f.renewals++; bundle = f.bundle })
			_ = json.NewEncoder(w).Encode(agentproto.RenewResponse{Certificate: string(agentca.CertPEM(cert.Raw)), TrustBundle: bundle})
		}
	})
	mux.HandleFunc("POST /agent/v1/report", func(w http.ResponseWriter, r *http.Request) {
		var rep agentproto.Report
		_ = json.NewDecoder(r.Body).Decode(&rep)
		f.with(func() { f.reports = append(f.reports, rep) })
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /agent/v1/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		f.with(func() { f.heartbeats++ })
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /agent/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		var status int
		var onWS func(context.Context, *fakeWS)
		var unsigned bool
		f.with(func() { f.wsConns++; status, onWS, unsigned = f.wsStatus, f.onWS, f.wsUnsigned })
		if status == http.StatusUnauthorized && !unsigned { // a signed refusal: revoked
			f.proto.wsRefuse(w, r, status)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		c := f.proto.wsUpgrade(w, r)
		if c == nil {
			return
		}
		defer c.CloseNow()                                //nolint:errcheck // best-effort test cleanup
		if _, _, err := c.Read(r.Context()); err != nil { // hello
			return
		}
		if onWS != nil {
			onWS(r.Context(), c)
		}
	})
	mux.HandleFunc("GET /agent/v1/assignments", func(w http.ResponseWriter, r *http.Request) {
		var deny bool
		f.with(func() { deny = f.deny })
		if deny {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"title":"Unauthorized","detail":"no client certificate"}`))
			return
		}
		var gate chan struct{}
		f.with(func() { f.assignHits++; gate = f.assignGate })
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		_ = json.NewEncoder(w).Encode(agentproto.Assignments{Revision: 7})
	})
	f.proto = &fakeProtocol{l: l, sessions: map[string]*fakeSession{}, enrol: f.serveEnrol}
	f.srv = httptest.NewUnstartedServer(nil)
	f.proto.au = f.srv.Listener.Addr().String()
	f.srv.Config.Handler = f.proto.handler(mux)
	f.srv.TLS = l.TLSConfig()
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) token(t *testing.T) string {
	t.Helper()
	tok, err := agentproto.NewToken(f.srv.URL, agentca.Fingerprint(f.ca.Cert.Raw))
	if err != nil {
		t.Fatal(err)
	}
	f.with(func() {
		f.tokens[string(agentproto.LookupIDBytes(agentproto.TokenHash(tok)))] = agentproto.TokenHash(tok)
	})
	return tok
}

func (f *fakeServer) respond(w http.ResponseWriter, status int, nonce string, body []byte) {
	sg, _ := f.proto.l.Responder()
	_ = agentproto.SignResponse(w.Header(), status, body, sg.Key, agentproto.RespParams{KeyID: "responder", ReqNonce: nonce, Created: time.Now()})
	w.Header().Set(agentproto.HeaderSignerCert, base64.StdEncoding.EncodeToString(sg.Chain[0].Raw))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (f *fakeServer) sealed(w http.ResponseWriter, status int, path, nonce string, to string, v any) {
	raw, _ := base64.StdEncoding.DecodeString(to)
	pub, _ := ecdh.P256().NewPublicKey(raw)
	pt, _ := json.Marshal(v)
	ct, _ := agentproto.HPKESeal(pub, agentproto.SealInfo(agentproto.DirS2C, path, nonce), pt)
	f.respond(w, status, nonce, ct)
}

// serveEnrol is the server half of the enrolment exchange.
func (f *fakeServer) serveEnrol(w http.ResponseWriter, r *http.Request) {
	au := f.proto.au
	switch {
	case r.Method == http.MethodGet && r.URL.Path == agentproto.PathEnrollHello:
		priv, _ := ecdh.P256().GenerateKey(rand.Reader)
		idRaw := make([]byte, 16)
		_, _ = rand.Read(idRaw)
		id := base64.RawURLEncoding.EncodeToString(idRaw)
		f.with(func() { f.hellos[id] = priv })
		sg, _ := f.proto.l.Responder()
		out, _ := json.Marshal(agentproto.EnrollHello{ID: id, Ephemeral: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
			Chain: []string{base64.StdEncoding.EncodeToString(sg.Chain[1].Raw)}, ExpiresIn: 120})
		var unsigned bool
		f.with(func() { unsigned = f.unsignedHel })
		if unsigned {
			_, _ = w.Write(out)
			return
		}
		f.respond(w, http.StatusOK, r.URL.Query().Get("nonce"), out)
	case r.Method == http.MethodPost && r.URL.Path == agentproto.PathEnroll:
		helloID := r.Header.Get(agentproto.HeaderEnrollHello)
		var priv *ecdh.PrivateKey
		f.with(func() { priv = f.hellos[helloID]; delete(f.hellos, helloID) })
		body, _ := io.ReadAll(r.Body)
		pt, err := agentproto.HPKEOpen(priv, agentproto.SealInfo(agentproto.DirC2S, agentproto.PathEnroll, helloID), body)
		if priv == nil || err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var sub agentproto.EnrollSubmit
		_ = json.Unmarshal(pt, &sub)
		lookup, _ := base64.RawURLEncoding.DecodeString(sub.LookupID)
		var th []byte
		f.with(func() { th = f.tokens[string(lookup)] })
		der, _ := agentproto.CSRDER(sub.CSR)
		if th == nil || !agentproto.VerifyPop(sub.Pop, th, der, au, sub.Created, sub.Nonce, sub.Reply) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		csr, err := agentca.ParseCSR([]byte(sub.CSR))
		if err != nil {
			f.sealed(w, http.StatusUnprocessableEntity, agentproto.PathEnroll, helloID, sub.Reply, map[string]any{"title": "Invalid", "detail": err.Error()})
			return
		}
		secretRaw := make([]byte, 16)
		_, _ = rand.Read(secretRaw)
		id := uuid.New()
		rq := &fakeEnrolReq{pub: csr.PublicKey.(*ecdsa.PublicKey), csr: sub.CSR, secret: base64.RawURLEncoding.EncodeToString(secretRaw)}
		var wrong bool
		status := agentproto.EnrollApproved
		f.with(func() {
			f.reqs[id.String()] = rq
			wrong = f.wrongCode
			if f.pendingFor > 0 || f.outcome != "" {
				status = agentproto.EnrollPending
			}
		})
		code := agentproto.VerifyCode(csr.RawSubjectPublicKeyInfo, agentca.Fingerprint(f.ca.Cert.Raw))
		if wrong {
			code = "AAAAAAAA"
		}
		f.sealed(w, http.StatusOK, agentproto.PathEnroll, helloID, sub.Reply, agentproto.EnrollAccepted{ID: id, PollSecret: rq.secret,
			VerifyCode: code, Status: status, ExpiresAt: time.Now().Add(time.Hour)})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, agentproto.PathEnroll+"/"):
		var rq *fakeEnrolReq
		f.with(func() { rq = f.reqs[strings.TrimPrefix(r.URL.Path, agentproto.PathEnroll+"/")] })
		body, _ := io.ReadAll(r.Body)
		if rq == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rp, err := agentproto.VerifyRequest(r, body, au, time.Now(), func(string) (*ecdsa.PublicKey, error) { return rq.pub, nil })
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var pr agentproto.EnrollPollRequest
		_ = json.Unmarshal(body, &pr)
		if pr.PollSecret != rq.secret {
			f.sealed(w, http.StatusUnauthorized, r.URL.Path, rp.Nonce, rp.Ephemeral, map[string]any{"title": "Unauthorized", "detail": "The poll secret is wrong."})
			return
		}
		var outcome, bundle, agentURL string
		var pending int
		f.with(func() {
			rq.polls++
			outcome, pending, bundle, agentURL = f.outcome, f.pendingFor, f.bundle, f.agentURL
			if agentURL == "" {
				agentURL = f.srv.URL
			}
		})
		out := agentproto.EnrollPoll{Status: agentproto.EnrollPending, ExpiresAt: time.Now().Add(time.Hour)}
		switch {
		case outcome != "":
			out.Status = outcome
		case rq.polls > pending:
			csr, _ := agentca.ParseCSR([]byte(rq.csr))
			cert, _ := agentca.SignClient(f.ca, csr, f.clientID, 90*24*time.Hour, time.Now())
			out = agentproto.EnrollPoll{Status: agentproto.EnrollApproved, Certificate: string(agentca.CertPEM(cert.Raw)),
				TrustBundle: bundle, AgentURL: agentURL, ClientID: f.clientID}
		}
		f.sealed(w, http.StatusOK, r.URL.Path, rp.Nonce, rp.Ephemeral, out)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

var facts = agentproto.Facts{Hostname: "h", OS: "linux", Arch: "amd64", AgentVersion: "test"}

func mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestEnrollPinsCAFingerprint(t *testing.T) {
	f := newFakeServer(t)
	dir := filepath.Join(t.TempDir(), "data")
	tok := f.token(t)
	id, err := Enroll(context.Background(), dir, tok, facts)
	if err != nil {
		t.Fatal(err)
	}
	if id.State.ClientID != f.clientID || id.State.AgentURL != f.srv.URL || id.State.TokenHash != TokenHashHex(tok) {
		t.Fatalf("state %+v", id.State)
	}
	if mode(t, filepath.Join(dir, "agent.key")) != 0o600 || mode(t, filepath.Join(dir, "state.json")) != 0o600 || mode(t, dir) != 0o700 {
		t.Fatal("file modes")
	}
	as, err := NewClient(id).Assignments(context.Background())
	if err != nil || as.Revision != 7 {
		t.Fatalf("mTLS assignments %+v %v", as, err)
	}
	other, _, _ := agentca.NewCA(time.Now())
	bad, _ := agentproto.NewToken(f.srv.URL, agentca.Fingerprint(other.Raw))
	if _, err := Enroll(context.Background(), t.TempDir(), bad, facts); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("wrong fingerprint: %v", err)
	}
}

func quickPolls(t *testing.T) {
	t.Helper()
	oldMin, oldMax := EnrollPollMin, EnrollPollMax
	EnrollPollMin, EnrollPollMax = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { EnrollPollMin, EnrollPollMax = oldMin, oldMax })
}

type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func TestEnrollWaitsForApprovalAndLogsCode(t *testing.T) {
	quickPolls(t)
	f := newFakeServer(t)
	f.with(func() { f.pendingFor = 3 })
	sink := &logSink{}
	dir := t.TempDir()
	id, err := EnrollWith(context.Background(), EnrollOptions{Log: slog.New(slog.NewTextHandler(sink, nil))}, dir, f.token(t), facts)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := loadOrCreateKey(dir)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	code := agentproto.FormatVerifyCode(agentproto.VerifyCode(der, agentca.Fingerprint(f.ca.Cert.Raw)))
	if !strings.Contains(sink.String(), "WAITING FOR APPROVAL") || !strings.Contains(sink.String(), code) {
		t.Fatalf("code %s not logged prominently: %s", code, sink.String())
	}
	var polls int
	for _, r := range f.reqs {
		polls = r.polls
	}
	if polls != 4 || id.State.ClientID != f.clientID {
		t.Fatalf("polls %d state %+v", polls, id.State)
	}
}

func TestEnrollRejectedExpiredAndStopped(t *testing.T) {
	quickPolls(t)
	for outcome, want := range map[string]string{agentproto.EnrollRejected: "rejected", agentproto.EnrollExpired: "expired"} {
		f := newFakeServer(t)
		f.with(func() { f.outcome = outcome })
		dir := t.TempDir()
		if _, err := Enroll(context.Background(), dir, f.token(t), facts); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v", outcome, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "agent.crt")); err == nil {
			t.Fatalf("%s: certificate written", outcome)
		}
	}
	f := newFakeServer(t)
	f.with(func() { f.pendingFor = 1 << 30 })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := Enroll(ctx, t.TempDir(), f.token(t), facts); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled wait: %v", err)
	}
}

func TestEnrollRefusesUnverifiedServer(t *testing.T) {
	quickPolls(t)
	f := newFakeServer(t)
	f.with(func() { f.unsignedHel = true })
	if _, err := Enroll(context.Background(), t.TempDir(), f.token(t), facts); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned hello: %v", err)
	}
	f = newFakeServer(t)
	f.with(func() { f.wrongCode = true })
	if _, err := Enroll(context.Background(), t.TempDir(), f.token(t), facts); err == nil || !strings.Contains(err.Error(), "verification code") {
		t.Fatalf("wrong code: %v", err)
	}
	// A token the server never issued gets an unsigned refusal: an error, no state.
	f = newFakeServer(t)
	stranger, _ := agentproto.NewToken(f.srv.URL, agentca.Fingerprint(f.ca.Cert.Raw))
	dir := t.TempDir()
	if _, err := Enroll(context.Background(), dir, stranger, facts); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unknown token: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		t.Fatal("state written for a refused enrolment")
	}
}

func TestLoadIdentityNotEnrolled(t *testing.T) {
	if _, err := LoadIdentity(t.TempDir()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenewReplacesCertificate(t *testing.T) {
	f := newFakeServer(t)
	dir := t.TempDir()
	id, err := Enroll(context.Background(), dir, f.token(t), facts)
	if err != nil {
		t.Fatal(err)
	}
	before := id.Cert.SerialNumber
	if err := NewClient(id).Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	again, err := LoadIdentity(dir)
	if err != nil || again.Cert.SerialNumber.Cmp(before) == 0 || id.Cert.SerialNumber.Cmp(before) == 0 {
		t.Fatalf("not renewed: %v", err)
	}
}

func TestUnauthorizedIsReported(t *testing.T) {
	f := newFakeServer(t)
	id, err := Enroll(context.Background(), t.TempDir(), f.token(t), facts)
	if err != nil {
		t.Fatal(err)
	}
	cl := NewClient(id)
	f.with(func() { f.deny = true })
	if _, err := cl.Assignments(context.Background()); !IsUnauthorized(err) || !strings.Contains(err.Error(), "no client certificate") {
		t.Fatalf("err = %v", err)
	}
}

func TestStatusOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := Status(&buf, t.TempDir(), time.Now()); err != nil || !strings.Contains(buf.String(), "Not enrolled") {
		t.Fatalf("not enrolled: %s %v", buf.String(), err)
	}
	f := newFakeServer(t)
	dir := t.TempDir()
	if _, err := Enroll(context.Background(), dir, f.token(t), facts); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := Status(&buf, dir, time.Now()); err != nil || !strings.Contains(buf.String(), f.clientID.String()) || !strings.Contains(buf.String(), "Revision:") {
		t.Fatalf("status %s %v", buf.String(), err)
	}
}

func TestEnrollRejectsNonHTTPSAgentURL(t *testing.T) {
	f := newFakeServer(t)
	f.with(func() { f.agentURL = "http://evil.example" })
	dir := filepath.Join(t.TempDir(), "data")
	if _, err := Enroll(context.Background(), dir, f.token(t), facts); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		t.Fatal("state.json written for a rejected enrolment")
	}
}

func TestLoadIdentityRejectsNonHTTPSAgentURL(t *testing.T) {
	f := newFakeServer(t)
	dir := t.TempDir()
	id, err := Enroll(context.Background(), dir, f.token(t), facts)
	if err != nil {
		t.Fatal(err)
	}
	id.State.AgentURL = "http://evil.example"
	if err := id.SaveState(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(dir); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("err = %v", err)
	}
}
