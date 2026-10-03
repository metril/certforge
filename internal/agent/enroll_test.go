package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
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

	mu         sync.Mutex
	bundle     string // trust bundle returned by enrol and renew
	renewals   int
	reports    []agentproto.Report
	heartbeats int
	wsConns    int
	wsStatus   int                                          // non-zero: refuse the upgrade with this status
	onWS       func(ctx context.Context, c *websocket.Conn) // runs after the agent's hello
	assignGate chan struct{}                                // non-nil: GET assignments blocks until it is closed
	assignHits int                                          // GET assignments requests served or blocked
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
func sendAndWait(m agentproto.Message) func(context.Context, *websocket.Conn) {
	return func(ctx context.Context, c *websocket.Conn) {
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
	f := &fakeServer{ca: &agentca.CA{ID: uuid.New(), Cert: caCert, Key: caKey}, clientID: uuid.New(), bundle: string(agentca.CertPEM(caCert.Raw))}
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
	mux.HandleFunc("POST /agent/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req agentproto.EnrollRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if cert := sign(w, req.CSR); cert != nil {
			var bundle string
			f.with(func() { bundle = f.bundle })
			_ = json.NewEncoder(w).Encode(agentproto.EnrollResponse{Certificate: string(agentca.CertPEM(cert.Raw)),
				TrustBundle: bundle, AgentURL: f.srv.URL, ClientID: f.clientID})
		}
	})
	mux.HandleFunc("POST /agent/v1/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
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
		var onWS func(context.Context, *websocket.Conn)
		f.with(func() { f.wsConns++; status, onWS = f.wsStatus, f.onWS })
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
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
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
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
	f.srv = httptest.NewUnstartedServer(mux)
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
	return tok
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
	cl.tr.TLSClientConfig.GetClientCertificate = nil // present no certificate
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
