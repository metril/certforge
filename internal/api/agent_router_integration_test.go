//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// agentEnv serves NewAgentRouter over real TLS. ts is the agent listener;
// the embedded fixture's srv is the main API *Server.
type agentEnv struct {
	*agentFixture
	ts       *httptest.Server
	listener *agentca.Listener
}

func newAgentEnv(t *testing.T, opts ...func(*Deps)) *agentEnv {
	t.Helper()
	f := newAgentFixture(t)
	ctx := context.Background()
	if _, err := f.ca.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	l := &agentca.Listener{Source: f.ca, Names: func(context.Context) ([]string, error) { return []string{"127.0.0.1", "localhost"}, nil }}
	if err := l.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	f.svc.Listener = l
	f.srv.d.AgentListener = l
	d := f.srv.d
	d.EnrollLimiter = authn.NewLimiter(0, 0)
	for _, o := range opts {
		o(&d)
	}
	srv := httptest.NewUnstartedServer(NewAgentRouter(d))
	srv.TLS = l.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &agentEnv{agentFixture: f, ts: srv, listener: l}
}

// httpClient trusts the current agent CA bundle and presents cert if set.
func (e *agentEnv) httpClient(t *testing.T, cert *tls.Certificate) *http.Client {
	t.Helper()
	trusted, err := e.ca.Trusted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	for _, c := range trusted {
		pool.AddCert(c)
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func doAgent(hc *http.Client, method, url string, body, out any) (int, error) {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, rdr)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (e *agentEnv) post(t *testing.T, hc *http.Client, path string, body, out any) int {
	t.Helper()
	code, err := doAgent(hc, http.MethodPost, e.ts.URL+path, body, out)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func (e *agentEnv) get(t *testing.T, hc *http.Client, path string, out any) int {
	t.Helper()
	code, err := doAgent(hc, http.MethodGet, e.ts.URL+path, nil, out)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func csrPEM(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func (e *agentEnv) enrollRaw(hc *http.Client, token, csr string) (int, agentproto.EnrollResponse, error) {
	var resp agentproto.EnrollResponse
	code, err := doAgent(hc, http.MethodPost, e.ts.URL+"/agent/v1/enroll", agentproto.EnrollRequest{Token: token, CSR: csr,
		Facts: agentproto.Facts{Hostname: "host-1", OS: "linux", Arch: "amd64", AgentVersion: "test"}}, &resp)
	return code, resp, err
}

// enroll enrols with token and returns the agent's TLS identity.
func (e *agentEnv) enroll(t *testing.T, token string) (tls.Certificate, agentproto.EnrollResponse, int) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	code, resp, err := e.enrollRaw(e.httpClient(t, nil), token, csrPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK {
		return tls.Certificate{}, resp, code
	}
	blk, _ := pem.Decode([]byte(resp.Certificate))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: key, Leaf: leaf}, resp, code
}

func TestEnrollAndRenew(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	en := e.newClient(t, "web-1")
	cert, resp, code := e.enroll(t, en.Token)
	if code != http.StatusOK || resp.ClientID != en.Client.ID || resp.AgentURL != "https://cf.example.test:8443" ||
		!strings.Contains(resp.TrustBundle, "BEGIN CERTIFICATE") {
		t.Fatalf("enroll %d %+v", code, resp)
	}
	c, _ := e.q.GetClientByID(ctx, en.Client.ID)
	if c.Status != "active" || c.Hostname != "host-1" || c.AgentVersion != "test" || c.AgentCertSerial != agentca.SerialHex(cert.Leaf) {
		t.Fatalf("client %+v", c)
	}
	rows, err := e.q.ListAuditEvents(ctx, sqlcgen.ListAuditEventsParams{Action: "client.enrolled", AnyOrg: true, PageLimit: 10})
	if err != nil || len(rows) != 1 || rows[0].ActorType != "agent" || rows[0].ActorID != en.Client.ID.String() || rows[0].ActorName != "web-1" {
		t.Fatalf("audit %+v %v", rows, err)
	}
	var rr agentproto.RenewResponse
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, &rr); code != http.StatusOK {
		t.Fatalf("renew %d", code)
	}
	blk, _ := pem.Decode([]byte(rr.Certificate))
	renewed, _ := x509.ParseCertificate(blk.Bytes)
	if agentca.SerialHex(renewed) == agentca.SerialHex(cert.Leaf) || e.auditCount(t, "client.cert_renewed") != 1 {
		t.Fatal("renew did not re-issue or audit")
	}
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, nil); code != http.StatusUnauthorized {
		t.Fatalf("old certificate after renew: %d", code)
	}
}

// Review Focus: a replayed or raced enrolment token.
func TestEnrollTokenSingleUse(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	en := e.newClient(t, "web-1")
	hc := e.httpClient(t, nil)
	codes := make(chan int, 2)
	for range 2 {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr := csrPEM(t, key)
		go func() {
			code, _, _ := e.enrollRaw(hc, en.Token, csr)
			codes <- code
		}()
	}
	got := []int{<-codes, <-codes}
	slices.Sort(got)
	if !slices.Equal(got, []int{http.StatusOK, http.StatusUnauthorized}) {
		t.Fatalf("concurrent enrolments %v", got)
	}
	en2 := e.newClient(t, "web-2")
	if _, err := e.pool.Exec(ctx, `UPDATE enrollment_tokens SET expires_at = now() - interval '1 minute' WHERE client_id = $1`, en2.Client.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, code := e.enroll(t, en2.Token); code != http.StatusUnauthorized {
		t.Fatalf("expired token %d", code)
	}
	if _, _, code := e.enroll(t, "cf1.nope"); code != http.StatusUnauthorized {
		t.Fatalf("garbage token %d", code)
	}
	en3 := e.newClient(t, "web-3")
	next, _, err := e.ca.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.listener.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	// The listener keeps the oldest CA until it is retired, so a token from
	// before the rotation still enrols, with a certificate from the new CA.
	cert3, _, code := e.enroll(t, en3.Token)
	if code != http.StatusOK {
		t.Fatalf("token from before a rotation %d", code)
	}
	if leaf, _ := x509.ParseCertificate(cert3.Certificate[0]); leaf == nil || leaf.CheckSignatureFrom(next.Cert) != nil {
		t.Fatal("enrolled certificate not signed by the new active CA")
	}
	en4 := e.newClient(t, "web-4")
	parts := strings.Split(en4.Token, ".")
	parts[2] = strings.Repeat("0", 64)
	if _, _, code := e.enroll(t, strings.Join(parts, ".")); code != http.StatusConflict {
		t.Fatalf("token pinned to another CA %d", code)
	}
	var used *time.Time
	if err := e.pool.QueryRow(ctx, `SELECT used_at FROM enrollment_tokens WHERE client_id = $1`, en4.Client.ID).Scan(&used); err != nil || used != nil {
		t.Fatalf("refused token consumed: %v %v", used, err)
	}
}

func TestAgentRoutesNeedClientCert(t *testing.T) {
	e := newAgentEnv(t)
	if code := e.post(t, e.httpClient(t, nil), "/agent/v1/renew", agentproto.RenewRequest{CSR: "x"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("no cert %d", code)
	}
	fc, fk, _ := agentca.NewCA(time.Now())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := agentca.ParseCSR([]byte(csrPEM(t, key)))
	leaf, _ := agentca.SignClient(&agentca.CA{Cert: fc, Key: fk}, csr, uuid.New(), time.Hour, time.Now())
	if _, err := doAgent(e.httpClient(t, &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}),
		http.MethodPost, e.ts.URL+"/agent/v1/renew", agentproto.RenewRequest{CSR: "x"}, nil); err == nil {
		t.Fatal("foreign client certificate accepted")
	}
}

// Review Focus: a stale or revoked agent certificate.
func TestAgentAuthRejectsStaleSerial(t *testing.T) {
	e := newAgentEnv(t)
	op := e.as("operator")
	en := e.newClient(t, "web-1")
	cert, _, _ := e.enroll(t, en.Token)
	if _, err := e.svc.RevokeClient(op, e.org, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked %d", code)
	}
	en2 := e.newClient(t, "web-2")
	cert2, _, _ := e.enroll(t, en2.Token)
	if _, err := e.svc.ReenrollClient(op, e.org, en2.Client.ID); err != nil {
		t.Fatal(err)
	}
	if code := e.post(t, e.httpClient(t, &cert2), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, cert2.PrivateKey.(crypto.Signer))}, nil); code != http.StatusUnauthorized {
		t.Fatalf("re-enrolled %d", code)
	}
}

// A certificate from a trusted agent CA that carries no client URI SAN
// passes the handshake but is refused by requireAgent.
func TestAgentAuthRejectsCertWithoutClientURI(t *testing.T) {
	e := newAgentEnv(t)
	ca, err := e.ca.Active(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "no-uri"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, key)}, nil); code != http.StatusUnauthorized {
		t.Fatalf("certificate without a client URI: %d", code)
	}
}

func TestEnrollRateLimited(t *testing.T) {
	e := newAgentEnv(t, func(d *Deps) { d.EnrollLimiter = authn.NewLimiter(1, 1) })
	if _, _, code := e.enroll(t, "cf1.nope"); code != http.StatusUnauthorized {
		t.Fatalf("first %d", code)
	}
	if _, _, code := e.enroll(t, "cf1.nope"); code != http.StatusTooManyRequests {
		t.Fatalf("second %d", code)
	}
}

// waitForLockWait polls pg_stat_activity for this database's own backend
// blocked waiting on the agent_cas row lock (wait_event_type = 'Lock'),
// bounded to 5s. It replaces a fixed sleep so the test does not race the
// goroutine's transaction.
func waitForLockWait(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%agent_cas%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a backend to block on a row lock")
}

// Review Focus: a CA retired while an enrolment or renewal is in flight must
// never leave a client anchored to it (Task 3 review carry-forward). Enroll
// and Renew lock the signing CA row inside their own transaction, so they
// serialize against agentca.Store.Retire's row lock on the same CA: a
// concurrent transaction that locks the CA row and marks it retired before
// enrol's row lock is granted must make enrol fail instead of activating
// the client against a CA nothing trusts any more.

func TestEnrollBlocksOnConcurrentRetire(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	active, err := e.ca.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	en := e.newClient(t, "web-1")
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT * FROM agent_cas WHERE id = $1 FOR UPDATE`, active.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{ code int }, 1)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := csrPEM(t, key)
	go func() {
		code, _, err := e.enrollRaw(e.httpClient(t, nil), en.Token, csr)
		if err != nil {
			t.Error(err)
		}
		done <- struct{ code int }{code}
	}()
	waitForLockWait(ctx, t, e.pool) // let enroll's tx block on the CA row lock
	if _, err := tx.Exec(ctx, `UPDATE agent_cas SET status = 'retired' WHERE id = $1`, active.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.code != http.StatusConflict {
		t.Fatalf("enroll against a CA retired mid-flight: %d", res.code)
	}
	c, err := e.q.GetClientByID(ctx, en.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "pending" {
		t.Fatalf("client activated despite the retired CA: %+v", c)
	}
}

// Same guard, for renew: a certificate must never be re-anchored to a CA
// retired between the transaction's signing read and its commit.
func TestRenewBlocksOnConcurrentRetire(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	en := e.newClient(t, "web-1")
	cert, _, code := e.enroll(t, en.Token)
	if code != http.StatusOK {
		t.Fatalf("enroll %d", code)
	}
	active, err := e.ca.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT * FROM agent_cas WHERE id = $1 FOR UPDATE`, active.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{ code int }, 1)
	go func() {
		code, err := doAgent(e.httpClient(t, &cert), http.MethodPost, e.ts.URL+"/agent/v1/renew",
			agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, nil)
		if err != nil {
			t.Error(err)
		}
		done <- struct{ code int }{code}
	}()
	waitForLockWait(ctx, t, e.pool) // let renew's tx block on the CA row lock
	if _, err := tx.Exec(ctx, `UPDATE agent_cas SET status = 'retired' WHERE id = $1`, active.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.code != http.StatusConflict {
		t.Fatalf("renew against a CA retired mid-flight: %d", res.code)
	}
	c, err := e.q.GetClientByID(ctx, en.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentCertSerial != agentca.SerialHex(cert.Leaf) {
		t.Fatalf("client re-anchored despite the retired CA: %+v", c)
	}
}
