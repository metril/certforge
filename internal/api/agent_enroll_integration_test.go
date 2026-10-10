//go:build integration

//nolint:bodyclose // post and readAll read and close every body before returning it
package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agent"
	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

var enrolFacts = agentproto.Facts{Hostname: "host-1", OS: "linux", Arch: "amd64", AgentVersion: "test"}

// enrolSession is the agent half of one hello, written out by hand so tests
// can tamper with every step.
type enrolSession struct {
	e     *agentEnv
	hc    *http.Client
	base  string
	au    string
	hello agentproto.EnrollHello
	srv   *ecdh.PublicKey
	pool  *x509.CertPool
}

func (e *agentEnv) trustedPool(t *testing.T) *x509.CertPool {
	t.Helper()
	trusted, err := e.ca.Trusted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return x509CertPool(trusted)
}

// verifySigned checks resp against the agent CA bundle, for nonce.
func (e *agentEnv) verifySigned(t *testing.T, resp *http.Response, raw []byte, nonce string) error {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(resp.Header.Get(agentproto.HeaderSignerCert))
	if err != nil || len(der) == 0 {
		return agent.ErrUnsigned
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return agent.ErrUnsigned
	}
	pub, err := agentproto.VerifyResponder(leaf, e.trustedPool(t), time.Now())
	if err != nil {
		return err
	}
	_, err = agentproto.VerifyResponse(resp.Header, resp.StatusCode, raw, nonce, time.Now(), pub)
	return err
}

func readAll(resp *http.Response) []byte {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}

// newEnrolSession performs GET enroll/hello and verifies it. A non-200 answer
// is returned as its status with a nil session.
func (e *agentEnv) newEnrolSession(t *testing.T, hc *http.Client, base string) (*enrolSession, int) {
	t.Helper()
	nonce := agentproto.NewNonce()
	hreq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, base+agentproto.PathEnrollHello+"?nonce="+nonce, nil)
	resp, err := hc.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	raw := readAll(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	if err := e.verifySigned(t, resp, raw, nonce); err != nil {
		t.Fatalf("hello not signed by the responder: %v", err)
	}
	var h agentproto.EnrollHello
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	pubRaw, _ := base64.StdEncoding.DecodeString(h.Ephemeral)
	pub, err := ecdh.P256().NewPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	return &enrolSession{e: e, hc: hc, base: base, au: agentproto.Authority(base), hello: h, srv: pub, pool: e.trustedPool(t)}, http.StatusOK
}

// submission builds the sealed plaintext for token and csr, with a fresh reply key.
func (s *enrolSession) submission(token, csr string) (agentproto.EnrollSubmit, *ecdh.PrivateKey) {
	reply, _ := ecdh.P256().GenerateKey(rand.Reader)
	der, _ := agentproto.CSRDER(csr)
	th := agentproto.TokenHash(token)
	sub := agentproto.EnrollSubmit{LookupID: agentproto.LookupID(th), CSR: csr, Facts: enrolFacts, Created: time.Now().Unix(),
		Nonce: agentproto.NewNonce(), Reply: base64.StdEncoding.EncodeToString(reply.PublicKey().Bytes())}
	sub.Pop = agentproto.EnrollPop(th, der, s.au, sub.Created, sub.Nonce, sub.Reply)
	return sub, reply
}

func (s *enrolSession) seal(t *testing.T, sub agentproto.EnrollSubmit) []byte {
	t.Helper()
	pt, _ := json.Marshal(sub)
	ct, err := agentproto.HPKESeal(s.srv, agentproto.SealInfo(agentproto.DirC2S, agentproto.PathEnroll, s.hello.ID), pt)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func (s *enrolSession) post(t *testing.T, sealed []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.base+agentproto.PathEnroll, bytes.NewReader(sealed))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(agentproto.HeaderEnrollHello, s.hello.ID)
	resp, err := s.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, readAll(resp)
}

// open verifies a signed enrol reply and opens it with the reply key.
func (s *enrolSession) open(t *testing.T, resp *http.Response, raw []byte, reply *ecdh.PrivateKey, out any) {
	t.Helper()
	if err := s.e.verifySigned(t, resp, raw, s.hello.ID); err != nil {
		t.Fatalf("enrol reply (status %d) not signed: %v", resp.StatusCode, err)
	}
	pt, err := agentproto.HPKEOpen(reply, agentproto.SealInfo(agentproto.DirS2C, agentproto.PathEnroll, s.hello.ID), raw)
	if err != nil {
		t.Fatalf("enrol reply not sealed to the reply key: %v", err)
	}
	if out != nil {
		if err := json.Unmarshal(pt, out); err != nil {
			t.Fatal(err)
		}
	}
}

// enrollRaw does hello and the sealed exchange for token with csr. It returns
// the status of the exchange and, on 200, the verified acceptance. A refused
// hello returns its status.
func (e *agentEnv) enrollRaw(t *testing.T, hc *http.Client, token, csr string) (int, agentproto.EnrollAccepted, error) {
	return e.enrollRawT(t, hc, e.ts.URL, token, csr)
}

func (e *agentEnv) enrollRawT(t *testing.T, hc *http.Client, base, token, csr string) (int, agentproto.EnrollAccepted, error) {
	s, code := e.newEnrolSession(t, hc, base)
	if s == nil {
		return code, agentproto.EnrollAccepted{}, nil
	}
	sub, reply := s.submission(token, csr)
	resp, raw := s.post(t, s.seal(t, sub))
	if resp.StatusCode != http.StatusOK {
		// A refusal after the proof is signed; before it, not. Either way no body to read.
		return resp.StatusCode, agentproto.EnrollAccepted{}, nil
	}
	var acc agentproto.EnrollAccepted
	s.open(t, resp, raw, reply, &acc)
	return http.StatusOK, acc, nil
}

// pollOnce sends one signed poll for acc and returns the status and the opened answer.
func (e *agentEnv) pollOnce(t *testing.T, hc *http.Client, key *ecdsa.PrivateKey, acc agentproto.EnrollAccepted) (int, agentproto.EnrollPoll) {
	t.Helper()
	return e.pollWith(t, hc, e.ts.URL, key, acc.ID, acc.PollSecret, nil)
}

// pollWith polls /enroll/{id}; mutate may change the request after signing.
func (e *agentEnv) pollWith(t *testing.T, hc *http.Client, base string, key *ecdsa.PrivateKey, id uuid.UUID, secret string, mutate func(*http.Request)) (int, agentproto.EnrollPoll) {
	t.Helper()
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	body, _ := json.Marshal(agentproto.EnrollPollRequest{PollSecret: secret})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, base+agentproto.PathEnroll+"/"+id.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	nonce := agentproto.NewNonce()
	if err := agentproto.SignRequest(req, body, key, agentproto.ReqParams{Authority: agentproto.Authority(base), KeyID: id.String(), Nonce: nonce,
		Created: time.Now(), Ephemeral: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())}); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw := readAll(resp)
	if err := e.verifySigned(t, resp, raw, nonce); err != nil {
		return resp.StatusCode, agentproto.EnrollPoll{} // an unsigned refusal
	}
	if resp.Header.Get(agentproto.HeaderError) != "" {
		return resp.StatusCode, agentproto.EnrollPoll{}
	}
	pt, err := agentproto.HPKEOpen(priv, agentproto.SealInfo(agentproto.DirS2C, req.URL.Path, nonce), raw)
	if err != nil {
		t.Fatalf("poll reply (status %d) not sealed to the poll key: %v", resp.StatusCode, err)
	}
	var out agentproto.EnrollPoll
	_ = json.Unmarshal(pt, &out)
	return resp.StatusCode, out
}

// enroll enrols with token the way an agent does when an administrator approves
// at once, and returns the agent's TLS identity.
func (e *agentEnv) enroll(t *testing.T, token string) (tls.Certificate, agentproto.EnrollPoll, int) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hc := e.httpClient(t, nil)
	code, acc, err := e.enrollRawT(t, hc, e.ts.URL, token, csrPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK {
		return tls.Certificate{}, agentproto.EnrollPoll{}, code
	}
	if acc.Status == agentproto.EnrollPending {
		req, err := e.q.GetEnrollmentRequest(context.Background(), acc.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.svc.ApproveEnrollment(e.as("operator"), req.OrgID, acc.ID); err != nil {
			t.Fatal(err)
		}
	}
	code, out := e.pollOnce(t, hc, key, acc)
	if code != http.StatusOK {
		return tls.Certificate{}, out, code
	}
	if out.Status != agentproto.EnrollApproved {
		t.Fatalf("poll status %q", out.Status)
	}
	blk, _ := pem.Decode([]byte(out.Certificate))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: key, Leaf: leaf}, out, code
}

// tokenAt issues a fresh token for en's client that names url as the agent URL
// (the fixture's tokens name cf.example.test) and pins the CA the listener uses.
func (e *agentEnv) tokenAt(t *testing.T, en agents.Enrolment, url string) string {
	t.Helper()
	ctx := context.Background()
	oldest, err := e.ca.Oldest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := agentproto.NewToken(url, agentca.Fingerprint(oldest.Cert.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.q.DeleteUnusedEnrollmentTokens(ctx, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.q.InsertEnrollmentToken(ctx, sqlcgen.InsertEnrollmentTokenParams{ClientID: en.Client.ID, TokenHash: agentproto.TokenHash(tok),
		LookupID: agentproto.LookupIDBytes(agentproto.TokenHash(tok)), ExpiresAt: time.Now().Add(time.Hour), CreatedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	return tok
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func fastEnrolPolls(t *testing.T) {
	t.Helper()
	oldMin, oldMax := agent.EnrollPollMin, agent.EnrollPollMax
	agent.EnrollPollMin, agent.EnrollPollMax = 10*time.Millisecond, 30*time.Millisecond
	t.Cleanup(func() { agent.EnrollPollMin, agent.EnrollPollMax = oldMin, oldMax })
}

func waitPending(t *testing.T, e *agentEnv, clientID uuid.UUID) sqlcgen.EnrollmentRequest {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var r sqlcgen.EnrollmentRequest
		err := e.pool.QueryRow(context.Background(), `SELECT id FROM enrollment_requests WHERE client_id = $1 AND status = 'pending'`, clientID).Scan(&r.ID)
		if err == nil {
			r, _ = e.q.GetEnrollmentRequest(context.Background(), r.ID)
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no pending enrolment request appeared")
	return sqlcgen.EnrollmentRequest{}
}

// The whole story through a hostile TLS-terminating proxy: token, pending, the
// administrator approves through the admin API, the poll returns the
// certificate, and the signed, sealed session then works. Nothing the proxy
// saw contained the token, the CSR or the certificate.
func TestEnrolApprovalThroughTerminatingProxy(t *testing.T) {
	e := newAgentEnv(t)
	fastEnrolPolls(t)
	proxy, tr := e.proxied(t)
	ctx := context.Background()
	en := e.newClient(t, "web-1")
	token := e.tokenAt(t, en, proxy.URL)
	rec := &hostile{next: tr}
	logs := &syncBuf{}

	type result struct {
		id  *agent.Identity
		err error
	}
	done := make(chan result, 1)
	go func() {
		id, err := agent.EnrollWith(ctx, agent.EnrollOptions{Log: slog.New(slog.NewTextHandler(logs, nil)), Transport: rec}, t.TempDir(), token, enrolFacts)
		done <- result{id, err}
	}()

	req := waitPending(t, e, en.Client.ID)
	if c, _ := e.q.GetClientByID(ctx, en.Client.ID); c.Status != "pending" {
		t.Fatalf("client %s before approval", c.Status)
	}
	select {
	case r := <-done:
		t.Fatalf("enrolment finished before approval: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	if !strings.Contains(logs.String(), "WAITING FOR APPROVAL") || !strings.Contains(logs.String(), agentproto.FormatVerifyCode(req.VerifyCode)) {
		t.Fatalf("verification code %s not logged: %s", req.VerifyCode, logs.String())
	}

	// The administrator lists, compares codes and approves through the admin API.
	op := e.as("operator")
	lr, err := e.srv.ListEnrollmentRequests(op, gen.ListEnrollmentRequestsRequestObject{OrgId: e.org})
	if err != nil {
		t.Fatal(err)
	}
	items := lr.(gen.ListEnrollmentRequests200JSONResponse).Items
	if len(items) != 1 || items[0].VerifyCode != req.VerifyCode || items[0].ClientName != "web-1" || items[0].Hostname != "host-1" || items[0].Id != req.ID {
		t.Fatalf("list %+v", items)
	}
	if _, err := e.srv.ApproveEnrollmentRequest(op, gen.ApproveEnrollmentRequestRequestObject{OrgId: e.org, Id: req.ID}); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if c, _ := e.q.GetClientByID(ctx, en.Client.ID); c.Status != "active" || c.Hostname != "host-1" {
		t.Fatalf("client %+v", c)
	}

	// The signed session works through the same proxy, with the issued identity.
	hc := secureClient(r.id, rec)
	areq, _ := http.NewRequestWithContext(ctx, http.MethodGet, proxy.URL+"/agent/v1/assignments", nil)
	resp, err := hc.Do(areq)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("assignments: %v %v", resp, err)
	}
	resp.Body.Close()

	// The proxy saw only sealed bytes: the exchange hides the token, the CSR
	// and the poll secret; a poll answer hides the certificate.
	var submits, polls int
	for _, x := range rec.exchanges() {
		switch {
		case x.method == http.MethodPost && x.uri == agentproto.PathEnroll:
			submits++
			for _, s := range []string{token, strings.Split(token, ".")[3], "BEGIN", "lookupId", "host-1", "csr"} {
				if bytes.Contains(x.reqBody, []byte(s)) {
					t.Errorf("enrol request shows %q", s)
				}
			}
			for _, s := range []string{"pollSecret", "verifyCode", "requestId"} {
				if bytes.Contains(x.respBody, []byte(s)) {
					t.Errorf("enrol reply shows %q", s)
				}
			}
		case x.method == http.MethodPost && strings.HasPrefix(x.uri, agentproto.PathEnroll+"/"):
			polls++
			for _, s := range []string{"BEGIN", "CERTIFICATE", "clientId", "trustBundle", "approved"} {
				if bytes.Contains(x.respBody, []byte(s)) {
					t.Errorf("poll answer shows %q", s)
				}
			}
		}
	}
	if submits != 1 || polls < 2 {
		t.Fatalf("proxy saw %d submissions and %d polls", submits, polls)
	}
	if e.auditCount(t, "client.enrol_requested") != 1 || e.auditCount(t, "client.enrol_approved") != 1 || e.auditCount(t, "client.enrolled") != 1 {
		t.Fatal("enrolment not audited")
	}
}

// A stolen token buys a pending request and nothing else: no certificate until
// an administrator approves, and the thief cannot poll as the real agent.
func TestEnrolStolenTokenGetsNoCertWithoutApproval(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	en := e.newClient(t, "web-1")
	hc := e.httpClient(t, nil)

	thief, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	code, acc, err := e.enrollRawT(t, hc, e.ts.URL, en.Token, csrPEM(t, thief))
	if err != nil || code != http.StatusOK || acc.Status != agentproto.EnrollPending {
		t.Fatalf("submit %d %+v %v", code, acc, err)
	}
	for range 3 {
		code, out := e.pollOnce(t, hc, thief, acc)
		if code != http.StatusOK || out.Status != agentproto.EnrollPending || out.Certificate != "" {
			t.Fatalf("poll %d %+v", code, out)
		}
	}
	if c, _ := e.q.GetClientByID(ctx, en.Client.ID); c.Status != "pending" || c.AgentCertSerial != "" {
		t.Fatalf("client %+v", c)
	}
	// The real agent has the token too, but it is spent: it gets nothing, and
	// neither do polls signed by another key or with a wrong secret.
	honest, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if code, _, _ := e.enrollRawT(t, hc, e.ts.URL, en.Token, csrPEM(t, honest)); code != http.StatusUnauthorized {
		t.Fatalf("second key on a spent token: %d", code)
	}
	if code, out := e.pollOnce(t, hc, honest, acc); code != http.StatusUnauthorized || out.Certificate != "" {
		t.Fatalf("poll signed by another key: %d", code)
	}
	if code, out := e.pollWith(t, hc, e.ts.URL, thief, acc.ID, "not-the-secret", nil); code != http.StatusUnauthorized || out.Certificate != "" {
		t.Fatalf("wrong poll secret: %d", code)
	}
	// Rejection ends it: the thief is told so and never gets a certificate.
	if _, err := e.srv.RejectEnrollmentRequest(e.as("operator"), gen.RejectEnrollmentRequestRequestObject{OrgId: e.org, Id: acc.ID}); err != nil {
		t.Fatal(err)
	}
	if code, out := e.pollOnce(t, hc, thief, acc); code != http.StatusOK || out.Status != agentproto.EnrollRejected || out.Certificate != "" {
		t.Fatalf("poll after rejection %d %+v", code, out)
	}
	if c, _ := e.q.GetClientByID(ctx, en.Client.ID); c.Status != "pending" {
		t.Fatal("client activated despite rejection")
	}
}

// An eavesdropper who recovers the sealed plaintext (or a body bound to one
// hello) cannot re-use it for another key or another hello.
func TestEnrolStolenBodyWithDifferentCSRFails(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	en := e.newClient(t, "web-1")
	hc := e.httpClient(t, nil)
	honest, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thief, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// The thief holds the honest plaintext (CSR, nonce, created, pop) but not the token.
	s, _ := e.newEnrolSession(t, hc, e.ts.URL)
	stolen, _ := s.submission(en.Token, csrPEM(t, honest))

	s2, _ := e.newEnrolSession(t, hc, e.ts.URL)
	forged := stolen
	forged.CSR = csrPEM(t, thief)
	resp, _ := s2.post(t, s2.seal(t, forged))
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(agentproto.HeaderSignerCert) != "" {
		t.Fatalf("stolen body with a different CSR: %d (signed: %v)", resp.StatusCode, resp.Header.Get(agentproto.HeaderSignerCert) != "")
	}
	// Nor with the reply key swapped, which would redirect the answer.
	s3, _ := e.newEnrolSession(t, hc, e.ts.URL)
	swapped := stolen
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	swapped.Reply = base64.StdEncoding.EncodeToString(other.PublicKey().Bytes())
	if resp, _ := s3.post(t, s3.seal(t, swapped)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stolen body with another reply key: %d", resp.StatusCode)
	}
	// Nor for another host.
	s4, _ := e.newEnrolSession(t, hc, e.ts.URL)
	s4.au = "evil.example.com"
	hostSub, _ := s4.submission(en.Token, csrPEM(t, honest))
	if resp, _ := s4.post(t, s4.seal(t, hostSub)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("proof for another host: %d", resp.StatusCode)
	}
	var n int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM enrollment_requests`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("forged bodies created %d requests (%v)", n, err)
	}
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM enrollment_tokens WHERE client_id = $1 AND used_at IS NOT NULL`, en.Client.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("forged bodies consumed the token (%d, %v)", n, err)
	}

	// The honest body, sent once, works; sent again (a replay) it does not,
	// whether to the same hello or to a fresh one.
	s5, _ := e.newEnrolSession(t, hc, e.ts.URL)
	good, reply := s5.submission(en.Token, csrPEM(t, honest))
	sealed := s5.seal(t, good)
	resp, raw := s5.post(t, sealed)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("honest body: %d", resp.StatusCode)
	}
	s5.open(t, resp, raw, reply, nil)
	if resp, _ := s5.post(t, sealed); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed sealed bytes: %d", resp.StatusCode)
	}
	s6, _ := e.newEnrolSession(t, hc, e.ts.URL)
	resp, raw = s6.post(t, s6.seal(t, good))
	var problem struct{ Detail string }
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed plaintext: %d", resp.StatusCode)
	}
	s6.open(t, resp, raw, reply, &problem)
	if !strings.Contains(problem.Detail, "already seen") {
		t.Fatalf("replayed plaintext: %q", problem.Detail)
	}
}

// The legacy {token} body is gone on both ports, with or without a hello.
func TestEnrolLegacyBodyRejected(t *testing.T) {
	e := newAgentEnv(t)
	proxy, tr := e.proxied(t)
	en := e.newClient(t, "web-1")
	legacy, _ := json.Marshal(map[string]any{"token": en.Token, "csr": csrPEM(t, mustKey(t)), "facts": enrolFacts})
	for name, c := range map[string]struct {
		hc   *http.Client
		base string
	}{
		"agent port": {e.httpClient(t, nil), e.ts.URL},
		"http port":  {&http.Client{Transport: tr}, proxy.URL},
	} {
		for hello := range 2 {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, c.base+agentproto.PathEnroll, bytes.NewReader(legacy))
			req.Header.Set("Content-Type", "application/json")
			if hello == 1 {
				s, code := e.newEnrolSession(t, c.hc, c.base)
				if s == nil {
					t.Fatalf("%s hello %d", name, code)
				}
				req.Header.Set(agentproto.HeaderEnrollHello, s.hello.ID)
			}
			resp, err := c.hc.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw := readAll(resp)
			if resp.StatusCode < 400 || bytes.Contains(raw, []byte("BEGIN")) {
				t.Fatalf("%s legacy body (hello %d): %d %s", name, hello, resp.StatusCode, raw)
			}
		}
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM enrollment_tokens WHERE client_id = $1 AND used_at IS NOT NULL`, en.Client.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal("legacy body consumed the token")
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Polls are signed requests: a replay of one and a tampered one are refused.
func TestEnrolPollReplayAndTamper(t *testing.T) {
	e := newAgentEnv(t)
	en := e.newClient(t, "web-1")
	hc := e.httpClient(t, nil)
	key := mustKey(t)
	code, acc, err := e.enrollRawT(t, hc, e.ts.URL, en.Token, csrPEM(t, key))
	if err != nil || code != http.StatusOK {
		t.Fatalf("submit %d %v", code, err)
	}
	var captured *http.Request
	var body []byte
	if code, _ := e.pollWith(t, hc, e.ts.URL, key, acc.ID, acc.PollSecret, func(r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		captured = r.Clone(context.Background())
	}); code != http.StatusOK {
		t.Fatalf("poll %d", code)
	}
	replay := captured.Clone(context.Background())
	replay.Body = io.NopCloser(bytes.NewReader(body))
	resp, err := hc.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(agentproto.HeaderError) != agentproto.ErrCodeReplay {
		t.Fatalf("replayed poll: %d %q", resp.StatusCode, resp.Header.Get(agentproto.HeaderError))
	}
	// A proxy swapping the reply key to one it holds breaks the signature.
	mine, _ := ecdh.P256().GenerateKey(rand.Reader)
	if code, out := e.pollWith(t, hc, e.ts.URL, key, acc.ID, acc.PollSecret, func(r *http.Request) {
		r.Header.Set(agentproto.HeaderEphemeral, base64.StdEncoding.EncodeToString(mine.PublicKey().Bytes()))
	}); code != http.StatusUnauthorized || out.Status != "" {
		t.Fatalf("poll with a swapped reply key: %d %+v", code, out)
	}
	// Polling a made-up id is refused without revealing whether it exists.
	if code, _ := e.pollWith(t, hc, e.ts.URL, key, uuid.New(), acc.PollSecret, nil); code != http.StatusUnauthorized {
		t.Fatalf("unknown request: %d", code)
	}
}

func TestEnrollmentAdminAPI(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	en := e.newClient(t, "web-1")
	hc := e.httpClient(t, nil)
	code, acc, err := e.enrollRawT(t, hc, e.ts.URL, en.Token, csrPEM(t, mustKey(t)))
	if err != nil || code != http.StatusOK {
		t.Fatalf("submit %d %v", code, err)
	}
	viewer, operator := e.as("viewer"), e.as("operator")
	if _, err := e.srv.ListEnrollmentRequests(viewer, gen.ListEnrollmentRequestsRequestObject{OrgId: e.org}); err != nil {
		t.Fatalf("viewer list: %v", err)
	}
	for name, call := range map[string]func() error{
		"approve": func() error {
			_, err := e.srv.ApproveEnrollmentRequest(viewer, gen.ApproveEnrollmentRequestRequestObject{OrgId: e.org, Id: acc.ID})
			return err
		},
		"reject": func() error {
			_, err := e.srv.RejectEnrollmentRequest(viewer, gen.RejectEnrollmentRequestRequestObject{OrgId: e.org, Id: acc.ID})
			return err
		},
	} {
		var he *HTTPError
		if err := call(); err == nil || !errors.As(err, &he) || he.Status != http.StatusForbidden {
			t.Errorf("viewer %s: %v", name, err)
		}
	}
	all, err := e.srv.ListAllEnrollmentRequests(operator, gen.ListAllEnrollmentRequestsRequestObject{})
	if err != nil || len(all.(gen.ListAllEnrollmentRequests200JSONResponse).Items) != 1 {
		t.Fatalf("list all: %v", err)
	}
	var he *HTTPError
	if _, err := e.srv.ApproveEnrollmentRequest(operator, gen.ApproveEnrollmentRequestRequestObject{OrgId: uuid.New(), Id: acc.ID}); err == nil || !errors.As(err, &he) {
		t.Fatalf("approve in another org: %v", err)
	}
	if _, err := e.srv.RejectEnrollmentRequest(operator, gen.RejectEnrollmentRequestRequestObject{OrgId: e.org, Id: acc.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.ApproveEnrollmentRequest(operator, gen.ApproveEnrollmentRequestRequestObject{OrgId: e.org, Id: acc.ID}); err == nil || !errors.As(err, &he) || he.Status != http.StatusConflict {
		t.Fatalf("approve after reject: %v", err)
	}
	if _, err := e.srv.ApproveEnrollmentRequest(operator, gen.ApproveEnrollmentRequestRequestObject{OrgId: e.org, Id: uuid.New()}); err == nil || !errors.As(err, &he) || he.Status != http.StatusNotFound {
		t.Fatalf("approve unknown: %v", err)
	}
	if lr, _ := e.srv.ListEnrollmentRequests(operator, gen.ListEnrollmentRequestsRequestObject{OrgId: e.org}); len(lr.(gen.ListEnrollmentRequests200JSONResponse).Items) != 0 {
		t.Fatal("decided request still listed")
	}
	_ = ctx
}
