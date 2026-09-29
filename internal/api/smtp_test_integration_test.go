//go:build integration

package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/notify"
)

// smtpFake is a minimal in-process SMTP server for this file's own
// integration tests: EHLO, an optional STARTTLS/AUTH PLAIN, MAIL/RCPT/
// DATA, QUIT. A separate, richer fake lives in internal/notify's own unit
// tests (mail_test.go/fakesmtp_test.go); this one only needs to prove
// testSmtpSettings is wired end to end, not re-cover SendMail's own three
// security modes.
type smtpFake struct {
	addr          string
	offerSTARTTLS bool
	wantAuth      bool
	authOK        func(user, pass string) bool
	tlsConfig     *tls.Config

	mu   sync.Mutex
	msgs []smtpFakeMessage
}

type smtpFakeMessage struct {
	From string
	To   []string
	Data string
}

func startSMTPFake(t *testing.T, offerSTARTTLS, wantAuth bool, authOK func(user, pass string) bool, tlsConfig *tls.Config) *smtpFake {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &smtpFake{addr: ln.Addr().String(), offerSTARTTLS: offerSTARTTLS, wantAuth: wantAuth, authOK: authOK, tlsConfig: tlsConfig}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *smtpFake) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(s.addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, port
}

func (s *smtpFake) messages() []smtpFakeMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]smtpFakeMessage, len(s.msgs))
	copy(out, s.msgs)
	return out
}

func (s *smtpFake) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	tp := textproto.NewConn(conn)
	if err := tp.PrintfLine("220 fake.test ESMTP"); err != nil {
		return
	}
	isTLS := false
	var msg smtpFakeMessage
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			lines := []string{"fake.test"}
			if s.offerSTARTTLS && !isTLS {
				lines = append(lines, "STARTTLS")
			}
			if s.wantAuth {
				lines = append(lines, "AUTH PLAIN")
			}
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				_ = tp.PrintfLine("250%s%s", sep, l)
			}
		case upper == "STARTTLS":
			if !s.offerSTARTTLS || isTLS {
				_ = tp.PrintfLine("500 command not recognized")
				continue
			}
			if err := tp.PrintfLine("220 Go ahead"); err != nil {
				return
			}
			tlsConn := tls.Server(conn, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			tp = textproto.NewConn(conn)
			isTLS = true
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			b64 := strings.TrimSpace(line[len("AUTH PLAIN"):])
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				_ = tp.PrintfLine("501 malformed auth")
				continue
			}
			parts := strings.SplitN(string(raw), "\x00", 3)
			var user, pass string
			if len(parts) == 3 {
				user, pass = parts[1], parts[2]
			}
			if s.authOK != nil && s.authOK(user, pass) {
				_ = tp.PrintfLine("235 2.7.0 Authentication successful")
			} else {
				_ = tp.PrintfLine("535 5.7.8 Authentication failed")
			}
		case strings.HasPrefix(upper, "MAIL FROM:"):
			msg = smtpFakeMessage{From: smtpFakeAddr(line)}
			_ = tp.PrintfLine("250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			msg.To = append(msg.To, smtpFakeAddr(line))
			_ = tp.PrintfLine("250 OK")
		case upper == "DATA":
			if err := tp.PrintfLine("354 Send message content"); err != nil {
				return
			}
			data, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			msg.Data = string(data)
			s.mu.Lock()
			s.msgs = append(s.msgs, msg)
			s.mu.Unlock()
			_ = tp.PrintfLine("250 OK")
		case upper == "QUIT":
			_ = tp.PrintfLine("221 Bye")
			return
		default:
			_ = tp.PrintfLine("500 command not recognized")
		}
	}
}

func smtpFakeAddr(line string) string {
	i := strings.Index(line, "<")
	j := strings.LastIndex(line, ">")
	if i >= 0 && j > i {
		return line[i+1 : j]
	}
	return strings.TrimSpace(line)
}

// smtpFakeCert returns a fresh self-signed certificate for "127.0.0.1" and
// its own leaf as a trust root.
func smtpFakeCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, pool
}

// smtpTestEnv is a testEnv with the "smtp"/"notifications" settings
// sections registered (newTestEnvOpts's shared fixture registers neither
// by default) and an admin session ready.
func smtpTestEnv(t *testing.T) (*testEnv, string, uuid.UUID) {
	t.Helper()
	e := newTestEnvOpts(t, func(d *api.Deps) {
		if err := notify.RegisterSettings(d.Sections); err != nil {
			t.Fatal(err)
		}
	})
	csrf, org := e.seedAdminSession()
	return e, csrf, org
}

// TestSmtpTestEndpointUnconfigured covers the 422 "SMTP is not configured"
// path: no PUT /settings/smtp has ever run.
func TestSmtpTestEndpointUnconfigured(t *testing.T) {
	e, csrf, _ := smtpTestEnv(t)

	resp, body := e.do(http.MethodPost, "/api/v1/settings/smtp/test", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"to": "ops@example.test"}, csrf)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "SMTP is not configured") {
		t.Fatalf("unconfigured: %d %s", resp.StatusCode, body)
	}
}

// TestSmtpTestEndpointRequiresSettingsWrite covers authz: an org viewer
// (no global settings:write) is refused.
func TestSmtpTestEndpointRequiresSettingsWrite(t *testing.T) {
	e, _, org := smtpTestEnv(t)
	viewer, viewerCSRF, _ := e.userSession("val", "viewer", &org)

	resp, body := e.doClient(viewer, http.MethodPost, "/api/v1/settings/smtp/test", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"to": "ops@example.test"}, http.Header{authn.CSRFHeader: []string{viewerCSRF}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer: %d %s", resp.StatusCode, body)
	}
}

// TestSmtpTestEndpointDelivers covers the success path end to end: the
// fake server receives the fixed test message, and the attempt is audited
// as smtp.test {ok: true}.
func TestSmtpTestEndpointDelivers(t *testing.T) {
	e, csrf, _ := smtpTestEnv(t)
	fake := startSMTPFake(t, false, false, nil, nil)
	host, port := fake.hostPort(t)

	resp, body := e.do(http.MethodPut, "/api/v1/settings/smtp", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"host": host, "port": port, "from": "certforge@example.test", "security": "none"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put smtp: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPost, "/api/v1/settings/smtp/test", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"to": "ops@example.test"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test: %d %s", resp.StatusCode, body)
	}
	var res struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.Status != "delivered" {
		t.Fatalf("result: %s (err %v)", body, err)
	}

	msgs := fake.messages()
	if len(msgs) != 1 || len(msgs[0].To) != 1 || msgs[0].To[0] != "ops@example.test" {
		t.Fatalf("fake server messages: %+v", msgs)
	}

	if n := auditCount(t, e, "smtp.test", notify.SMTPSectionName); n != 1 {
		t.Fatalf("smtp.test audit count = %d", n)
	}
	if details := lastAuditDetails(t, e, "smtp.test", notify.SMTPSectionName); !strings.Contains(details, `"ok": true`) && !strings.Contains(details, `"ok":true`) {
		t.Fatalf("audit details: %s", details)
	}
}

// TestSmtpTestEndpointAuthFailureOmitsPassword covers the contract: a
// rejected AUTH PLAIN comes back as a failed DeliveryResult whose error
// never contains the stored password, and is audited smtp.test {ok:
// false}.
func TestSmtpTestEndpointAuthFailureOmitsPassword(t *testing.T) {
	e, csrf, _ := smtpTestEnv(t)
	cert, pool := smtpFakeCert(t)
	fake := startSMTPFake(t, true, true, func(string, string) bool { return false }, &tls.Config{Certificates: []tls.Certificate{cert}})
	host, port := fake.hostPort(t)

	orig := notify.TestRootCAs
	notify.TestRootCAs = pool
	t.Cleanup(func() { notify.TestRootCAs = orig })

	const password = "sup3r-s3cret"
	resp, body := e.do(http.MethodPut, "/api/v1/settings/smtp", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"host": host, "port": port, "from": "certforge@example.test", "security": "starttls",
			"username": "alice", "password": password}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put smtp: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPost, "/api/v1/settings/smtp/test", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"to": "ops@example.test"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), password) {
		t.Fatalf("response leaks the password: %s", body)
	}
	var res struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.Status != "failed" || res.Error == "" {
		t.Fatalf("result: %s (err %v)", body, err)
	}

	if details := lastAuditDetails(t, e, "smtp.test", notify.SMTPSectionName); strings.Contains(details, password) {
		t.Fatalf("audit leaks the password: %s", details)
	} else if !strings.Contains(details, `"ok": false`) && !strings.Contains(details, `"ok":false`) {
		t.Fatalf("audit details: %s", details)
	}
}
