package notify_test

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/notify"
)

// splitAddr turns "host:port" (fakeSMTPServer.Addr) into SMTPSettings'
// Host/Port fields.
func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return host, port
}

// TestSendMailStartTLS covers the "starttls" security mode end to end: a
// plain dial, STARTTLS, AUTH PLAIN over the now-encrypted connection, and
// delivery of a recognisable message.
func TestSendMailStartTLS(t *testing.T) {
	cert, pool := generateTestSMTPCert(t)
	srv := startFakeSMTP(t, fakeSMTPOptions{
		offerSTARTTLS: true,
		wantAuth:      true,
		authOK:        func(user, pass string) bool { return user == "alice" && pass == "s3cret" },
		tlsConfig:     &tls.Config{Certificates: []tls.Certificate{cert}},
	})

	orig := notify.TestRootCAs
	notify.TestRootCAs = pool
	t.Cleanup(func() { notify.TestRootCAs = orig })

	host, port := splitAddr(t, srv.Addr())
	cfg := notify.SMTPSettings{Host: host, Port: port, Username: "alice", From: "certforge@example.test",
		Security: "starttls", TimeoutSeconds: 5}

	if err := notify.SendMail(context.Background(), cfg, "s3cret", []string{"ops@example.test"}, "hello", "body text\n"); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	if msgs[0].From != "certforge@example.test" || len(msgs[0].To) != 1 || msgs[0].To[0] != "ops@example.test" {
		t.Fatalf("message envelope = %+v", msgs[0])
	}
	if !strings.Contains(msgs[0].Data, "Subject: hello") {
		t.Fatalf("data missing subject: %q", msgs[0].Data)
	}
}

// TestSendMailImplicitTLS covers the "tls" security mode: the listener
// itself is TLS, dialed via tls.DialWithDialer.
func TestSendMailImplicitTLS(t *testing.T) {
	cert, pool := generateTestSMTPCert(t)
	srv := startFakeSMTP(t, fakeSMTPOptions{
		implicitTLS: true,
		tlsConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
	})

	orig := notify.TestRootCAs
	notify.TestRootCAs = pool
	t.Cleanup(func() { notify.TestRootCAs = orig })

	host, port := splitAddr(t, srv.Addr())
	cfg := notify.SMTPSettings{Host: host, Port: port, From: "certforge@example.test", Security: "tls", TimeoutSeconds: 5}

	if err := notify.SendMail(context.Background(), cfg, "", []string{"ops@example.test"}, "hi", "body\n"); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if len(srv.Messages()) != 1 {
		t.Fatalf("messages = %d, want 1", len(srv.Messages()))
	}
}

// TestSendMailPlainNoAuth covers the "none" security mode: a plain dial,
// no STARTTLS attempt even when the server would offer it, no AUTH (no
// username).
func TestSendMailPlainNoAuth(t *testing.T) {
	srv := startFakeSMTP(t, fakeSMTPOptions{offerSTARTTLS: true})

	host, port := splitAddr(t, srv.Addr())
	cfg := notify.SMTPSettings{Host: host, Port: port, From: "certforge@example.test", Security: "none", TimeoutSeconds: 5}

	if err := notify.SendMail(context.Background(), cfg, "", []string{"ops@example.test"}, "hi", "body\n"); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if len(srv.Messages()) != 1 {
		t.Fatalf("messages = %d, want 1", len(srv.Messages()))
	}
}

// TestStartTLSMissingIsError covers the contract's "a server that does
// not offer it is an error, never a downgrade": a "starttls" SendMail
// against a server that never advertises STARTTLS must fail outright, and
// must never have sent the message in plaintext.
func TestStartTLSMissingIsError(t *testing.T) {
	srv := startFakeSMTP(t, fakeSMTPOptions{offerSTARTTLS: false})

	host, port := splitAddr(t, srv.Addr())
	cfg := notify.SMTPSettings{Host: host, Port: port, From: "certforge@example.test", Security: "starttls", TimeoutSeconds: 5}

	err := notify.SendMail(context.Background(), cfg, "", []string{"ops@example.test"}, "hi", "body\n")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v, want a STARTTLS error", err)
	}
	if len(srv.Messages()) != 0 {
		t.Fatalf("messages = %d, want 0 (no plaintext downgrade)", len(srv.Messages()))
	}
}

// TestSendMailAuthFailure covers the contract's "the password never
// appears in errors": a rejected AUTH PLAIN must fail SendMail without the
// password surfacing in its error text.
func TestSendMailAuthFailure(t *testing.T) {
	cert, pool := generateTestSMTPCert(t)
	srv := startFakeSMTP(t, fakeSMTPOptions{
		offerSTARTTLS: true,
		wantAuth:      true,
		authOK:        func(string, string) bool { return false },
		tlsConfig:     &tls.Config{Certificates: []tls.Certificate{cert}},
	})

	orig := notify.TestRootCAs
	notify.TestRootCAs = pool
	t.Cleanup(func() { notify.TestRootCAs = orig })

	host, port := splitAddr(t, srv.Addr())
	cfg := notify.SMTPSettings{Host: host, Port: port, Username: "alice", From: "certforge@example.test",
		Security: "starttls", TimeoutSeconds: 5}

	const password = "tr0ub4dor"
	err := notify.SendMail(context.Background(), cfg, password, []string{"ops@example.test"}, "hi", "body\n")
	if err == nil {
		t.Fatal("SendMail succeeded, want an auth failure")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("error leaks the password: %v", err)
	}
	if len(srv.Messages()) != 0 {
		t.Fatalf("messages = %d, want 0", len(srv.Messages()))
	}
}

// TestSMTPSubjectStripsCRLF covers header injection (Review Focus): a
// summary carrying CR/LF must never let a crafted event add an extra
// header line to the message SendMail transmits.
func TestSMTPSubjectStripsCRLF(t *testing.T) {
	srv := startFakeSMTP(t, fakeSMTPOptions{})
	host, port := splitAddr(t, srv.Addr())
	cfg := notify.SMTPSettings{Host: host, Port: port, From: "certforge@example.test", Security: "none", TimeoutSeconds: 5}

	subject := "hello\r\nX-Injected: evil"
	if err := notify.SendMail(context.Background(), cfg, "", []string{"ops@example.test"}, subject, "body\n"); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	if strings.Contains(msgs[0].Data, "\nX-Injected:") {
		t.Fatalf("subject injection created a header line: %q", msgs[0].Data)
	}
	if !strings.Contains(msgs[0].Data, "Subject: helloX-Injected: evil") {
		t.Fatalf("subject not on one line: %q", msgs[0].Data)
	}
}

// TestSMTPNonASCIISubjectEncoded covers the Wire formats row: a non-ASCII
// subject is RFC 2047 Q-encoded, never sent as raw UTF-8 bytes in a
// header.
func TestSMTPNonASCIISubjectEncoded(t *testing.T) {
	srv := startFakeSMTP(t, fakeSMTPOptions{})
	host, port := splitAddr(t, srv.Addr())
	cfg := notify.SMTPSettings{Host: host, Port: port, From: "certforge@example.test", Security: "none", TimeoutSeconds: 5}

	subject := "café expiring"
	if err := notify.SendMail(context.Background(), cfg, "", []string{"ops@example.test"}, subject, "body\n"); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	if strings.Contains(msgs[0].Data, "café") {
		t.Fatalf("subject not encoded, raw UTF-8 present: %q", msgs[0].Data)
	}
	if !strings.Contains(msgs[0].Data, "Subject: =?UTF-8?") {
		t.Fatalf("subject not Q-encoded: %q", msgs[0].Data)
	}
}
