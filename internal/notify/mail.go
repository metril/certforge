package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/notify/httpx"
)

// TestRootCAs, when non-nil, replaces the system root pool SendMail's TLS
// and STARTTLS handshakes verify a server certificate against — never
// skipping verification, only handing it a different, still fully checked,
// trust anchor. It exists because the "smtp" settings section (task-1
// brief) carries no caPem field the way a channel's config does, so a fake
// in-process SMTP server built for a test (a self-signed certificate) has
// no other way to be trusted; production code never sets it, and it stays
// nil there. A test that sets it must restore it (t.Cleanup) since it is a
// package-level var shared by every SendMail call.
var TestRootCAs *x509.CertPool

// tlsConfigForHost returns the tls.Config SendMail uses for both the "tls"
// and "starttls" security modes.
func tlsConfigForHost(host string) *tls.Config {
	return &tls.Config{ServerName: host, RootCAs: TestRootCAs, MinVersion: tls.VersionTLS12}
}

// SendMail sends one text/plain email over the SMTP server cfg describes,
// using password for AUTH PLAIN when cfg.Username is set (contract:
// "AUTH PLAIN runs only when username is set"). security dials three ways
// (contract):
//   - "tls": an implicit-TLS connection via tls.DialWithDialer, ServerName
//     = cfg.Host.
//   - "starttls" (the default when cfg.Security is empty): a plain dial,
//     then STARTTLS; a server that does not advertise STARTTLS is an
//     error, never a silent downgrade to plaintext.
//   - "none": a plain dial, no upgrade.
//
// The dial's net.Dialer.Control is httpx.DialControl (the same host
// policy every HTTP notifier's dial re-applies against the resolved
// address) — SMTP relays are an operator-configured, settings:write-gated
// global resource rather than a per-channel URL a lower-privileged actor
// could point anywhere, and are often local (a mailhog/postfix on the same
// host), so loopback is always allowed here; only the cloud-metadata
// blocklist inside DialControl still applies. The connection's single
// deadline (contract: "the deadline is timeoutSeconds on the conn") is
// min(now+cfg.TimeoutSeconds (or 10s when unset), ctx's own deadline when
// it has one) — net/smtp itself has no context support, so ctx is also
// wired directly onto the connection via context.AfterFunc(ctx, ...): a
// cancelled or expired ctx closes conn immediately (batch-2 review),
// unblocking whichever net/smtp call is in flight well before the
// deadline, not just bounding the initial dial (DialContext/tls.Dialer).
// Every returned error has password (and, incidentally, any occurrence of
// it in a URL-escaped or path-escaped form) redacted, so a bad password
// value can never surface through it (contract: "the password never
// appears in errors").
func SendMail(ctx context.Context, cfg SMTPSettings, password string, to []string, subject, body string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: timeout, Control: httpx.DialControl(true)}

	var conn net.Conn
	var err error
	if cfg.Security == "tls" {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsConfigForHost(cfg.Host)}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return redactSMTPErr(fmt.Errorf("notify: smtp: dial: %w", err), password)
	}

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return redactSMTPErr(fmt.Errorf("notify: smtp: %w", err), password)
	}
	// Closes conn the moment ctx is done (cancelled or its own deadline
	// passes), so every net/smtp call below — which takes no context of
	// its own — is bounded by ctx too, not only by the fixed deadline just
	// set (batch-2 review: testChannel's 10s WithTimeout must bound an
	// smtp channel's whole exchange, not just its dial). stop() releases
	// the AfterFunc registration once SendMail is about to return either
	// way, so a completed call never leaves a live closer behind.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return redactSMTPErr(fmt.Errorf("notify: smtp: connect: %w", err), password)
	}
	defer func() { _ = client.Close() }()

	// "starttls" is also the fallback for an empty/unrecognised Security —
	// the schema's own default (smtp.schema.json: "security" default
	// "starttls") — so an empty value behaves the same here as it does
	// once the section has actually been saved.
	if cfg.Security != "tls" && cfg.Security != "none" {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return redactSMTPErr(errors.New("notify: smtp: server does not offer STARTTLS"), password)
		}
		if err := client.StartTLS(tlsConfigForHost(cfg.Host)); err != nil {
			return redactSMTPErr(fmt.Errorf("notify: smtp: starttls: %w", err), password)
		}
	}

	if cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, password, cfg.Host)); err != nil {
			return redactSMTPErr(fmt.Errorf("notify: smtp: auth: %w", err), password)
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return redactSMTPErr(fmt.Errorf("notify: smtp: mail from: %w", err), password)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return redactSMTPErr(fmt.Errorf("notify: smtp: rcpt to: %w", err), password)
		}
	}
	w, err := client.Data()
	if err != nil {
		return redactSMTPErr(fmt.Errorf("notify: smtp: data: %w", err), password)
	}
	if _, err := w.Write(buildMessage(cfg.From, to, subject, body)); err != nil {
		return redactSMTPErr(fmt.Errorf("notify: smtp: write: %w", err), password)
	}
	if err := w.Close(); err != nil {
		return redactSMTPErr(fmt.Errorf("notify: smtp: %w", err), password)
	}
	return redactSMTPErr(client.Quit(), password)
}

// redactSMTPErr wraps err with password (and its URL/path-escaped forms)
// redacted, or returns nil unchanged.
func redactSMTPErr(err error, password string) error {
	if err == nil {
		return nil
	}
	return errors.New(httpx.Redact(err.Error(), password))
}

// buildMessage renders the RFC 5322 message SendMail transmits: From,
// To, a CR/LF-stripped Subject (Q-encoded when it holds non-ASCII text —
// Wire formats row), Date, a fresh Message-ID, MIME-Version and a
// quoted-printable text/plain body.
func buildMessage(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeSubject(stripCRLFAndControl(subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@certforge>\r\n", uuid.NewString())
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("\r\n")
	qw := quotedprintable.NewWriter(&b)
	_, _ = qw.Write([]byte(body))
	_ = qw.Close()
	return b.Bytes()
}

// encodeSubject Q-encodes s (RFC 2047) when it holds any non-ASCII rune,
// and returns it unchanged otherwise (Wire formats row: "Q-encoded when
// non-ASCII").
func encodeSubject(s string) string {
	for _, r := range s {
		if r > 127 {
			return mime.QEncoding.Encode("UTF-8", s)
		}
	}
	return s
}
