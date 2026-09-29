package notify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTPMessage is one message a fakeSMTPServer received.
type fakeSMTPMessage struct {
	From string
	To   []string
	Data string
}

// fakeSMTPOptions configures a fakeSMTPServer.
type fakeSMTPOptions struct {
	implicitTLS   bool // the listener itself speaks TLS (SendMail's "tls" security mode)
	offerSTARTTLS bool // EHLO advertises STARTTLS before any upgrade
	wantAuth      bool // EHLO advertises AUTH PLAIN
	authOK        func(user, pass string) bool
	tlsConfig     *tls.Config
	// hang accepts the connection but never sends the "220" greeting (or
	// anything else), so a client blocks reading it until its own
	// deadline/context — batch-2 review's TestSendMailCancelledContextAbortsWithinBound
	// uses this to prove a cancelled ctx unblocks SendMail well before its
	// configured timeout, not just before the dial.
	hang bool
}

// fakeSMTPServer is a minimal in-process SMTP server for mail_test.go: it
// speaks just enough SMTP (EHLO, STARTTLS, AUTH PLAIN, MAIL/RCPT/DATA,
// QUIT) to exercise SendMail's three security modes and an auth failure,
// with no real network exposure (127.0.0.1:0 only).
type fakeSMTPServer struct {
	opts fakeSMTPOptions
	ln   net.Listener
	addr string

	mu       sync.Mutex
	messages []fakeSMTPMessage
}

// startFakeSMTP starts a fakeSMTPServer and arranges for it to stop when t
// finishes.
func startFakeSMTP(t *testing.T, opts fakeSMTPOptions) *fakeSMTPServer {
	t.Helper()
	srv := &fakeSMTPServer{opts: opts}
	var ln net.Listener
	var err error
	if opts.implicitTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", opts.tlsConfig)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.ln = ln
	srv.addr = ln.Addr().String()
	go srv.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

// Addr is "host:port" for SMTPSettings.Host/Port.
func (s *fakeSMTPServer) Addr() string { return s.addr }

// Messages returns every message received so far.
func (s *fakeSMTPServer) Messages() []fakeSMTPMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]fakeSMTPMessage, len(s.messages))
	copy(out, s.messages)
	return out
}

func (s *fakeSMTPServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	tp := textproto.NewConn(conn)
	if s.opts.hang {
		// Never greets; just block until the client (or our own deadline
		// above) closes the connection.
		_, _ = tp.ReadLine()
		return
	}
	if err := tp.PrintfLine("220 fake.test ESMTP"); err != nil {
		return
	}

	isTLS := s.opts.implicitTLS
	var msg fakeSMTPMessage
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			s.writeEHLO(tp, isTLS)
		case upper == "STARTTLS":
			if !s.opts.offerSTARTTLS || isTLS {
				_ = tp.PrintfLine("500 command not recognized")
				continue
			}
			if err := tp.PrintfLine("220 Go ahead"); err != nil {
				return
			}
			tlsConn := tls.Server(conn, s.opts.tlsConfig)
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
			if s.opts.authOK != nil && s.opts.authOK(user, pass) {
				_ = tp.PrintfLine("235 2.7.0 Authentication successful")
			} else {
				_ = tp.PrintfLine("535 5.7.8 Authentication failed")
			}
		case strings.HasPrefix(upper, "MAIL FROM:"):
			msg = fakeSMTPMessage{From: extractSMTPAddr(line)}
			_ = tp.PrintfLine("250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			msg.To = append(msg.To, extractSMTPAddr(line))
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
			s.messages = append(s.messages, msg)
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

func (s *fakeSMTPServer) writeEHLO(tp *textproto.Conn, isTLS bool) {
	lines := []string{"fake.test"}
	if s.opts.offerSTARTTLS && !isTLS {
		lines = append(lines, "STARTTLS")
	}
	if s.opts.wantAuth {
		lines = append(lines, "AUTH PLAIN")
	}
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		_ = tp.PrintfLine("250%s%s", sep, l)
	}
}

// extractSMTPAddr returns the address between "<" and ">" in a MAIL
// FROM/RCPT TO line, or the trimmed line when there are no angle brackets.
func extractSMTPAddr(line string) string {
	i := strings.Index(line, "<")
	j := strings.LastIndex(line, ">")
	if i >= 0 && j > i {
		return line[i+1 : j]
	}
	return strings.TrimSpace(line)
}

// generateTestSMTPCert returns a fresh self-signed certificate for
// "127.0.0.1" and its own leaf as a trust root: a self-signed certificate
// verifies successfully when it is itself present in the verifying pool.
func generateTestSMTPCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
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
