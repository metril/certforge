package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/challenge/tlsalpn01"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

// acmeTLS1 is the ALPN protocol id RFC 8737 reserves for tls-alpn-01.
const acmeTLS1 = "acme-tls/1"

// ChallengeServer serves the http-01 and tls-alpn-01 challenges the server
// relays over the agent WebSocket (challenge_present/challenge_cleanup). It
// binds only the listeners Config configures; either (or both) may be
// empty, in which case Present for that method fails with a clear error
// instead of a nil dereference.
type ChallengeServer struct {
	HTTP01Listen  string // Config.HTTP01Listen; "" disables http-01
	TLSALPNListen string // Config.TLSALPNListen; "" disables tls-alpn-01
	WriteAllow    []string
	Files         *FileWriter
	Log           *slog.Logger

	mu          sync.Mutex
	tokens      map[string]string           // http-01 (no webroot): token -> keyAuth
	webroots    map[string]string           // http-01 (webroot): token -> the file path written, for CleanUp
	certs       map[string]*tls.Certificate // tls-alpn-01: lower-case domain -> challenge cert
	certDomains map[string]string           // tls-alpn-01: token -> domain, for CleanUp
}

// NewChallengeServer constructs a ChallengeServer sharing the deployer's
// file writer and CF_WRITE_ALLOW confinement.
func NewChallengeServer(cfg Config, files *FileWriter, log *slog.Logger) *ChallengeServer {
	return &ChallengeServer{HTTP01Listen: cfg.HTTP01Listen, TLSALPNListen: cfg.TLSALPNListen, WriteAllow: cfg.WriteAllow, Files: files, Log: log,
		tokens: map[string]string{}, webroots: map[string]string{}, certs: map[string]*tls.Certificate{}, certDomains: map[string]string{}}
}

// Start binds the configured listeners and serves until ctx ends; it
// returns once both are bound (or immediately when neither is configured).
// A bind failure is returned; the listeners themselves stop silently on
// ctx.Done, since by then the agent is shutting down anyway.
func (c *ChallengeServer) Start(ctx context.Context) error {
	if c.HTTP01Listen != "" {
		l, err := net.Listen("tcp", c.HTTP01Listen)
		if err != nil {
			return fmt.Errorf("CF_AGENT_HTTP01_LISTEN: %w", err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /.well-known/acme-challenge/{token}", c.serveHTTP01)
		srv := &http.Server{Handler: mux}
		go func() { <-ctx.Done(); _ = srv.Close() }()
		go func() {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				c.Log.Error("http-01 listener stopped", "err", err)
			}
		}()
	}
	if c.TLSALPNListen != "" {
		l, err := net.Listen("tcp", c.TLSALPNListen)
		if err != nil {
			return fmt.Errorf("CF_AGENT_TLSALPN_LISTEN: %w", err)
		}
		tlsL := tls.NewListener(l, &tls.Config{NextProtos: []string{acmeTLS1}, GetCertificate: c.getCertificate})
		go func() { <-ctx.Done(); _ = l.Close() }()
		go c.serveTLSALPN(tlsL)
	}
	return nil
}

// serveHTTP01 answers the exact well-known path from memory; an unknown or
// no-longer-present token is a 404, same as any other unrecognised path.
func (c *ChallengeServer) serveHTTP01(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	keyAuth, ok := c.tokens[r.PathValue("token")]
	c.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(keyAuth))
}

// getCertificate refuses a ClientHello that did not request acme-tls/1
// (RFC 8737 section 4: this listener answers no other protocol), then
// looks up the challenge certificate by SNI.
func (c *ChallengeServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !slices.Contains(hello.SupportedProtos, acmeTLS1) {
		return nil, fmt.Errorf("agent: tls-alpn-01 listener refuses a ClientHello without %s", acmeTLS1)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cert, ok := c.certs[strings.ToLower(hello.ServerName)]
	if !ok {
		return nil, fmt.Errorf("agent: no tls-alpn-01 challenge is being served for %q", hello.ServerName)
	}
	return cert, nil
}

// serveTLSALPN accepts and completes handshakes until l closes (ctx
// ending, or Start's own listener error path); no application data is
// ever read or written, since a completed handshake is the whole proof.
func (c *ChallengeServer) serveTLSALPN(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close() //nolint:errcheck // best-effort cleanup
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
		}()
	}
}

// Present handles one challenge_present message and returns the
// challenge_ready reply: keyAuth is kept in memory for http-01 (or written
// under Webroot, when set), or a self-signed tls-alpn-01 certificate is
// built and served by SNI. A method this agent cannot serve (no matching
// listener, and no webroot for http-01) fails with a clear error.
func (c *ChallengeServer) Present(m agentproto.ChallengePresent) agentproto.ChallengeReady {
	switch m.Method {
	case "http-01":
		if m.Webroot != "" {
			if err := c.presentWebroot(m); err != nil {
				return agentproto.ChallengeReady{Token: m.Token, Error: err.Error()}
			}
			return agentproto.ChallengeReady{Token: m.Token}
		}
		if c.HTTP01Listen == "" {
			return agentproto.ChallengeReady{Token: m.Token, Error: "this agent has no http-01 listener configured (CF_AGENT_HTTP01_LISTEN) and no webroot was given"}
		}
		c.mu.Lock()
		c.tokens[m.Token] = m.KeyAuth
		c.mu.Unlock()
		return agentproto.ChallengeReady{Token: m.Token}
	case "tls-alpn-01":
		if c.TLSALPNListen == "" {
			return agentproto.ChallengeReady{Token: m.Token, Error: "this agent has no tls-alpn-01 listener configured (CF_AGENT_TLSALPN_LISTEN)"}
		}
		cert, err := tlsalpn01.ChallengeCert(m.Domain, m.KeyAuth)
		if err != nil {
			return agentproto.ChallengeReady{Token: m.Token, Error: err.Error()}
		}
		domain := strings.ToLower(m.Domain)
		c.mu.Lock()
		c.certs[domain] = cert
		c.certDomains[m.Token] = domain
		c.mu.Unlock()
		return agentproto.ChallengeReady{Token: m.Token}
	default:
		return agentproto.ChallengeReady{Token: m.Token, Error: fmt.Sprintf("this agent cannot serve challenge method %q", m.Method)}
	}
}

// presentWebroot writes keyAuth at <webroot>/.well-known/acme-challenge/
// <token>, confined to WriteAllow the same as any grant's files.
func (c *ChallengeServer) presentWebroot(m agentproto.ChallengePresent) error {
	p := path.Join(m.Webroot, ".well-known", "acme-challenge", m.Token)
	if err := delivery.CleanPath("webroot", p); err != nil {
		return err
	}
	real, err := confine(c.WriteAllow, p)
	if err != nil {
		return err
	}
	if err := c.Files.Write(real, []byte(m.KeyAuth), 0o644, "", ""); err != nil {
		return err
	}
	c.mu.Lock()
	c.webroots[m.Token] = p
	c.mu.Unlock()
	return nil
}

// CleanUp handles one challenge_cleanup message: best-effort, since by the
// time it arrives the order is already finishing either way.
func (c *ChallengeServer) CleanUp(m agentproto.ChallengeCleanup) {
	c.mu.Lock()
	delete(c.tokens, m.Token)
	wp, hadWebroot := c.webroots[m.Token]
	delete(c.webroots, m.Token)
	domain, hadCert := c.certDomains[m.Token]
	delete(c.certDomains, m.Token)
	if hadCert {
		delete(c.certs, domain)
	}
	c.mu.Unlock()
	if hadWebroot {
		if real, err := confine(c.WriteAllow, wp); err == nil {
			_ = c.Files.Remove(real)
		}
	}
}
