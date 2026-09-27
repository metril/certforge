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
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/tlsalpn01"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

// acmeTLS1 is the ALPN protocol id RFC 8737 reserves for tls-alpn-01.
const acmeTLS1 = "acme-tls/1"

// challengeTTL is how long a presented http-01 token, tls-alpn-01
// certificate or webroot file is served after Present, in case
// challenge_cleanup is lost (a dropped socket, a crashed or superseded
// attempt): long enough for CA validation to reach it, short enough that a
// stale entry does not linger until restart. Matches
// challenge.DefaultHTTPTokenTTL server-side; internal/agent cannot import
// internal/challenge (see the package comment), so the value is repeated
// here rather than shared.
const challengeTTL = 10 * time.Minute

// tlsHandshakeTimeout bounds how long a tls-alpn-01 accept goroutine waits
// for a ClientHello and handshake to complete, so a client that connects
// and never proceeds cannot pin a goroutine (and a file descriptor)
// forever.
const tlsHandshakeTimeout = 10 * time.Second

// readHeaderTimeout bounds the agent's http-01 listener the same way the
// server's own listeners are bounded (cmd/certforge/serve.go).
const readHeaderTimeout = 10 * time.Second

// tokenRe matches an ACME token: the same shape the server's own public
// well-known route requires (global constraints, "Public route"). Present
// checks it before any token reaches a filesystem path (presentWebroot's
// path.Join).
var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// httpTokenEntry is a stored http-01 key authorization with its expiry.
type httpTokenEntry struct {
	keyAuth string
	expires time.Time
}

// webrootEntry is a webroot file this server wrote, with its expiry.
type webrootEntry struct {
	path    string
	expires time.Time
}

// certEntry is a tls-alpn-01 challenge certificate, the token that
// presented it (so CleanUp only ever removes the entry it itself created —
// never a newer Present's for the same domain) and its expiry.
type certEntry struct {
	cert    *tls.Certificate
	token   string
	expires time.Time
}

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
	Now           func() time.Time // nil = time.Now; overridable for tests

	mu          sync.Mutex
	tokens      map[string]httpTokenEntry // http-01 (no webroot): token -> keyAuth
	webroots    map[string]webrootEntry   // http-01 (webroot): token -> the file path written, for CleanUp
	certs       map[string]certEntry      // tls-alpn-01: lower-case domain -> challenge cert
	certDomains map[string]string         // tls-alpn-01: token -> domain, for CleanUp
}

// NewChallengeServer constructs a ChallengeServer sharing the deployer's
// file writer and CF_WRITE_ALLOW confinement.
func NewChallengeServer(cfg Config, files *FileWriter, log *slog.Logger) *ChallengeServer {
	return &ChallengeServer{HTTP01Listen: cfg.HTTP01Listen, TLSALPNListen: cfg.TLSALPNListen, WriteAllow: cfg.WriteAllow, Files: files, Log: log,
		tokens: map[string]httpTokenEntry{}, webroots: map[string]webrootEntry{}, certs: map[string]certEntry{}, certDomains: map[string]string{}}
}

func (c *ChallengeServer) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
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
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: readHeaderTimeout}
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

// serveHTTP01 answers the exact well-known path from memory; an unknown,
// expired or no-longer-present token is a 404, same as any other
// unrecognised path.
func (c *ChallengeServer) serveHTTP01(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	e, ok := c.tokens[r.PathValue("token")]
	c.mu.Unlock()
	if !ok || !c.now().Before(e.expires) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(e.keyAuth))
}

// getCertificate refuses a ClientHello that did not request acme-tls/1
// (RFC 8737 section 4: this listener answers no other protocol), then
// looks up the challenge certificate by SNI; an expired entry is treated
// as absent, same as serveHTTP01.
func (c *ChallengeServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !slices.Contains(hello.SupportedProtos, acmeTLS1) {
		return nil, fmt.Errorf("agent: tls-alpn-01 listener refuses a ClientHello without %s", acmeTLS1)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.certs[strings.ToLower(hello.ServerName)]
	if !ok || !c.now().Before(e.expires) {
		return nil, fmt.Errorf("agent: no tls-alpn-01 challenge is being served for %q", hello.ServerName)
	}
	return e.cert, nil
}

// serveTLSALPN accepts and completes handshakes until l closes (ctx
// ending, or Start's own listener error path); no application data is ever
// read or written, since a completed handshake is the whole proof. Each
// connection gets a deadline before the handshake so a client that
// connects and stalls cannot pin the goroutine (and a file descriptor)
// forever.
func (c *ChallengeServer) serveTLSALPN(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close() //nolint:errcheck // best-effort cleanup
			_ = conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
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
// listener, and no webroot for http-01) fails with a clear error. Every
// call first purges expired entries (bounding memory and, for webroot
// files, disk use, the same TTL sweep challenge.HTTPTokens.Put does
// server-side) and rejects a malformed token before it can reach a
// filesystem path.
func (c *ChallengeServer) Present(m agentproto.ChallengePresent) agentproto.ChallengeReady {
	if !tokenRe.MatchString(m.Token) {
		return agentproto.ChallengeReady{Token: m.Token, Error: fmt.Sprintf("invalid token %q", m.Token)}
	}
	now := c.now()
	c.mu.Lock()
	expiredWebroots := c.purgeLocked(now)
	c.mu.Unlock()
	c.removeWebrootFiles(expiredWebroots)

	switch m.Method {
	case "http-01":
		if m.Webroot != "" {
			if err := c.presentWebroot(m, now); err != nil {
				return agentproto.ChallengeReady{Token: m.Token, Error: err.Error()}
			}
			return agentproto.ChallengeReady{Token: m.Token}
		}
		if c.HTTP01Listen == "" {
			return agentproto.ChallengeReady{Token: m.Token, Error: "this agent has no http-01 listener configured (CF_AGENT_HTTP01_LISTEN) and no webroot was given"}
		}
		c.mu.Lock()
		c.tokens[m.Token] = httpTokenEntry{keyAuth: m.KeyAuth, expires: now.Add(challengeTTL)}
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
		c.certs[domain] = certEntry{cert: cert, token: m.Token, expires: now.Add(challengeTTL)}
		c.certDomains[m.Token] = domain
		c.mu.Unlock()
		return agentproto.ChallengeReady{Token: m.Token}
	default:
		return agentproto.ChallengeReady{Token: m.Token, Error: fmt.Sprintf("this agent cannot serve challenge method %q", m.Method)}
	}
}

// purgeLocked drops every expired token, webroot and certificate entry
// (mu must be held by the caller) and returns the webroot paths that
// expired, for their files to be removed by the caller after unlocking
// (file I/O must never run with mu held).
func (c *ChallengeServer) purgeLocked(now time.Time) []string {
	var expiredWebroots []string
	for tok, e := range c.tokens {
		if !now.Before(e.expires) {
			delete(c.tokens, tok)
		}
	}
	for tok, e := range c.webroots {
		if !now.Before(e.expires) {
			expiredWebroots = append(expiredWebroots, e.path)
			delete(c.webroots, tok)
		}
	}
	for domain, e := range c.certs {
		if !now.Before(e.expires) {
			delete(c.certs, domain)
		}
	}
	for tok, domain := range c.certDomains {
		if _, ok := c.certs[domain]; !ok {
			delete(c.certDomains, tok)
		}
	}
	return expiredWebroots
}

// removeWebrootFiles best-effort removes every path in paths, confined to
// WriteAllow the same as any grant's files; used both by the TTL sweep and
// by CleanUp's own webroot removal.
func (c *ChallengeServer) removeWebrootFiles(paths []string) {
	for _, p := range paths {
		if real, err := confine(c.WriteAllow, p); err == nil {
			_ = c.Files.Remove(real)
		}
	}
}

// presentWebroot writes keyAuth at <webroot>/.well-known/acme-challenge/
// <token>, confined to WriteAllow the same as any grant's files.
func (c *ChallengeServer) presentWebroot(m agentproto.ChallengePresent, now time.Time) error {
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
	c.webroots[m.Token] = webrootEntry{path: p, expires: now.Add(challengeTTL)}
	c.mu.Unlock()
	return nil
}

// CleanUp handles one challenge_cleanup message: best-effort, since by the
// time it arrives the order is already finishing either way. It removes
// only the entries this token itself created: a tls-alpn-01 certificate is
// removed only when it is still the one this token presented, so a late or
// racing CleanUp for a superseded token can never delete a newer Present's
// certificate for the same domain.
func (c *ChallengeServer) CleanUp(m agentproto.ChallengeCleanup) {
	c.mu.Lock()
	delete(c.tokens, m.Token)
	wr, hadWebroot := c.webroots[m.Token]
	delete(c.webroots, m.Token)
	domain, hadDomain := c.certDomains[m.Token]
	if hadDomain {
		delete(c.certDomains, m.Token)
		if entry, ok := c.certs[domain]; ok && entry.token == m.Token {
			delete(c.certs, domain)
		}
	}
	c.mu.Unlock()
	if hadWebroot {
		c.removeWebrootFiles([]string{wr.path})
	}
}
