package api

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
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/authn"
)

// The agent protocol's application layer, identical on the agent port and on
// the HTTP port behind any TLS-terminating proxy: a signed handshake opens an
// in-memory session (ephemeral ECDH, forward secret), and every later request
// is signed by the agent's key and sealed under the session; every response is
// sealed and signed by the responder. The TLS layer, and who terminates it,
// is not trusted for anything.

const (
	// nonceSkew is how far a request's created may be from the server clock
	// (tighter than agentproto.MaxSkew); nonceTTL covers that window twice.
	nonceSkew = 60 * time.Second
	nonceTTL  = 120 * time.Second

	sessionTTL        = time.Duration(agentproto.SessionTTLSeconds) * time.Second
	maxSessionsClient = 16
	responderKeyID    = "responder"
)

// NonceStore remembers request nonces for replay protection. The default is
// in memory, so a restart forgets the last nonceTTL; a replay in that window
// still cannot be answered to anyone but the agent, whose session keys the
// proxy does not hold. Swap it for a shared store when running several servers.
type NonceStore interface {
	// Add records key at now. It reports false when the key was already
	// recorded and has not expired (a replay), and errNonceFull when the store
	// is at capacity and cannot record it.
	Add(key string, now time.Time) (bool, error)
}

// maxNonces bounds the in-memory replay cache: about 120 s of requests at the
// rate limits, with generous headroom.
const maxNonces = 200000

var errNonceFull = errors.New("agent nonce cache full")

type memNonces struct {
	max    int
	mu     sync.Mutex
	seen   map[string]time.Time // key -> expiry
	pruned time.Time
}

// NewAgentNonces returns the in-memory replay cache. Both the HTTP router and
// the agent listener's router must be given the same one (Deps.AgentNonces),
// or a request captured on one port replays on the other.
func NewAgentNonces() NonceStore { return newMemNonces() }

func newMemNonces() *memNonces { return &memNonces{max: maxNonces, seen: map[string]time.Time{}} }

func (m *memNonces) prune(now time.Time) {
	for k, exp := range m.seen {
		if !now.Before(exp) {
			delete(m.seen, k)
		}
	}
	m.pruned = now
}

func (m *memNonces) Add(key string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.Sub(m.pruned) > nonceTTL/2 {
		m.prune(now)
	}
	if exp, ok := m.seen[key]; ok && now.Before(exp) {
		return false, nil
	}
	if len(m.seen) >= m.max {
		m.prune(now)
		if len(m.seen) >= m.max {
			return false, errNonceFull
		}
	}
	m.seen[key] = now.Add(nonceTTL)
	return true, nil
}

// agentSession is one live handshake: the keys, and the client it belongs to.
type agentSession struct {
	id       string
	sess     *agentproto.Session
	clientID uuid.UUID
	serial   string
	pub      *ecdsa.PublicKey
	created  time.Time
}

func (s *agentSession) keyID() string { return s.clientID.String() + ":" + s.serial }

type agentSessions struct {
	mu sync.Mutex
	m  map[string]*agentSession
}

func (s *agentSessions) put(x *agentSession, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]*agentSession{}
	}
	n := 0
	var oldest *agentSession
	for id, o := range s.m {
		if now.Sub(o.created) >= sessionTTL {
			delete(s.m, id)
			continue
		}
		if o.clientID == x.clientID {
			n++
			if oldest == nil || o.created.Before(oldest.created) {
				oldest = o
			}
		}
	}
	if n >= maxSessionsClient {
		delete(s.m, oldest.id)
	}
	s.m[x.id] = x
}

func (s *agentSessions) get(id string, now time.Time) *agentSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.m[id]
	if x != nil && now.Sub(x.created) >= sessionTTL {
		delete(s.m, id)
		return nil
	}
	return x
}

func (a *agentAPI) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// authorities are the hosts requests may be signed for: never taken from the
// request, only from configuration. The HTTP port also answers for the base URL.
func (a *agentAPI) authorities(ctx context.Context) []string {
	if len(a.d.AgentAuthorities) > 0 {
		return a.d.AgentAuthorities
	}
	var out []string
	if a.d.AgentSettings != nil {
		if st, err := a.d.AgentSettings.Get(ctx); err == nil {
			if au := agentproto.Authority(st.AgentURL); au != "" {
				out = append(out, au)
			}
			// Agents enrolled against an earlier Agent URL keep signing for
			// its host; it stays valid while it is a listener name.
			out = append(out, listenerAuthorities(st)...)
		}
	}
	if a.httpPort {
		if au := agentproto.Authority(a.d.Config.BaseURL); au != "" {
			out = append(out, au)
		}
	}
	return out
}

// listenerAuthorities are the authorities an agent reaching the server by one
// of the listener names signs for: the bare name (default port) and the name
// on the Agent URL's port.
func listenerAuthorities(st agents.Settings) []string {
	var port string
	if u, err := url.Parse(st.AgentURL); err == nil {
		port = u.Port()
	}
	var out []string
	for _, n := range st.ListenerNames {
		h := strings.ToLower(n)
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		out = append(out, h)
		if port != "" && port != "443" {
			out = append(out, h+":"+port)
		}
	}
	return out
}

func (a *agentAPI) verify(r *http.Request, body []byte, now time.Time, lookup func(string) (*ecdsa.PublicKey, error)) (agentproto.ReqParams, error) {
	err := agentproto.ErrSig
	for _, au := range a.authorities(r.Context()) {
		p, e := agentproto.VerifyRequest(r, body, au, now, lookup)
		if e == nil {
			return p, nil
		}
		if !errors.Is(e, agentproto.ErrSig) {
			return agentproto.ReqParams{}, e
		}
		err = e
	}
	return agentproto.ReqParams{}, err
}

func (a *agentAPI) responder() *respSigner {
	if a.d.AgentListener == nil {
		return nil
	}
	s, ok := a.d.AgentListener.Responder()
	if !ok {
		return nil
	}
	a.refreshResponder(s.Chain[0])
	rs := &respSigner{key: s.Key, leaf: base64.StdEncoding.EncodeToString(s.Chain[0].Raw)}
	for _, c := range s.Chain[1:] {
		rs.chain = append(rs.chain, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return rs
}

// refreshResponder renews the responder certificate in the background once it
// is due, in case the hourly renewal job is late: agents refuse an expired
// responder, so it must never be served past its 24 h lifetime.
func (a *agentAPI) refreshResponder(leaf *x509.Certificate) {
	if !agentproto.RenewDue(leaf.NotBefore, leaf.NotAfter, a.clock()) || !a.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.refreshing.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := a.d.AgentListener.Reload(ctx); err != nil && !errors.Is(err, agentca.ErrNoNames) {
			a.d.Log.Error("agent responder certificate not renewed", "err", err)
		}
	}()
}

type respSigner struct {
	key   *ecdsa.PrivateKey
	leaf  string
	chain []string // base64 DER of the certificates above the leaf
}

// signResponse signs h for a response of status over body (the bytes on the
// wire), answering reqNonce. It reports false when there is no responder.
func (a *agentAPI) signResponse(h http.Header, status int, body []byte, reqNonce string) bool {
	sg := a.responder()
	if sg == nil {
		return false
	}
	if err := agentproto.SignResponse(h, status, body, sg.key, agentproto.RespParams{KeyID: responderKeyID, ReqNonce: reqNonce, Created: a.clock()}); err != nil {
		return false
	}
	h.Set(agentproto.HeaderSignerCert, sg.leaf)
	return true
}

// reject answers a request that has not been authenticated with an unsigned,
// bodyless refusal and a machine-readable code. It is unsigned on purpose: a
// responder signature on a refusal vouches that the agent's own signature
// verified, which is only true after verification (see refuse). The agent
// treats an unsigned refusal as a transport error, never as revocation.
func (a *agentAPI) reject(w http.ResponseWriter, status int, code string) {
	w.Header().Set(agentproto.HeaderError, code)
	w.WriteHeader(status)
}

// refuse is reject for a request whose signature verified: the refusal is
// signed by the responder, binds the code and the request nonce, and so
// cannot be forged or replayed by a proxy.
func (a *agentAPI) refuse(w http.ResponseWriter, status int, code, nonce string) {
	h := w.Header()
	sg := a.responder()
	if sg == nil || agentproto.SignResponse(h, status, nil, sg.key, agentproto.RespParams{KeyID: responderKeyID, ReqNonce: nonce, Created: a.clock(), Error: code}) != nil {
		a.reject(w, status, code)
		return
	}
	h.Set(agentproto.HeaderSignerCert, sg.leaf)
	w.WriteHeader(status)
}

// rejectErr refuses with the status of a service error: signed when nonce
// names a verified request, unsigned (nonce "") otherwise.
func (a *agentAPI) rejectErr(w http.ResponseWriter, err error, nonce string) {
	status, code := http.StatusInternalServerError, "internal"
	var he *HTTPError
	if errors.As(mapAgentErr(err), &he) {
		status, code = he.Status, agentproto.ErrCodeAuth
	} else {
		a.d.Log.Error("agent request failed", "err", err)
	}
	if nonce == "" {
		a.reject(w, status, code)
		return
	}
	a.refuse(w, status, code, nonce)
}

func (a *agentAPI) readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		a.reject(w, http.StatusRequestEntityTooLarge, "size")
		return nil, false
	}
	return b, true
}

// checkFresh applies the nonce window and the replay cache to a verified
// request and, when it fails, answers it (a signed refusal; an unsigned 503
// when the cache is full) and reports false.
func (a *agentAPI) checkFresh(w http.ResponseWriter, p agentproto.ReqParams, now time.Time) bool {
	if d := now.Sub(p.Created); d > nonceSkew || d < -nonceSkew {
		a.refuse(w, http.StatusUnauthorized, agentproto.ErrCodeStale, p.Nonce)
		return false
	}
	fresh, err := a.nonces.Add(p.KeyID+"|"+p.Nonce, now)
	if errors.Is(err, errNonceFull) {
		a.d.Log.Error("agent replay cache full; refusing signed requests until entries expire")
		w.Header().Set("Retry-After", "5")
		a.reject(w, http.StatusServiceUnavailable, "busy")
		return false
	}
	if err != nil || !fresh {
		a.refuse(w, http.StatusUnauthorized, agentproto.ErrCodeReplay, p.Nonce)
		return false
	}
	return true
}

// session is POST /agent/v1/session: the signed handshake. The agent sends
// its certificate (verified against the agent CA), a fresh ephemeral key and
// a signature by its static key; the reply carries the server's ephemeral key
// and a session id, signed by the responder.
func (a *agentAPI) session(w http.ResponseWriter, r *http.Request) {
	now := a.clock()
	body, ok := a.readBody(w, r, 1<<10)
	if !ok {
		return
	}
	if a.responder() == nil {
		Write(w, http.StatusServiceUnavailable, "Service unavailable", "The agent responder identity is not ready.")
		return
	}
	der, err := base64.StdEncoding.DecodeString(r.Header.Get(agentproto.HeaderAgentCert))
	if err != nil || len(der) == 0 || len(der) > 8<<10 {
		a.reject(w, http.StatusUnauthorized, agentproto.ErrCodeAuth)
		return
	}
	clientID, serial, pub, err := a.d.Agents.VerifyAgentCert(r.Context(), der)
	if err != nil {
		a.rejectErr(w, err, "")
		return
	}
	keyID := clientID.String() + ":" + serial
	p, err := a.verify(r, body, now, func(id string) (*ecdsa.PublicKey, error) {
		if id != keyID {
			return nil, agentproto.ErrSig
		}
		return pub, nil
	})
	if err != nil {
		a.reject(w, http.StatusUnauthorized, errCode(err))
		return
	}
	c, err := a.d.Agents.AuthenticateKey(r.Context(), clientID, serial)
	if err != nil {
		a.rejectErr(w, err, p.Nonce)
		return
	}
	if !a.checkFresh(w, p, now) {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(p.Ephemeral)
	peer, perr := ecdh.P256().NewPublicKey(raw)
	if err != nil || perr != nil {
		a.refuse(w, http.StatusBadRequest, "ephemeral", p.Nonce)
		return
	}
	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		a.rejectErr(w, err, p.Nonce)
		return
	}
	idRaw := make([]byte, 16)
	_, _ = rand.Read(idRaw)
	sess, err := agentproto.NewSession(local, peer, idRaw, false)
	if err != nil {
		a.rejectErr(w, err, p.Nonce)
		return
	}
	id := base64.RawURLEncoding.EncodeToString(idRaw)
	a.sessions.put(&agentSession{id: id, sess: sess, clientID: c.ID, serial: serial, pub: pub, created: now}, now)
	out, _ := json.Marshal(agentproto.SessionResponse{Session: id, Ephemeral: base64.StdEncoding.EncodeToString(local.PublicKey().Bytes()),
		ExpiresIn: agentproto.SessionTTLSeconds})
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	a.signResponse(h, http.StatusOK, out, p.Nonce)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func errCode(err error) string {
	if errors.Is(err, agentproto.ErrStale) {
		return agentproto.ErrCodeStale
	}
	return agentproto.ErrCodeAuth
}

// sealWriter buffers a handler's response so secure can seal and sign it.
type sealWriter struct {
	h      http.Header
	status int
	buf    bytes.Buffer
}

func (s *sealWriter) Header() http.Header { return s.h }
func (s *sealWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
}
func (s *sealWriter) Write(b []byte) (int, error) {
	s.WriteHeader(http.StatusOK)
	return s.buf.Write(b)
}

// secure admits only a request signed by an agent's key inside a live session
// (whatever the transport or client certificate), opens its body, and seals and
// signs whatever the handler answers, errors included.
func (a *agentAPI) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := a.clock()
		sess := a.sessions.get(r.Header.Get(agentproto.HeaderEphemeral), now)
		if sess == nil {
			a.reject(w, http.StatusUnauthorized, agentproto.ErrCodeSession)
			return
		}
		// Per client, not per address: a fleet behind one proxy shares an
		// address. 600 a minute is ten times the busiest agent's rate.
		if ok, wait := a.reqLim.Allow(sess.clientID.String()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			Write(w, http.StatusTooManyRequests, "Too many requests", "Wait before sending more requests.")
			return
		}
		body, ok := a.readBody(w, r, agentproto.MaxMessage+1024)
		if !ok {
			return
		}
		p, err := a.verify(r, body, now, func(id string) (*ecdsa.PublicKey, error) {
			if id != sess.keyID() {
				return nil, agentproto.ErrSig
			}
			return sess.pub, nil
		})
		if err != nil {
			a.reject(w, http.StatusUnauthorized, errCode(err))
			return
		}
		sw := &sealWriter{h: http.Header{}}
		c, err := a.d.Agents.AuthenticateKey(r.Context(), sess.clientID, sess.serial)
		if err != nil {
			a.rejectErr(w, err, p.Nonce)
			return
		}
		if !a.checkFresh(w, p, now) {
			return
		}
		pt := body
		if len(body) > 0 {
			seq, perr := strconv.ParseUint(r.Header.Get(agentproto.HeaderSeq), 10, 64)
			if perr == nil {
				pt, perr = sess.sess.OpenWindow(seq, body, agentproto.ReqExtra(sess.id, p.Nonce, r.Method, r.URL.RequestURI()))
			}
			if perr != nil {
				a.refuse(w, http.StatusUnauthorized, agentproto.ErrCodeSession, p.Nonce)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(pt))
		r.ContentLength = int64(len(pt))
		if len(pt) > 0 {
			r.Header.Set("Content-Type", "application/json")
		}
		ctx := authn.WithPrincipal(r.Context(), agents.AgentPrincipal(c))
		ctx = context.WithValue(ctx, agentClientKey{}, c)
		next.ServeHTTP(sw, r.WithContext(ctx))
		a.finish(w, r, sw, sess, p.Nonce)
	})
}

// finish seals sw's response under sess, signs it and writes it.
func (a *agentAPI) finish(w http.ResponseWriter, r *http.Request, sw *sealWriter, sess *agentSession, nonce string) {
	status := sw.status
	if status == 0 {
		status = http.StatusOK
	}
	out := sw.buf.Bytes()
	h := w.Header()
	for k, v := range sw.h {
		if k != "Content-Type" && k != "Content-Length" {
			h[k] = v
		}
	}
	if len(out) > 0 {
		seq, ct, err := sess.sess.Seal(out, agentproto.RespExtra(sess.id, nonce, status))
		if err != nil {
			a.refuse(w, http.StatusUnauthorized, agentproto.ErrCodeSession, nonce)
			return
		}
		out = ct
		h.Set(agentproto.HeaderSeq, strconv.FormatUint(seq, 10))
		h.Set("Content-Type", "application/octet-stream")
	}
	if !a.signResponse(h, status, out, nonce) {
		Write(w, http.StatusServiceUnavailable, "Service unavailable", "The agent responder identity is not ready.")
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(out)
}
