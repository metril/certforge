package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
)

// fakeProtocol is the server half of the agent protocol for tests: the
// handshake, and a wrapper that verifies, opens, seals and signs for a mux of
// plain handlers. Enrol and the WebSocket stay outside it, as on the server.
type fakeProtocol struct {
	l  *agentca.Listener
	au string

	mu       sync.Mutex
	sessions map[string]*fakeSession
	// handshakes counts accepted handshakes; dropSessions forgets every
	// session once (the server restarted).
	handshakes int

	// enrol serves every /agent/v1/enroll* request (nil: 404).
	enrol http.HandlerFunc
}

type fakeSession struct {
	id  string
	s   *agentproto.Session
	pub *ecdsa.PublicKey
}

var fakeNonceRe = regexp.MustCompile(`;nonce="([^"]+)"`)

func (p *fakeProtocol) sign(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	m := fakeNonceRe.FindStringSubmatch(r.Header.Get(agentproto.HeaderSignatureInput))
	sg, _ := p.l.Responder()
	_ = agentproto.SignResponse(w.Header(), status, body, sg.Key, agentproto.RespParams{KeyID: "responder", ReqNonce: m[1], Created: time.Now()})
	w.Header().Set(agentproto.HeaderSignerCert, base64.StdEncoding.EncodeToString(sg.Chain[0].Raw))
}

func (p *fakeProtocol) handshake(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	der, _ := base64.StdEncoding.DecodeString(r.Header.Get(agentproto.HeaderAgentCert))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		http.Error(w, "cert", http.StatusUnauthorized)
		return
	}
	pub := leaf.PublicKey.(*ecdsa.PublicKey)
	rp, err := agentproto.VerifyRequest(r, body, p.au, time.Now(), func(string) (*ecdsa.PublicKey, error) { return pub, nil })
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	raw, _ := base64.StdEncoding.DecodeString(rp.Ephemeral)
	peer, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		http.Error(w, "ephemeral", http.StatusBadRequest)
		return
	}
	local, _ := ecdh.P256().GenerateKey(rand.Reader)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	s, _ := agentproto.NewSession(local, peer, salt, false)
	id := base64.RawURLEncoding.EncodeToString(salt)
	p.mu.Lock()
	p.sessions[id] = &fakeSession{id: id, s: s, pub: pub}
	p.handshakes++
	p.mu.Unlock()
	out, _ := json.Marshal(agentproto.SessionResponse{Session: id, Ephemeral: base64.StdEncoding.EncodeToString(local.PublicKey().Bytes()), ExpiresIn: 600})
	p.sign(w, r, http.StatusOK, out)
	_, _ = w.Write(out)
}

func (p *fakeProtocol) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		sess := p.sessions[r.Header.Get(agentproto.HeaderEphemeral)]
		p.mu.Unlock()
		if sess == nil {
			w.Header().Set(agentproto.HeaderError, agentproto.ErrCodeSession)
			p.sign(w, r, http.StatusUnauthorized, nil)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rp, err := agentproto.VerifyRequest(r, body, p.au, time.Now(), func(string) (*ecdsa.PublicKey, error) { return sess.pub, nil })
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if len(body) > 0 {
			seq, _ := strconv.ParseUint(r.Header.Get(agentproto.HeaderSeq), 10, 64)
			if body, err = sess.s.OpenWindow(seq, body, agentproto.ReqExtra(sess.id, rp.Nonce, r.Method, r.URL.RequestURI())); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		out := rec.Body.Bytes()
		for k, v := range rec.Header() {
			if k != "Content-Type" {
				w.Header()[k] = v
			}
		}
		if len(out) > 0 {
			seq, ct, _ := sess.s.Seal(out, agentproto.RespExtra(sess.id, rp.Nonce, rec.Code))
			out = ct
			w.Header().Set(agentproto.HeaderSeq, strconv.FormatUint(seq, 10))
		}
		p.sign(w, r, rec.Code, out)
		w.WriteHeader(rec.Code)
		_, _ = w.Write(out)
	})
}

// handler routes enrol and the WebSocket straight to mux, the handshake to
// the protocol, and everything else through it.
func (p *fakeProtocol) handler(mux http.Handler) http.Handler {
	secured := p.secure(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == agentproto.PathSession:
			p.handshake(w, r)
		case strings.HasPrefix(r.URL.Path, agentproto.PathEnroll):
			p.enrol(w, r)
		case strings.HasSuffix(r.URL.Path, "/ws"):
			mux.ServeHTTP(w, r)
		default:
			secured.ServeHTTP(w, r)
		}
	})
}

// fakeWS is the server end of an agent socket after the handshake, shaped like
// the websocket.Conn the older tests were written against.
type fakeWS struct {
	*agentproto.SealedWS
	// Raw is the underlying connection, for a hostile test that bypasses sealing.
	Raw *websocket.Conn
}

// Write seals and sends b (the message type is ignored: the channel is binary).
func (c *fakeWS) Write(ctx context.Context, _ websocket.MessageType, b []byte) error {
	return c.WriteMsg(ctx, b)
}

// Read opens the next frame.
func (c *fakeWS) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	b, err := c.ReadMsg(ctx)
	return websocket.MessageText, b, err
}

// wsRefuse answers the upgrade with a signed refusal (code "auth" for 401).
func (p *fakeProtocol) wsRefuse(w http.ResponseWriter, r *http.Request, status int) {
	m := fakeNonceRe.FindStringSubmatch(r.Header.Get(agentproto.HeaderSignatureInput))
	sg, _ := p.l.Responder()
	_ = agentproto.SignResponse(w.Header(), status, nil, sg.Key, agentproto.RespParams{KeyID: "responder", ReqNonce: m[1], Created: time.Now(), Error: agentproto.ErrCodeAuth})
	w.Header().Set(agentproto.HeaderSignerCert, base64.StdEncoding.EncodeToString(sg.Chain[0].Raw))
	w.WriteHeader(status)
}

// wsUpgrade verifies the signed upgrade, accepts it, sends the signed hello_ack
// and returns the sealed server end.
func (p *fakeProtocol) wsUpgrade(w http.ResponseWriter, r *http.Request) *fakeWS {
	der, _ := base64.StdEncoding.DecodeString(r.Header.Get(agentproto.HeaderAgentCert))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		http.Error(w, "cert", http.StatusUnauthorized)
		return nil
	}
	pub := leaf.PublicKey.(*ecdsa.PublicKey)
	rp, err := agentproto.VerifyRequest(r, nil, p.au, time.Now(), func(string) (*ecdsa.PublicKey, error) { return pub, nil })
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return nil
	}
	raw, _ := base64.StdEncoding.DecodeString(rp.Ephemeral)
	peer, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		http.Error(w, "ephemeral", http.StatusBadRequest)
		return nil
	}
	local, _ := ecdh.P256().GenerateKey(rand.Reader)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	sess, _ := agentproto.NewSession(local, peer, salt, false)
	sg, _ := p.l.Responder()
	ack := agentproto.HelloAck{Ephemeral: base64.StdEncoding.EncodeToString(local.PublicKey().Bytes()),
		Session: base64.RawURLEncoding.EncodeToString(salt),
		Chain:   []string{base64.StdEncoding.EncodeToString(sg.Chain[0].Raw), base64.StdEncoding.EncodeToString(sg.Chain[1].Raw)}}
	_ = agentproto.SignHelloAck(&ack, sg.Key, rp.Ephemeral, rp.Nonce, time.Now())
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil
	}
	c.SetReadLimit(agentproto.MaxMessage + agentproto.FrameOverhead)
	first, _ := agentproto.Marshal(ack)
	if err := (agentproto.WS{C: c}).WriteMsg(r.Context(), first); err != nil {
		return nil
	}
	return &fakeWS{SealedWS: agentproto.NewSealedWS(c, sess, ack.Session), Raw: c}
}
