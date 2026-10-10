package agent

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/metril/certforge/internal/agentproto"
)

// ErrUnsigned means a response was not signed by the server's responder
// identity, or its body was not sealed: it is discarded, whatever its status.
var ErrUnsigned = errors.New("agent: response is not signed and sealed by the CertForge server")

// sessionRenewAfter retires a session a little before the server's own limit.
const sessionRenewAfter = 9 * time.Minute

// secureTransport speaks the agent protocol over base, which may be any
// transport, including one that runs through a TLS-terminating proxy: it opens
// a signed ephemeral-key session, seals and signs every request, and accepts
// only responses signed by a responder certificate chaining to the agent CA
// bundle that answer this very request, opening their sealed bodies. Nothing
// about the transport below it is trusted.
type secureTransport struct {
	id   *Identity
	base http.RoundTripper
	now  func() time.Time

	mu       sync.Mutex                // guards sessions, and serialises handshakes
	sessions map[string]*clientSession // by authority
}

type clientSession struct {
	id    string
	keyID string
	s     *agentproto.Session
	at    time.Time
}

// NewSecureTransport wraps base, which must already do TLS the way the
// deployment needs (system roots or the agent CA pin).
func NewSecureTransport(id *Identity, base http.RoundTripper) http.RoundTripper {
	return &secureTransport{id: id, base: base, now: time.Now, sessions: map[string]*clientSession{}}
}

func (t *secureTransport) keyID() (string, error) {
	cert, _ := t.id.current()
	cid, err := clientIDFromCert(cert)
	if err != nil {
		return "", err
	}
	return cid.String() + ":" + cert.SerialNumber.Text(16), nil
}

// RoundTrip performs req over a session, opening one first when needed and
// once more when the server says the session is gone.
func (t *secureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = b
	}
	au := agentproto.Authority(req.URL.String())
	for attempt := 0; ; attempt++ {
		cs, err := t.session(req, au)
		if err != nil {
			return refused(req, err)
		}
		resp, again, err := t.exchange(req, body, au, cs)
		if again && attempt == 0 {
			t.drop(au, cs)
			continue
		}
		if again {
			err = errors.New("agent: the server keeps refusing the session")
		}
		if err != nil {
			return refused(req, err)
		}
		return resp, nil
	}
}

// refused turns a verified refusal into the response callers expect (so a 401
// reads like any other 401); any other error passes through.
func refused(req *http.Request, err error) (*http.Response, error) {
	var pe *ProblemError
	if !errors.As(err, &pe) {
		return nil, err
	}
	b, _ := json.Marshal(map[string]any{"title": pe.Title, "status": pe.Status, "detail": pe.Detail})
	return &http.Response{Status: strconv.Itoa(pe.Status) + " " + pe.Title, StatusCode: pe.Status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"application/problem+json"}}, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: req}, nil
}

func (t *secureTransport) drop(au string, cs *clientSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessions[au] == cs {
		delete(t.sessions, au)
	}
}

// reset forgets every session (after a certificate renewal the keyid changes).
func (t *secureTransport) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = map[string]*clientSession{}
}

func (t *secureTransport) session(req *http.Request, au string) (*clientSession, error) {
	keyID, err := t.keyID()
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if cs := t.sessions[au]; cs != nil && cs.keyID == keyID && t.now().Sub(cs.at) < sessionRenewAfter {
		return cs, nil
	}
	cs, err := t.handshake(req, au, keyID)
	if err != nil {
		return nil, err
	}
	t.sessions[au] = cs
	return cs, nil
}

func (t *secureTransport) handshake(req *http.Request, au, keyID string) (*clientSession, error) {
	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	u := *req.URL
	u.Path, u.RawPath, u.RawQuery = agentproto.PathSession, "", ""
	hreq, err := http.NewRequestWithContext(req.Context(), http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, err
	}
	cert, _ := t.id.current()
	hreq.Header.Set(agentproto.HeaderAgentCert, base64.StdEncoding.EncodeToString(cert.Raw))
	nonce := agentproto.NewNonce()
	if err := agentproto.SignRequest(hreq, nil, t.id.Key, agentproto.ReqParams{Authority: au, KeyID: keyID, Nonce: nonce, Created: t.now(),
		Ephemeral: base64.StdEncoding.EncodeToString(local.PublicKey().Bytes())}); err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(hreq)
	if err != nil {
		return nil, err
	}
	raw, err := readResponse(resp)
	if err != nil {
		return nil, err
	}
	if isBusy(resp) {
		return nil, errBusy
	}
	if err := t.verifyResponse(resp, raw, nonce); err != nil {
		return nil, err // unsigned: a transport problem, whatever the status says
	}
	if resp.StatusCode != http.StatusOK {
		return nil, refusal(resp)
	}
	var sr agentproto.SessionResponse
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, fmt.Errorf("agent: handshake response: %w", err)
	}
	peerRaw, err := base64.StdEncoding.DecodeString(sr.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("agent: handshake response: %w", err)
	}
	peer, err := ecdh.P256().NewPublicKey(peerRaw)
	if err != nil {
		return nil, fmt.Errorf("agent: handshake response: %w", err)
	}
	salt, err := base64.RawURLEncoding.DecodeString(sr.Session)
	if err != nil || len(salt) == 0 {
		return nil, errors.New("agent: handshake response: bad session id")
	}
	s, err := agentproto.NewSession(local, peer, salt, true)
	if err != nil {
		return nil, err
	}
	return &clientSession{id: sr.Session, keyID: keyID, s: s, at: t.now()}, nil
}

// exchange sends one request in cs. again reports that the server no longer
// knows the session (or it ran out of messages), so a fresh one is needed.
func (t *secureTransport) exchange(req *http.Request, body []byte, au string, cs *clientSession) (resp *http.Response, again bool, err error) {
	nonce := agentproto.NewNonce()
	out := req.Clone(req.Context())
	wire := body
	if len(body) > 0 {
		seq, ct, serr := cs.s.Seal(body, agentproto.ReqExtra(cs.id, nonce, req.Method, req.URL.RequestURI()))
		if errors.Is(serr, agentproto.ErrSessionExhausted) {
			return nil, true, nil
		}
		if serr != nil {
			return nil, false, serr
		}
		wire = ct
		out.Header.Set(agentproto.HeaderSeq, strconv.FormatUint(seq, 10))
		out.Header.Set("Content-Type", "application/octet-stream")
	}
	out.Body, out.ContentLength = io.NopCloser(bytes.NewReader(wire)), int64(len(wire))
	out.GetBody = nil
	if err := agentproto.SignRequest(out, wire, t.id.Key, agentproto.ReqParams{Authority: au, KeyID: cs.keyID, Nonce: nonce, Created: t.now(), Ephemeral: cs.id}); err != nil {
		return nil, false, err
	}
	hr, err := t.base.RoundTrip(out)
	if err != nil {
		return nil, false, err
	}
	raw, err := readResponse(hr)
	if err != nil {
		return nil, false, err
	}
	code := hr.Header.Get(agentproto.HeaderError)
	// An unsigned 429 or 503 is the server shedding load. It says nothing about
	// the client, so it is only a hint to retry later.
	if isBusy(hr) {
		return nil, false, errBusy
	}
	if err := t.verifyResponse(hr, raw, nonce); err != nil {
		// An unverifiable "session" refusal (the server cannot sign for a
		// session it does not know) only buys one fresh handshake; it never
		// reaches the caller as a refusal.
		if code == agentproto.ErrCodeSession && hr.StatusCode == http.StatusUnauthorized && len(raw) == 0 {
			return nil, true, nil
		}
		return nil, false, err
	}
	if code == agentproto.ErrCodeSession && hr.StatusCode == http.StatusUnauthorized {
		return nil, true, nil
	}
	if code != "" {
		return nil, false, refusal(hr)
	}
	pt := raw
	if len(raw) > 0 {
		seq, perr := strconv.ParseUint(hr.Header.Get(agentproto.HeaderSeq), 10, 64)
		if perr != nil {
			return nil, false, ErrUnsigned
		}
		pt, err = cs.s.OpenWindow(seq, raw, agentproto.RespExtra(cs.id, nonce, hr.StatusCode))
		if err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrUnsigned, err)
		}
	}
	hr.Body, hr.ContentLength = io.NopCloser(bytes.NewReader(pt)), int64(len(pt))
	hr.Header.Del(agentproto.HeaderSeq)
	return hr, false, nil
}

func readResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, agentproto.MaxMessage+4096))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// isBusy reports an unsigned 429 or 503.
func isBusy(r *http.Response) bool {
	return (r.StatusCode == http.StatusTooManyRequests || r.StatusCode == http.StatusServiceUnavailable) && r.Header.Get(agentproto.HeaderSignerCert) == ""
}

// errBusy is an unsigned 429 or 503: retry after a pause.
var errBusy = errors.New("agent: the server is busy")

// refusal turns a verified, bodyless refusal into the error callers handle.
// Only a response whose signature covers Cf-Error and binds this request's
// nonce gets here, so a proxy cannot fake or alter a refusal and make the
// agent believe it was revoked. Clock and replay refusals are not 401s to
// the caller: they say nothing about the client.
func refusal(resp *http.Response) error {
	switch code := resp.Header.Get(agentproto.HeaderError); code {
	case agentproto.ErrCodeStale:
		return errors.New("agent: the server refused the request: the system clocks differ by more than a minute")
	case agentproto.ErrCodeReplay:
		return errors.New("agent: the server refused the request as a replay")
	default:
		return &ProblemError{Status: resp.StatusCode, Title: http.StatusText(resp.StatusCode), Detail: "refused by the server (" + code + ")"}
	}
}

// verifyResponse requires resp to be signed by a valid responder certificate
// for exactly the request that sent nonce, with an intact body.
func (t *secureTransport) verifyResponse(resp *http.Response, raw []byte, nonce string) error {
	der, err := base64.StdEncoding.DecodeString(resp.Header.Get(agentproto.HeaderSignerCert))
	if err != nil || len(der) == 0 {
		return ErrUnsigned
	}
	now := t.now()
	// Verified on every response, never cached: the responder certificate
	// expires in 24 h and the CA bundle can shrink under a long-lived client.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return ErrUnsigned
	}
	_, pool := t.id.current()
	pub, err := agentproto.VerifyResponder(leaf, pool, now)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsigned, err)
	}
	if _, err := agentproto.VerifyResponse(resp.Header, resp.StatusCode, raw, nonce, now, pub); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsigned, err)
	}
	return nil
}
