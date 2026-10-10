package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

// ProblemError is a non-2xx answer from the server.
type ProblemError struct {
	Status        int
	Title, Detail string
}

func (e *ProblemError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%d %s: %s", e.Status, e.Title, e.Detail)
	}
	return fmt.Sprintf("%d %s", e.Status, e.Title)
}

func problemError(resp *http.Response) error {
	var p struct{ Title, Detail string }
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = json.Unmarshal(b, &p)
	if p.Title == "" {
		p.Title = http.StatusText(resp.StatusCode)
	}
	return &ProblemError{Status: resp.StatusCode, Title: p.Title, Detail: p.Detail}
}

// IsUnauthorized reports a 401: revoked, re-enrolled or superseded.
func IsUnauthorized(err error) bool {
	var pe *ProblemError
	return errors.As(err, &pe) && pe.Status == http.StatusUnauthorized
}

// Client talks to /agent/v1/*: REST through the signed and sealed session
// protocol (secureTransport), the WebSocket through a signed upgrade and a
// sealed channel (Dial). The TLS layer underneath is hygiene only.
type Client struct {
	id   *Identity
	tr   *http.Transport
	st   *secureTransport
	hc   *http.Client // REST over the signed, sealed session protocol, with a timeout
	ws   *http.Client // WebSocket dial: coder/websocket refuses a client Timeout
	base string
}

// ClientOptions tune NewClientWith.
type ClientOptions struct {
	// Mode is TransportAuto (the default when empty), TransportMTLS or TransportProxy.
	Mode string
	// Roots replaces the operating system's roots for TransportProxy and the
	// fallback of TransportAuto (nil: the OS roots). For embedding and tests.
	Roots *x509.CertPool
}

// NewClient is NewClientWith with the default options.
func NewClient(id *Identity) *Client { return NewClientWith(id, ClientOptions{}) }

// NewClientWith trusts id's CA bundle where the mode says so. The bundle is
// read fresh from id on every handshake, not captured once at construction, so
// a renewal (Renew) or a trust-bundle update applies to the next connection
// without rebuilding the client.
func NewClientWith(id *Identity, o ClientOptions) *Client {
	mode, err := ParseTransport(o.Mode)
	if err != nil {
		mode = TransportAuto
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Standard verification is replaced, not skipped: VerifyConnection
		// below checks the peer according to the transport mode.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, pool := id.current()
			return verifyServerTLS(mode, cs, pool, o.Roots)
		},
	}, IdleConnTimeout: 90 * time.Second}
	st := NewSecureTransport(id, tr).(*secureTransport)
	return &Client{id: id, tr: tr, st: st, hc: &http.Client{Transport: st, Timeout: 60 * time.Second},
		ws: &http.Client{Transport: tr}, base: strings.TrimRight(id.State.AgentURL, "/")}
}

// verifyServerTLS decides whether a server's TLS certificate is acceptable.
// mtls trusts only the agent CA bundle (pin); proxy only the system roots
// (roots, or the OS roots when nil); auto uses the pin when the server presents
// a chain issued by an agent CA and the system roots otherwise. Nothing the
// application layer sends depends on the outcome: a hostile terminating proxy
// that passes this check still cannot read, forge or replay anything.
func verifyServerTLS(mode string, cs tls.ConnectionState, pin, roots *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("agent: server sent no certificate")
	}
	verify := func(rs *x509.CertPool, name string) error {
		opts := x509.VerifyOptions{Roots: rs, DNSName: name, Intermediates: x509.NewCertPool()}
		for _, ic := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(ic)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
	switch mode {
	case TransportMTLS:
		return verify(pin, cs.ServerName)
	case TransportProxy:
		return verify(roots, cs.ServerName)
	}
	if verify(pin, "") == nil { // an agent-CA chain: hold it to the pin, name included
		return verify(pin, cs.ServerName)
	}
	return verify(roots, cs.ServerName)
}

// busyBackoff is the first pause after the server answers 429 or 503; it
// doubles for each of busyRetries retries. A var so tests can shorten it.
var busyBackoff = time.Second

const busyRetries = 4

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
	}
	wait := busyBackoff
	for attempt := 0; ; attempt++ {
		err := c.doOnce(ctx, method, path, b, body != nil, out)
		if !errors.Is(err, errBusy) || attempt >= busyRetries {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
}

func (c *Client) doOnce(ctx context.Context, method, path string, b []byte, hasBody bool, out any) error {
	var rdr io.Reader
	if hasBody {
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return problemError(resp)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Assignments fetches the desired state.
func (c *Client) Assignments(ctx context.Context) (agentproto.Assignments, error) {
	var a agentproto.Assignments
	return a, c.do(ctx, http.MethodGet, "/agent/v1/assignments", nil, &a)
}

// Bundle fetches one grant's rendered files.
func (c *Client) Bundle(ctx context.Context, grantID uuid.UUID) (agentproto.Bundle, error) {
	var b agentproto.Bundle
	return b, c.do(ctx, http.MethodGet, "/agent/v1/grants/"+grantID.String()+"/bundle", nil, &b)
}

// Report sends deploy results over REST.
func (c *Client) Report(ctx context.Context, rep agentproto.Report) error {
	return c.do(ctx, http.MethodPost, "/agent/v1/report", rep, nil)
}

// Heartbeat sends installed digests over REST.
func (c *Client) Heartbeat(ctx context.Context, hb agentproto.Heartbeat) error {
	return c.do(ctx, http.MethodPost, "/agent/v1/heartbeat", hb, nil)
}

// Renew replaces the agent certificate (same key) and trust bundle.
func (c *Client) Renew(ctx context.Context) error {
	csr, err := csrPEM(c.id.Key)
	if err != nil {
		return err
	}
	var rr agentproto.RenewResponse
	if err := c.do(ctx, http.MethodPost, "/agent/v1/renew", agentproto.RenewRequest{CSR: string(csr)}, &rr); err != nil {
		return err
	}
	if err := c.id.saveCert([]byte(rr.Certificate), []byte(rr.TrustBundle)); err != nil {
		return err
	}
	c.st.reset()                // sessions are bound to the old certificate's serial
	c.tr.CloseIdleConnections() // kept-alive connections still carry the old certificate
	return nil
}

// Dial opens the agent WebSocket: a signed upgrade carrying a fresh ephemeral
// key, a first frame from the server that must be a hello_ack signed by a
// responder certificate chaining to the agent CA bundle over both ephemeral
// keys and this upgrade's nonce, and from then on only sealed frames. Anything
// else, a proxy's unsigned error page included, is a transport error: only a
// signed refusal (the same kind REST gets) says the agent is revoked.
func (c *Client) Dial(ctx context.Context) (*agentproto.SealedWS, error) {
	if !strings.HasPrefix(c.base, "https://") {
		return nil, fmt.Errorf("agent: agent URL %q is not https", c.base)
	}
	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyID, err := c.st.keyID()
	if err != nil {
		return nil, err
	}
	cert, _ := c.id.current()
	nonce, eph := agentproto.NewNonce(), base64.StdEncoding.EncodeToString(local.PublicKey().Bytes())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+agentproto.PathWS, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(agentproto.HeaderAgentCert, base64.StdEncoding.EncodeToString(cert.Raw))
	if err := agentproto.SignRequest(req, nil, c.id.Key, agentproto.ReqParams{Authority: agentproto.Authority(c.base), KeyID: keyID,
		Nonce: nonce, Created: c.st.now(), Ephemeral: eph}); err != nil {
		return nil, err
	}
	conn, resp, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(c.base, "https")+agentproto.PathWS, //nolint:bodyclose // coder/websocket owns resp.Body
		&websocket.DialOptions{HTTPClient: c.ws, HTTPHeader: req.Header, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		if resp != nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
			if c.st.verifyResponse(resp, raw, nonce) == nil && resp.Header.Get(agentproto.HeaderError) != "" {
				return nil, refusal(resp)
			}
		}
		return nil, err
	}
	conn.SetReadLimit(agentproto.MaxMessage + agentproto.FrameOverhead)
	sealed, err := c.handshakeWS(ctx, conn, local, eph, nonce)
	if err != nil {
		_ = conn.CloseNow()
		return nil, err
	}
	return sealed, nil
}

// handshakeWS reads and verifies the hello_ack and derives the session.
func (c *Client) handshakeWS(ctx context.Context, conn *websocket.Conn, local *ecdh.PrivateKey, eph, nonce string) (*agentproto.SealedWS, error) {
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	b, err := agentproto.WS{C: conn}.ReadMsg(rctx)
	if err != nil {
		return nil, err
	}
	m, err := agentproto.Unmarshal(b)
	ack, ok := m.(agentproto.HelloAck)
	if err != nil || !ok || len(ack.Chain) == 0 {
		return nil, fmt.Errorf("%w: the first frame is not a hello_ack", ErrUnsigned)
	}
	der, err := base64.StdEncoding.DecodeString(ack.Chain[0])
	if err != nil {
		return nil, ErrUnsigned
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrUnsigned
	}
	now := c.st.now()
	_, pool := c.id.current()
	pub, err := agentproto.VerifyResponder(leaf, pool, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsigned, err)
	}
	if err := agentproto.VerifyHelloAck(ack, pub, eph, nonce, now); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsigned, err)
	}
	raw, err := base64.StdEncoding.DecodeString(ack.Ephemeral)
	if err != nil {
		return nil, ErrUnsigned
	}
	peer, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, ErrUnsigned
	}
	salt, err := base64.RawURLEncoding.DecodeString(ack.Session)
	if err != nil || len(salt) == 0 {
		return nil, ErrUnsigned
	}
	sess, err := agentproto.NewSession(local, peer, salt, true)
	if err != nil {
		return nil, err
	}
	return agentproto.NewSealedWS(conn, sess, ack.Session), nil
}
