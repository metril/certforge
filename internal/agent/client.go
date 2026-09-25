package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

// Client talks to /agent/v1/* with the agent's certificate.
type Client struct {
	id   *Identity
	tr   *http.Transport
	hc   *http.Client // REST, with a timeout
	ws   *http.Client // WebSocket dial: coder/websocket refuses a client Timeout
	base string
}

// NewClient trusts id's CA bundle and presents id's current certificate.
// Both are read fresh from id on every handshake (VerifyConnection,
// GetClientCertificate), not captured once at construction, so a renewal
// (Renew) or a trust-bundle update (SaveBundle) applies to the next
// connection without rebuilding the client.
func NewClient(id *Identity) *Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Standard verification is replaced, not skipped: VerifyConnection
		// below checks the peer against id's live CA pool.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("agent: server sent no certificate")
			}
			_, pool := id.current()
			opts := x509.VerifyOptions{Roots: pool, DNSName: cs.ServerName, Intermediates: x509.NewCertPool()}
			for _, ic := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(ic)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c := id.TLSCertificate()
			return &c, nil
		},
	}, IdleConnTimeout: 90 * time.Second}
	return &Client{id: id, tr: tr, hc: &http.Client{Transport: tr, Timeout: 60 * time.Second},
		ws: &http.Client{Transport: tr}, base: strings.TrimRight(id.State.AgentURL, "/")}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
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
	c.tr.CloseIdleConnections() // kept-alive connections still carry the old certificate
	return nil
}

// Dial opens the agent WebSocket.
func (c *Client) Dial(ctx context.Context) (*websocket.Conn, error) {
	if !strings.HasPrefix(c.base, "https://") {
		return nil, fmt.Errorf("agent: agent URL %q is not https", c.base)
	}
	u := "wss" + strings.TrimPrefix(c.base, "https") + "/agent/v1/ws"
	conn, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: c.ws, CompressionMode: websocket.CompressionDisabled}) //nolint:bodyclose // coder/websocket owns resp.Body
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, &ProblemError{Status: http.StatusUnauthorized, Title: "Unauthorized"}
		}
		return nil, err
	}
	conn.SetReadLimit(1 << 20)
	return conn, nil
}
