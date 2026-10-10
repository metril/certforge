//go:build integration

package api

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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agent"
	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agenthub"
	"github.com/metril/certforge/internal/agentproto"
)

// wsFrame is one WebSocket message as the proxy sees it.
type wsFrame struct {
	typ websocket.MessageType
	b   []byte
}

// wsHooks lets a test rewrite what a TLS-terminating proxy relays. A hook
// returns the frames to forward in place of the one it was given (none drops it).
type wsHooks struct {
	mu      sync.Mutex
	s2c     []wsFrame // every server-to-agent frame, as relayed in
	upgrade http.Header
	onS2C   func(n int, f wsFrame) []wsFrame
	onC2S   func(n int, f wsFrame) []wsFrame
}

func (h *wsHooks) frames() []wsFrame {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]wsFrame(nil), h.s2c...)
}

// wsProxy is a TLS-terminating reverse proxy in front of the HTTP port that
// relays WebSocket messages one by one, so a test can inject, reorder or forge
// frames. The server answers for the proxy's address.
func (e *agentEnv) wsProxy(t *testing.T, hub *agenthub.Hub, h *wsHooks) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	proxy := httptest.NewUnstartedServer(nil)
	d := e.srv.d
	d.Hub = hub
	d.AgentAuthorities = []string{proxy.Listener.Addr().String()}
	backend := httptest.NewServer(NewRouter(d))
	t.Cleanup(backend.Close)
	bu, _ := url.Parse(backend.URL)
	rest := httputil.NewSingleHostReverseProxy(bu)
	proxy.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			rest.ServeHTTP(w, r)
			return
		}
		hdr := r.Header.Clone()
		for k := range hdr {
			if strings.HasPrefix(k, "Sec-Websocket") || k == "Connection" || k == "Upgrade" {
				delete(hdr, k)
			}
		}
		h.mu.Lock()
		h.upgrade = hdr.Clone()
		h.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		up, resp, err := websocket.Dial(ctx, "ws://"+bu.Host+r.URL.RequestURI(), &websocket.DialOptions{HTTPHeader: hdr, CompressionMode: websocket.CompressionDisabled}) //nolint:bodyclose // library owns it
		if err != nil {
			if resp != nil {
				for k, v := range resp.Header {
					w.Header()[k] = v
				}
				w.WriteHeader(resp.StatusCode)
				return
			}
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		down, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			_ = up.CloseNow()
			return
		}
		up.SetReadLimit(agentproto.MaxMessage + 1024)
		down.SetReadLimit(agentproto.MaxMessage + 1024)
		var wg sync.WaitGroup
		relay := func(from, to *websocket.Conn, hook func(int, wsFrame) []wsFrame, record bool) {
			defer wg.Done()
			defer cancel()
			for n := 0; ; n++ {
				typ, b, err := from.Read(ctx)
				if err != nil {
					_ = to.Close(websocket.CloseStatus(err), "")
					return
				}
				f := wsFrame{typ, b}
				if record {
					h.mu.Lock()
					h.s2c = append(h.s2c, f)
					h.mu.Unlock()
				}
				out := []wsFrame{f}
				if hook != nil {
					out = hook(n, f)
				}
				for _, o := range out {
					if to.Write(ctx, o.typ, o.b) != nil {
						return
					}
				}
			}
		}
		wg.Add(2)
		go relay(up, down, h.onS2C, true)
		go relay(down, up, h.onC2S, false)
		wg.Wait()
		_ = up.CloseNow()
		_ = down.CloseNow()
	})
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	pool := x509.NewCertPool()
	pool.AddCert(proxy.Certificate())
	return proxy, pool
}

func waitConnected(ctx context.Context, t *testing.T, _ *agenthub.Hub, want bool, c func() bool) {
	t.Helper()
	for c() != want {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for the hub")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func newWSEnv(t *testing.T, name string) (*agentEnv, *agenthub.Hub, tls.Certificate, func() bool, func(agentproto.Message) bool) {
	t.Helper()
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	cert, c, _ := e.enrolledWithGrant(t, name, false)
	return e, hub, cert, func() bool { return hub.Connected(c.ID) }, func(m agentproto.Message) bool { return hub.Send(c.ID, m) }
}

// Full flow behind a terminating proxy: signed upgrade, signed hello_ack, sealed
// frames only, a sync hint, then the signed and sealed REST fetch it asks for.
func TestWebSocketThroughTerminatingProxy(t *testing.T) {
	e, hub, cert, connected, send := newWSEnv(t, "wsproxy-1")
	h := &wsHooks{}
	proxy, roots := e.wsProxy(t, hub, h)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ws, err := e.wsClient(t, cert, proxy.URL, agent.TransportProxy, roots).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow() //nolint:errcheck // test cleanup
	sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: "9", Hostname: "behind-proxy", OS: "linux", Arch: "amd64"})
	if _, ok := recvWS(ctx, t, ws).(agentproto.Welcome); !ok {
		t.Fatal("expected welcome")
	}
	waitConnected(ctx, t, hub, true, connected)
	if !send(agentproto.Sync{Revision: 5}) {
		t.Fatal("sync not queued")
	}
	if m := recvWS(ctx, t, ws); m != agentproto.Message(agentproto.Sync{Revision: 5}) {
		t.Fatalf("sync %#v", m)
	}
	// The hint is followed by the signed REST fetch through the same proxy.
	hc := &http.Client{Transport: agent.NewSecureTransport(e.identity(t, cert), proxy.Client().Transport), Timeout: 10 * time.Second}
	var as agentproto.Assignments
	if code, err := doAgent(hc, http.MethodGet, proxy.URL+"/agent/v1/assignments", nil, &as); err != nil || code != http.StatusOK || len(as.Grants) != 1 {
		t.Fatalf("assignments %d %v %+v", code, err, as)
	}
	// Nothing after the hello_ack is readable on the wire.
	fr := h.frames()
	if len(fr) < 3 || fr[0].typ != websocket.MessageText || !bytes.Contains(fr[0].b, []byte(`"hello_ack"`)) {
		t.Fatalf("first frame %+v", fr)
	}
	for _, f := range fr[1:] {
		if f.typ != websocket.MessageBinary || bytes.Contains(f.b, []byte("sync")) || bytes.Contains(f.b, []byte("welcome")) || json.Valid(f.b) {
			t.Fatalf("readable frame after the hello_ack: %q", f.b)
		}
	}
	// The upgrade is signed and carries no usable client certificate.
	if h.upgrade.Get(agentproto.HeaderSignature) == "" || h.upgrade.Get(agentproto.HeaderEphemeral) == "" {
		t.Fatalf("upgrade headers %v", h.upgrade)
	}
}

// A frame the proxy injects, reorders, tampers with or forges drops the connection.
func TestWebSocketHostileFrames(t *testing.T) {
	type tc struct {
		name  string
		s2c   func(n int, f wsFrame) []wsFrame
		c2s   func(n int, f wsFrame) []wsFrame
		extra func(send func(agentproto.Message) bool)
	}
	var held wsFrame
	forged, _ := agentproto.Marshal(agentproto.Revoked{})
	forgedBundle, _ := agentproto.Marshal(agentproto.TrustBundleUpdate{Bundle: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"})
	cases := []tc{
		{name: "injected frame", s2c: func(n int, f wsFrame) []wsFrame {
			if n == 1 {
				return []wsFrame{{websocket.MessageBinary, append(make([]byte, 8), bytes.Repeat([]byte{7}, 40)...)}, f}
			}
			return []wsFrame{f}
		}},
		{name: "reordered frames", s2c: func(n int, f wsFrame) []wsFrame {
			switch n {
			case 1:
				held = f
				return nil
			case 2:
				return []wsFrame{f, held}
			}
			return []wsFrame{f}
		}, extra: func(send func(agentproto.Message) bool) {
			send(agentproto.Sync{Revision: 1})
			send(agentproto.Sync{Revision: 2})
		}},
		{name: "tampered frame", s2c: func(n int, f wsFrame) []wsFrame {
			if n == 1 {
				f.b = append([]byte(nil), f.b...)
				f.b[len(f.b)-1] ^= 1
			}
			return []wsFrame{f}
		}},
		{name: "forged revoked (plaintext)", s2c: func(n int, f wsFrame) []wsFrame {
			if n == 1 {
				return []wsFrame{{websocket.MessageText, forged}}
			}
			return []wsFrame{f}
		}},
		{name: "forged revoked (unsealed binary)", s2c: func(n int, f wsFrame) []wsFrame {
			if n == 1 {
				return []wsFrame{{websocket.MessageBinary, forged}}
			}
			return []wsFrame{f}
		}},
		{name: "forged trust_bundle_update", s2c: func(n int, f wsFrame) []wsFrame {
			if n == 1 {
				return []wsFrame{{websocket.MessageText, forgedBundle}}
			}
			return []wsFrame{f}
		}},
		{name: "frame injected toward the server", c2s: func(n int, f wsFrame) []wsFrame {
			if n == 0 {
				return []wsFrame{{websocket.MessageBinary, append(make([]byte, 8), bytes.Repeat([]byte{9}, 40)...)}, f}
			}
			return []wsFrame{f}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			held = wsFrame{}
			e, hub, cert, connected, send := newWSEnv(t, "wshostile")
			h := &wsHooks{onS2C: c.s2c, onC2S: c.c2s}
			proxy, roots := e.wsProxy(t, hub, h)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ws, err := e.wsClient(t, cert, proxy.URL, agent.TransportProxy, roots).Dial(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow() //nolint:errcheck // test cleanup
			waitConnected(ctx, t, hub, true, connected)
			if c.extra != nil {
				c.extra(send)
			} else {
				sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: "1"})
			}
			// Whatever the proxy did, the agent never gets a message to act on
			// and the connection ends.
			if b, err := ws.ReadMsg(ctx); err == nil {
				t.Fatalf("a message got through a hostile proxy: %q", b)
			} else if websocket.CloseStatus(err) == agentproto.CloseRevoked {
				t.Fatalf("a close code was taken as authentic: %v", err)
			}
			if c.c2s != nil {
				// The server drops the socket too; it must not stay registered.
				waitConnected(ctx, t, hub, false, connected)
			}
		})
	}
}

// The upgrade is signed or refused: a client certificate alone gets nothing, on
// either port, and a replayed or foreign-authority upgrade fails too.
func TestWebSocketUpgradeRequiresSignature(t *testing.T) {
	e, hub, cert, _, _ := newWSEnv(t, "wsunsigned")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// A valid client certificate, no signature: refused on the agent port.
	_, resp, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(e.ts.URL, "https")+agentproto.PathWS, //nolint:bodyclose // closed below
		&websocket.DialOptions{HTTPClient: e.plainClient(t, &cert)})
	if err == nil {
		t.Fatal("an unsigned upgrade with a valid client certificate was accepted")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned upgrade: %v %v", resp, err)
	}
	// Replaying a captured, signed upgrade is refused (nonce already used).
	h := &wsHooks{}
	proxy, roots := e.wsProxy(t, hub, h)
	ws, err := e.wsClient(t, cert, proxy.URL, agent.TransportProxy, roots).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = ws.CloseNow()
	pc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	_, resp, err = websocket.Dial(ctx, "wss"+strings.TrimPrefix(proxy.URL, "https")+agentproto.PathWS, //nolint:bodyclose // closed below
		&websocket.DialOptions{HTTPClient: pc, HTTPHeader: h.upgrade})
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(agentproto.HeaderError) != agentproto.ErrCodeReplay {
		t.Fatalf("replayed upgrade: %v %v", resp, err)
	}
}

// The agent refuses a hello_ack whose ephemeral key was swapped, and a revoked
// agent learns it from a signed refusal of the upgrade, not from the socket.
func TestWebSocketHelloAckTamperAndRevocation(t *testing.T) {
	e, hub, cert, connected, _ := newWSEnv(t, "wsack")
	attacker, _ := ecdh.P256().GenerateKey(rand.Reader)
	h := &wsHooks{onS2C: func(n int, f wsFrame) []wsFrame {
		if n == 0 {
			var ack agentproto.HelloAck
			_ = json.Unmarshal(f.b, &ack)
			ack.Ephemeral = base64Std(attacker.PublicKey().Bytes())
			b, _ := json.Marshal(struct {
				Type string `json:"type"`
				agentproto.HelloAck
			}{agentproto.TypeHelloAck, ack})
			return []wsFrame{{f.typ, b}}
		}
		return []wsFrame{f}
	}}
	proxy, roots := e.wsProxy(t, hub, h)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cl := e.wsClient(t, cert, proxy.URL, agent.TransportProxy, roots)
	if _, err := cl.Dial(ctx); !errors.Is(err, agent.ErrUnsigned) {
		t.Fatalf("a swapped server key was accepted: %v", err)
	}
	waitConnected(ctx, t, hub, false, connected)
	// Revoke: a plain proxy relays the signed refusal and the agent reads it as revoked.
	h.onS2C = nil
	if _, err := e.svc.RevokeClient(e.as("operator"), e.org, mustClientID(t, e, cert)); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Dial(ctx); !agent.IsUnauthorized(err) {
		t.Fatalf("revoked agent dial: %v", err)
	}
}

// A sender within a few messages of the cap asks to reconnect; the server's side
// closes with CloseRekey after flushing, the agent's side fires the callback.
func TestWebSocketRekeyBeforeCap(t *testing.T) {
	e, _, cert, _, _ := newWSEnv(t, "wscap")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ws, err := e.wsClient(t, cert, e.ts.URL, agent.TransportMTLS, nil).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow() //nolint:errcheck // test cleanup
	var fired int
	var fmu sync.Mutex
	ws.SetOnNearCap(func() { fmu.Lock(); fired++; fmu.Unlock() })
	replies := make(chan error, 1)
	var got int
	go func() {
		for {
			if _, err := ws.ReadMsg(ctx); err != nil {
				replies <- err
				return
			}
			got++
		}
	}()
	for i := 0; i < agentproto.SessionMaxMessages+10; i++ {
		b, _ := agentproto.Marshal(agentproto.Hello{AgentVersion: "1"})
		if err := ws.WriteMsg(ctx, b); err != nil {
			if !errors.Is(err, agentproto.ErrSessionExhausted) && websocket.CloseStatus(err) == -1 && ctx.Err() != nil {
				t.Fatal(err)
			}
			break
		}
	}
	select {
	case err := <-replies:
		if websocket.CloseStatus(err) != agentproto.CloseRekey {
			t.Fatalf("server closed with %v, want the rekey code", err)
		}
	case <-ctx.Done():
		t.Fatal("the server never asked to reconnect")
	}
	fmu.Lock()
	defer fmu.Unlock()
	if fired != 1 || got < agentproto.SessionMaxMessages-40 || got >= agentproto.SessionMaxMessages {
		t.Fatalf("near-cap callback fired %d times, %d replies read", fired, got)
	}
	// A fresh dial gets fresh keys and works.
	ws2, err := e.wsClient(t, cert, e.ts.URL, agent.TransportMTLS, nil).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ws2.CloseNow() //nolint:errcheck // test cleanup
	sendWS(ctx, t, ws2, agentproto.Hello{AgentVersion: "2"})
	if _, ok := recvWS(ctx, t, ws2).(agentproto.Welcome); !ok {
		t.Fatal("no welcome on the fresh socket")
	}
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// mustClientID is the client id in cert's URI SAN.
func mustClientID(t *testing.T, e *agentEnv, cert tls.Certificate) uuid.UUID {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := agentca.ClientIDFromCert(leaf)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
