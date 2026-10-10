package agentproto

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// MaxMessage caps one WebSocket message in either direction (the library's
// default is 1 MiB): a deploy report carries captured hook output for every
// grant, and an assignment or trust bundle can be large too. Both ends pass
// it (plus FrameOverhead) to SetReadLimit.
const MaxMessage = 8 << 20 // 8 MiB

// PathWS is the agent WebSocket. The upgrade request is signed like any other
// agent request, with the agent's ephemeral key in Cf-Ephemeral.
const PathWS = "/agent/v1/ws"

// FrameOverhead is what a sealed frame adds to its plaintext: the seq and the
// AEAD tag.
const FrameOverhead = 8 + 16

// rekeyMargin is how many messages before SessionMaxMessages a sender asks for
// a fresh socket (and so fresh session keys): reconnecting is the rekey.
const rekeyMargin = 16

// ErrFrame means a sealed frame was malformed, forged, replayed or out of order.
// The reader must drop the connection.
var ErrFrame = errors.New("agentproto: invalid sealed frame")

// WS adapts a coder/websocket connection to Conn. Messages are text, or
// binary when Binary is set (sealed frames); the other type is an error.
type WS struct {
	C      *websocket.Conn
	Binary bool
}

func (w WS) typ() websocket.MessageType {
	if w.Binary {
		return websocket.MessageBinary
	}
	return websocket.MessageText
}

// ReadMsg reads one message.
func (w WS) ReadMsg(ctx context.Context) ([]byte, error) {
	typ, b, err := w.C.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != w.typ() {
		return nil, errors.New("agentproto: unexpected WebSocket message type")
	}
	return b, nil
}

// WriteMsg writes one message.
func (w WS) WriteMsg(ctx context.Context, b []byte) error {
	return w.C.Write(ctx, w.typ(), b)
}

// Ping sends a ping and waits for the pong (a concurrent reader must run).
func (w WS) Ping(ctx context.Context) error { return w.C.Ping(ctx) }

// Close sends a close frame with code and reason.
func (w WS) Close(code int, reason string) error {
	return w.C.Close(websocket.StatusCode(code), reason)
}

// CloseNow drops the connection without a close handshake.
func (w WS) CloseNow() error { return w.C.CloseNow() }

// WSExtra is the AAD binding every frame of a socket to its session.
func WSExtra(session string) []byte { return []byte("ws\x00" + session) }

// SealedWS carries every message as a binary frame, seq (8 bytes, big endian)
// followed by the AEAD ciphertext, under the per-direction keys of a Session.
// Frames are opened strictly in order: a forged, replayed, dropped-then-later,
// reordered or tampered frame is an error and the caller must drop the
// connection. Close frames and pings are WebSocket control frames and carry no
// application data; they are not authenticated.
//
// Rekeying is by reconnecting: a session protects at most SessionMaxMessages
// per direction, so once a sender is within a few messages of it the near-cap
// callback fires (once) and the owner closes the socket; the agent dials again
// and a new handshake derives fresh keys.
type SealedWS struct {
	WS
	sess  *Session
	extra []byte

	wmu     sync.Mutex // Seal and the write must stay in seq order
	nearCap func()
	fired   bool
}

// NewSealedWS wraps c; session is the id from the hello_ack.
func NewSealedWS(c *websocket.Conn, sess *Session, session string) *SealedWS {
	return &SealedWS{WS: WS{C: c, Binary: true}, sess: sess, extra: WSExtra(session)}
}

// SetOnNearCap registers f, called once (from a writing goroutine) when this
// side has sent all but a few of the messages a session may carry. Set it
// before the socket is used.
func (s *SealedWS) SetOnNearCap(f func()) { s.nearCap = f }

// ReadMsg reads and opens the next frame.
func (s *SealedWS) ReadMsg(ctx context.Context) ([]byte, error) {
	b, err := s.WS.ReadMsg(ctx)
	if err != nil {
		return nil, err
	}
	if len(b) < FrameOverhead {
		return nil, ErrFrame
	}
	pt, err := s.sess.OpenInOrder(binary.BigEndian.Uint64(b[:8]), b[8:], s.extra)
	if err != nil {
		return nil, errors.Join(ErrFrame, err)
	}
	return pt, nil
}

// WriteMsg seals and writes one message. It fails with ErrSessionExhausted
// when the session has no messages left.
func (s *SealedWS) WriteMsg(ctx context.Context, b []byte) error {
	s.wmu.Lock()
	seq, ct, err := s.sess.Seal(b, s.extra)
	if err != nil {
		s.wmu.Unlock()
		return err
	}
	frame := binary.BigEndian.AppendUint64(make([]byte, 0, 8+len(ct)), seq)
	err = s.WS.WriteMsg(ctx, append(frame, ct...))
	fire := err == nil && !s.fired && seq+1 >= SessionMaxMessages-rekeyMargin && s.nearCap != nil
	if fire {
		s.fired = true
	}
	s.wmu.Unlock()
	if fire {
		s.nearCap()
	}
	return err
}

// helloTranscript is what the responder signs in a hello_ack.
func helloTranscript(agentEph, serverEph, session string) []byte {
	return []byte("certforge-ws-hello-v1\x00" + agentEph + "\x00" + serverEph + "\x00" + session)
}

// SignHelloAck fills a's Ephemeral-bound signature: the responder key signs
// both ephemeral keys, the session id and the upgrade request's nonce, so a
// proxy can neither splice in its own key nor replay an old hello_ack. a.Ephemeral
// and a.Session must be set.
func SignHelloAck(a *HelloAck, key *ecdsa.PrivateKey, agentEph, upgradeNonce string, now time.Time) error {
	h := http.Header{}
	body := helloTranscript(agentEph, a.Ephemeral, a.Session)
	if err := SignResponse(h, http.StatusSwitchingProtocols, body, key, RespParams{KeyID: "responder", ReqNonce: upgradeNonce, Created: now}); err != nil {
		return err
	}
	a.SignatureInput, a.Signature = h.Get(HeaderSignatureInput), h.Get(HeaderSignature)
	return nil
}

// VerifyHelloAck checks a against the responder's key and the agent's own
// ephemeral key and upgrade nonce.
func VerifyHelloAck(a HelloAck, pub *ecdsa.PublicKey, agentEph, upgradeNonce string, now time.Time) error {
	body := helloTranscript(agentEph, a.Ephemeral, a.Session)
	h := http.Header{}
	h.Set(HeaderSignatureInput, a.SignatureInput)
	h.Set(HeaderSignature, a.Signature)
	h.Set(HeaderContentDigest, ContentDigest(body))
	_, err := VerifyResponse(h, http.StatusSwitchingProtocols, body, upgradeNonce, now, pub)
	return err
}
