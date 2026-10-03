package agentproto

import (
	"context"
	"errors"

	"github.com/coder/websocket"
)

// MaxMessage caps one WebSocket message in either direction (the library's
// default is 1 MiB): a deploy report carries captured hook output for every
// grant, and an assignment or trust bundle can be large too. Both ends pass
// it to SetReadLimit.
const MaxMessage = 8 << 20 // 8 MiB

// WS adapts a coder/websocket connection to Conn. Only text messages are
// part of the protocol; a binary message is an error.
type WS struct{ C *websocket.Conn }

// ReadMsg reads one text message.
func (w WS) ReadMsg(ctx context.Context) ([]byte, error) {
	typ, b, err := w.C.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageText {
		return nil, errors.New("agentproto: binary WebSocket message")
	}
	return b, nil
}

// WriteMsg writes one text message.
func (w WS) WriteMsg(ctx context.Context, b []byte) error {
	return w.C.Write(ctx, websocket.MessageText, b)
}

// Ping sends a ping and waits for the pong (a concurrent reader must run).
func (w WS) Ping(ctx context.Context) error { return w.C.Ping(ctx) }

// Close sends a close frame with code and reason.
func (w WS) Close(code int, reason string) error {
	return w.C.Close(websocket.StatusCode(code), reason)
}
