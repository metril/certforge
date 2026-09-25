package agentproto

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestWSRoundTripAndCloseCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		s := WS{C: c}
		b, err := s.ReadMsg(r.Context())
		if err != nil {
			return
		}
		_ = s.WriteMsg(r.Context(), b)
		_ = s.Close(CloseRevoked, "revoked")
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // coder/websocket owns resp.Body
	if err != nil {
		t.Fatal(err)
	}
	cl := WS{C: c}
	msg, _ := Marshal(Sync{Revision: 7})
	if err := cl.WriteMsg(ctx, msg); err != nil {
		t.Fatal(err)
	}
	got, err := cl.ReadMsg(ctx)
	if err != nil || string(got) != string(msg) {
		t.Fatalf("echo %q %v", got, err)
	}
	if _, err := cl.ReadMsg(ctx); websocket.CloseStatus(err) != CloseRevoked {
		t.Fatalf("close status = %v (%v)", websocket.CloseStatus(err), err)
	}
}
