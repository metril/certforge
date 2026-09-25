//go:build integration

package api

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agenthub"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
)

func TestWebSocketHelloSyncRevoke(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	en := e.newClient(t, "web-1")
	cert, _, _ := e.enroll(t, en.Token)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dial := func() agentproto.WS {
		c, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(e.ts.URL, "https")+"/agent/v1/ws", //nolint:bodyclose // coder/websocket owns resp.Body
			&websocket.DialOptions{HTTPClient: e.httpClient(t, &cert)})
		if err != nil {
			t.Fatal(err)
		}
		return agentproto.WS{C: c}
	}
	send := func(ws agentproto.WS, m agentproto.Message) {
		b, _ := agentproto.Marshal(m)
		if err := ws.WriteMsg(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	recv := func(ws agentproto.WS) agentproto.Message {
		b, err := ws.ReadMsg(ctx)
		if err != nil {
			t.Fatal(err)
		}
		m, err := agentproto.Unmarshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ws := dial()
	send(ws, agentproto.Hello{AgentVersion: "1.2.3", Hostname: "host-9", OS: "linux", Arch: "arm64", Capabilities: []string{"traefik"}})
	if m := recv(ws); m != agentproto.Message(agentproto.HelloAck{HeartbeatSeconds: 60, Revision: 0}) {
		t.Fatalf("hello_ack %#v", m)
	}
	cl, _ := e.q.GetClientByID(ctx, en.Client.ID)
	if cl.AgentVersion != "1.2.3" || cl.Hostname != "host-9" || !slices.Equal(cl.Capabilities, []string{"traefik"}) {
		t.Fatalf("facts %+v", cl)
	}
	res, err := e.srv.GetClient(e.as("viewer"), gen.GetClientRequestObject{OrgId: e.org, Id: en.Client.ID})
	if err != nil || !res.(gen.GetClient200JSONResponse).Connected {
		t.Fatalf("connected %v %v", res, err)
	}
	certID, _ := e.currentCert(t, "web")
	layout := e.layout(t, "pem", "/etc/ssl/web.pem")
	if _, err := e.svc.CreateGrant(e.as("operator"), e.org, en.Client.ID, agents.GrantInput{CertID: certID, Delivery: "push", LayoutID: &layout}); err != nil {
		t.Fatal(err)
	}
	if m := recv(ws); m != agentproto.Message(agentproto.Sync{Revision: 1}) {
		t.Fatalf("sync %#v", m)
	}
	ws2 := dial()
	if _, err := ws.ReadMsg(ctx); websocket.CloseStatus(err) != agentproto.CloseReplaced {
		t.Fatalf("old socket: %v", err)
	}
	send(ws2, agentproto.Heartbeat{})
	if _, err := e.svc.RevokeClient(e.as("operator"), e.org, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	if m := recv(ws2); m != agentproto.Message(agentproto.Revoked{}) {
		t.Fatalf("revoked %#v", m)
	}
	if _, err := ws2.ReadMsg(ctx); websocket.CloseStatus(err) != agentproto.CloseRevoked {
		t.Fatalf("revoke close: %v", err)
	}
	for hub.Connected(en.Client.ID) {
		select {
		case <-ctx.Done():
			t.Fatal("still connected after revoke")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
