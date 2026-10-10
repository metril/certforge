//go:build integration

package api

import (
	"context"
	"crypto"
	"crypto/tls"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agenthub"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/challenge"
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
	ws := dialWS(ctx, t, e, cert)
	sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: "1.2.3", Hostname: "host-9", OS: "linux", Arch: "arm64", Capabilities: []string{"traefik"}})
	if m := recvWS(ctx, t, ws); m != agentproto.Message(agentproto.HelloAck{HeartbeatSeconds: 60, Revision: 0}) {
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
	if m := recvWS(ctx, t, ws); m != agentproto.Message(agentproto.Sync{Revision: 1}) {
		t.Fatalf("sync %#v", m)
	}
	ws2 := dialWS(ctx, t, e, cert)
	if _, err := ws.ReadMsg(ctx); websocket.CloseStatus(err) != agentproto.CloseReplaced {
		t.Fatalf("old socket: %v", err)
	}
	sendWS(ctx, t, ws2, agentproto.Heartbeat{})
	if _, err := e.svc.RevokeClient(e.as("operator"), e.org, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	if m := recvWS(ctx, t, ws2); m != agentproto.Message(agentproto.Revoked{}) {
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

// TestWebSocketRejectsStaleCertificateAfterRenew (M4): OnMessage re-checks
// the serial (via the same Authenticate requireAgent uses) on every
// message, not only at connect, so a certificate a renew replaces is
// refused mid-socket exactly as it already would be on a fresh REST
// request, instead of the socket trusting whatever certificate it opened
// under until something else eventually reconnects it.
func TestWebSocketRejectsStaleCertificateAfterRenew(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	en := e.newClient(t, "web-1")
	cert, _, code := e.enroll(t, en.Token)
	if code != http.StatusOK {
		t.Fatalf("enroll %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws := dialWS(ctx, t, e, cert)
	sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: "1.0", Hostname: "h", OS: "linux", Arch: "amd64"})
	recvWS(ctx, t, ws)
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew",
		agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, nil); code != http.StatusOK {
		t.Fatalf("renew %d", code)
	}
	sendWS(ctx, t, ws, agentproto.Heartbeat{})
	if _, err := ws.ReadMsg(ctx); websocket.CloseStatus(err) != agentproto.CloseRevoked {
		t.Fatalf("stale socket after renew: %v", err)
	}
}

func dialWS(ctx context.Context, t *testing.T, e *agentEnv, cert tls.Certificate) agentproto.WS {
	t.Helper()
	c, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(e.ts.URL, "https")+"/agent/v1/ws", //nolint:bodyclose // coder/websocket owns resp.Body
		&websocket.DialOptions{HTTPClient: e.plainClient(t, &cert)})
	if err != nil {
		t.Fatal(err)
	}
	return agentproto.WS{C: c}
}

func sendWS(ctx context.Context, t *testing.T, ws agentproto.WS, m agentproto.Message) {
	t.Helper()
	b, _ := agentproto.Marshal(m)
	if err := ws.WriteMsg(ctx, b); err != nil {
		t.Fatal(err)
	}
}

func recvWS(ctx context.Context, t *testing.T, ws agentproto.WS) agentproto.Message {
	t.Helper()
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

// TestWebSocketHeartbeatAndDeployResult covers the two remaining socket
// message kinds against the same service methods the REST endpoints use:
// deploy_result (a Report) settles the deployment and applies the
// revision, and heartbeat touches last_seen without regressing the state
// deploy_result already reported.
func TestWebSocketHeartbeatAndDeployResult(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	cert, c, gid := e.enrolledWithGrant(t, "web-2", false)
	// 30s, not 15s: the test chains two independent 5s wall-clock poll
	// loops below (deploy result, then heartbeat) on top of the hello/
	// assignments round trip, all sharing this one ctx. Under full-suite
	// load a 15s budget could run out while a poll loop was still legally
	// within its own 5s window, so a later ctx-bound call (GetClientByID)
	// would silently return a zero value instead of a real answer,
	// surfacing as a spurious "heartbeat did not update last_seen" failure
	// rather than a slow-poll timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ws := dialWS(ctx, t, e, cert)
	sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: "1"})
	if _, ok := recvWS(ctx, t, ws).(agentproto.HelloAck); !ok {
		t.Fatal("expected hello_ack")
	}
	hc := e.httpClient(t, &cert)
	var as agentproto.Assignments
	if code := e.get(t, hc, "/agent/v1/assignments", &as); code != http.StatusOK || len(as.Grants) != 1 {
		t.Fatalf("assignments %d %+v", code, as)
	}
	sendWS(ctx, t, ws, agentproto.DeployResult{Report: okReport(as)})
	deadline := time.Now().Add(5 * time.Second)
	for e.deploymentState(t, gid) != "ok" {
		if time.Now().After(deadline) {
			t.Fatalf("deploy_result over the socket did not apply: state %s", e.deploymentState(t, gid))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Report commits the deployment state and applied revision in one
	// transaction, then writes the audit event afterwards (a separate
	// insert): the state can legitimately read "ok" for a moment before
	// that audit row exists, so poll it too instead of checking once.
	deadline = time.Now().Add(5 * time.Second)
	for e.auditCount(t, "deployment.ok") != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("deployment.ok not audited: count %d", e.auditCount(t, "deployment.ok"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	cl, _ := e.q.GetClientByID(ctx, c.ID)
	if cl.AppliedRevision != 1 {
		t.Fatalf("applied revision %d", cl.AppliedRevision)
	}
	before := time.Now().Add(-time.Second)
	sendWS(ctx, t, ws, agentproto.Heartbeat{Installed: []agentproto.InstalledFile{
		{GrantID: gid, Path: as.Grants[0].Files[0].Path, SHA256: as.Grants[0].Files[0].SHA256, MTime: time.Now()},
	}})
	deadline = time.Now().Add(5 * time.Second)
	for {
		cl2, _ := e.q.GetClientByID(ctx, c.ID)
		if cl2.LastSeen != nil && !cl2.LastSeen.Before(before) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heartbeat over the socket did not update last_seen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.deploymentState(t, gid) != "ok" {
		t.Fatalf("heartbeat over the socket regressed deployment state: %s", e.deploymentState(t, gid))
	}
}

// TestWebSocketNonActiveClientMessageRejected isolates OnMessage's own
// rejection of a message from a client whose row is no longer active, from
// the hub's Close call an explicit RevokeClient already issues: the
// client's status is flipped directly in the database (RevokeClient would
// have proactively closed this same socket itself, so calling it here
// would never reach OnMessage with a still-open connection).
func TestWebSocketNonActiveClientMessageRejected(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	en := e.newClient(t, "web-3")
	cert, _, _ := e.enroll(t, en.Token)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws := dialWS(ctx, t, e, cert)
	sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: "1"})
	recvWS(ctx, t, ws)
	if _, err := e.pool.Exec(ctx, `UPDATE clients SET status = 'revoked' WHERE id = $1`, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	sendWS(ctx, t, ws, agentproto.Heartbeat{})
	if _, err := ws.ReadMsg(ctx); websocket.CloseStatus(err) != agentproto.CloseRevoked {
		t.Fatalf("close: %v", err)
	}
	for hub.Connected(en.Client.ID) {
		select {
		case <-ctx.Done():
			t.Fatal("still connected after a message from a non-active client")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestAgentChallengeOverWebSocket (Task 7): Service.Provider's Present
// sends challenge_present over the client's real socket, and the agent's
// challenge_ready reply (sent here by hand, standing in for Task 8's agent
// challenge server) resolves it.
func TestAgentChallengeOverWebSocket(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	en := e.newClient(t, "web-1")
	cert, _, _ := e.enroll(t, en.Token)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws := dialWS(ctx, t, e, cert)
	sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: "1", Capabilities: []string{"tls-alpn-01"}})
	if _, ok := recvWS(ctx, t, ws).(agentproto.HelloAck); !ok {
		t.Fatal("expected hello_ack")
	}

	p, err := e.svc.Provider(ctx, e.org, en.Client.ID, challenge.MethodTLSALPN01, "")
	if err != nil {
		t.Fatal(err)
	}
	present := make(chan error, 1)
	go func() { present <- p.Present(ctx, "example.test", "tok", "keyauth") }()

	m := recvWS(ctx, t, ws)
	cp, ok := m.(agentproto.ChallengePresent)
	if !ok || cp.Token != "tok" || cp.KeyAuth != "keyauth" || cp.Domain != "example.test" || cp.Method != "tls-alpn-01" {
		t.Fatalf("challenge_present %#v", m)
	}
	sendWS(ctx, t, ws, agentproto.ChallengeReady{Token: "tok"})
	if err := <-present; err != nil {
		t.Fatalf("present: %v", err)
	}
}

// TestWebSocketAcceptsLargeAgentMessage: an agent message above the old
// 1 MiB read limit (a deploy report carrying captured hook output for many
// grants) is read, not answered with a close.
func TestWebSocketAcceptsLargeAgentMessage(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	cert, _, _ := e.enrolledWithGrant(t, "web-big", false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ws := dialWS(ctx, t, e, cert)
	sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: strings.Repeat("v", 2<<20)})
	if _, ok := recvWS(ctx, t, ws).(agentproto.HelloAck); !ok {
		t.Fatal("expected hello_ack for a 2 MiB hello")
	}
}
