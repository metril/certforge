//go:build integration

package api

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agenthub"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
)

// failingReloader is an agents.Reloader that always fails, for
// TestRetireCAReloadFailure below.
type failingReloader struct{}

func (failingReloader) Reload(context.Context) error { return errors.New("listener boom") }

func TestAgentCARotateRetire(t *testing.T) {
	e := newAgentEnv(t)
	admin := e.as("admin")
	en := e.newClient(t, "web-1")
	cert, _, _ := e.enroll(t, en.Token)
	res, err := e.srv.ListAgentCAs(e.as("viewer"), gen.ListAgentCAsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	list := res.(gen.ListAgentCAs200JSONResponse)
	if len(list.Items) != 1 || string(list.Items[0].Status) != "active" || list.Items[0].ActiveClientCerts != 1 || len(list.Items[0].Fingerprint) != 64 ||
		list.Listener.CaId == nil || *list.Listener.CaId != list.Items[0].Id || !slices.Contains(list.Listener.Names, "127.0.0.1") {
		t.Fatalf("list %+v", list)
	}
	oldID := list.Items[0].Id
	_, err = e.srv.RotateAgentCA(e.as("operator"), gen.RotateAgentCARequestObject{})
	wantStatus(t, err, 403)
	rot, err := e.srv.RotateAgentCA(admin, gen.RotateAgentCARequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	next := rot.(gen.RotateAgentCA201JSONResponse)
	if next.Id == oldID || string(next.Status) != "active" {
		t.Fatalf("rotated %+v", next)
	}
	if len(e.hub.broadcasts) != 1 || strings.Count(e.hub.broadcasts[0].(agentproto.TrustBundleUpdate).Bundle, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("broadcasts %v", e.hub.broadcasts)
	}
	if info, _ := e.listener.Info(); info.CAID != oldID {
		t.Fatal("listener switched CA before the old one was retired")
	}
	// Rotate's reload already put the new CA into the listener's trust pool
	// (only the listener's own signing identity waits for retire), so an
	// agent enrolled right after the rotation completes a handshake against
	// this same running listener at once, without waiting for the hourly
	// listener-renew job.
	en2 := e.newClient(t, "web-2")
	cert2, _, code2 := e.enroll(t, en2.Token)
	if code2 != http.StatusOK {
		t.Fatalf("enrol under the new CA right after rotate: %d", code2)
	}
	if leaf, _ := x509.ParseCertificate(cert2.Certificate[0]); leaf == nil || leaf.Issuer.CommonName != next.Subject {
		t.Fatal("client enrolled right after rotate was not signed by the new CA")
	}
	if code := e.post(t, e.httpClient(t, &cert2), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, cert2.PrivateKey.(crypto.Signer))}, nil); code != http.StatusOK {
		t.Fatalf("handshake with a new-CA certificate right after rotate: %d", code)
	}
	_, err = e.srv.RetireAgentCA(admin, gen.RetireAgentCARequestObject{Id: oldID})
	wantStatus(t, err, 409)
	var rr agentproto.RenewResponse
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, &rr); code != http.StatusOK {
		t.Fatalf("renew with an old-CA certificate after rotation: %d", code)
	}
	blk, _ := pem.Decode([]byte(rr.Certificate))
	renewed, _ := x509.ParseCertificate(blk.Bytes)
	if renewed.Issuer.CommonName != next.Subject {
		t.Fatalf("renewed by %s, want %s", renewed.Issuer.CommonName, next.Subject)
	}
	ret, err := e.srv.RetireAgentCA(admin, gen.RetireAgentCARequestObject{Id: oldID})
	if err != nil || string(ret.(gen.RetireAgentCA200JSONResponse).Status) != "retired" {
		t.Fatalf("retire %v %v", ret, err)
	}
	if info, _ := e.listener.Info(); info.CAID != next.Id {
		t.Fatal("listener not re-issued by the new CA after retire")
	}
	// The retired CA is no longer trusted: its certificate fails the signed handshake.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, e.ts.URL+"/agent/v1/renew", nil)
	if resp, err := e.httpClient(t, &cert).Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("certificate from a retired CA passed the handshake: %d", resp.StatusCode)
	}
	fresh := tls.Certificate{Certificate: [][]byte{renewed.Raw}, PrivateKey: cert.PrivateKey}
	if code := e.post(t, e.httpClient(t, &fresh), "/agent/v1/renew", agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, nil); code != http.StatusOK {
		t.Fatalf("renew with the new-CA certificate after retire: %d", code)
	}
	_, err = e.srv.RetireAgentCA(admin, gen.RetireAgentCARequestObject{Id: next.Id})
	wantStatus(t, err, 409)
	_, err = e.srv.RetireAgentCA(admin, gen.RetireAgentCARequestObject{Id: uuid.New()})
	wantStatus(t, err, 404)
	if e.auditCount(t, "agent_ca.rotate") != 1 || e.auditCount(t, "agent_ca.retire") != 1 || len(e.hub.broadcasts) != 2 {
		t.Fatal("rotation audit or broadcast missing")
	}
}

// TestAgentCARotateRetireWithLiveAgent (M7) extends the rotate/retire
// coverage above with an agent that holds an open WebSocket over a real
// agenthub.Hub (TestAgentCARotateRetire uses a fake hub that only records
// broadcasts), through the whole rotate → renew → retire chain: the live
// socket receives the trust_bundle_update on rotate; docs/guide/agents.md says a
// connected agent renews immediately on that message, which this test does
// over REST with the old certificate (still trusted; only the listener's
// own signing identity waits for retire) — after which the client's
// agent_ca_id has moved off the old CA, retire succeeds, and a fresh
// socket dialled with the renewed certificate operates normally against
// the now-switched listener chain. The original socket's own next message,
// sent with the now-superseded certificate, is rejected (agents.OnMessage's
// per-message serial re-check, M4), matching what a real agent does next
// in practice: stop using the old connection and reconnect with the one
// it just renewed.
func TestAgentCARotateRetireWithLiveAgent(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	admin := e.as("admin")
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

	res, err := e.srv.ListAgentCAs(e.as("viewer"), gen.ListAgentCAsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	oldID := res.(gen.ListAgentCAs200JSONResponse).Items[0].Id
	rot, err := e.srv.RotateAgentCA(admin, gen.RotateAgentCARequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	next := rot.(gen.RotateAgentCA201JSONResponse)
	if m := recvWS(ctx, t, ws); m == nil {
		t.Fatal("live agent did not receive a message on rotate")
	} else if tb, ok := m.(agentproto.TrustBundleUpdate); !ok || strings.Count(tb.Bundle, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("expected a trust_bundle_update with both CAs, got %#v", m)
	}
	if _, err := e.srv.RetireAgentCA(admin, gen.RetireAgentCARequestObject{Id: oldID}); err == nil {
		t.Fatal("retire succeeded while the live agent's certificate still depends on the old CA")
	}
	var rr agentproto.RenewResponse
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew",
		agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, &rr); code != http.StatusOK {
		t.Fatalf("renew after trust_bundle_update: %d", code)
	}
	blk, _ := pem.Decode([]byte(rr.Certificate))
	renewed, _ := x509.ParseCertificate(blk.Bytes)
	renewedCert := tls.Certificate{Certificate: [][]byte{renewed.Raw}, PrivateKey: cert.PrivateKey}
	if _, err := e.srv.RetireAgentCA(admin, gen.RetireAgentCARequestObject{Id: oldID}); err != nil {
		t.Fatalf("retire after the live agent renewed: %v", err)
	}
	if info, _ := e.listener.Info(); info.CAID != next.Id {
		t.Fatal("listener not re-issued by the new CA after retire")
	}
	// Retire itself broadcasts a fresh trust bundle (without the retired
	// CA) to every connected socket, including this stale one; drain it
	// before checking the close below.
	if m := recvWS(ctx, t, ws); m == nil {
		t.Fatal("no trust bundle broadcast on retire")
	} else if _, ok := m.(agentproto.TrustBundleUpdate); !ok {
		t.Fatalf("expected a trust_bundle_update after retire, got %#v", m)
	}
	// The original socket's certificate no longer matches the client's
	// current serial: its next message is rejected and the socket closes.
	sendWS(ctx, t, ws, agentproto.Heartbeat{})
	if _, err := ws.ReadMsg(ctx); websocket.CloseStatus(err) != agentproto.CloseRevoked {
		t.Fatalf("stale socket after renew+retire: %v", err)
	}
	// A fresh socket dialled with the renewed certificate operates
	// normally against the now-switched listener chain.
	ws2 := dialWS(ctx, t, e, renewedCert)
	sendWS(ctx, t, ws2, agentproto.Hello{AgentVersion: "1.0", Hostname: "h", OS: "linux", Arch: "amd64"})
	if m := recvWS(ctx, t, ws2); m != agentproto.Message(agentproto.Welcome{HeartbeatSeconds: 60, Revision: 0}) {
		t.Fatalf("live agent could not reconnect after the chain switch: %#v", m)
	}
}

func TestAgentsSettingsPutReloadsListener(t *testing.T) {
	e := newAgentEnv(t)
	if err := agents.RegisterSettings(e.srv.d.Sections); err != nil {
		t.Fatal(err)
	}
	src, err := agents.NewSettingsSource(e.srv.d.Settings, e.srv.d.Sections, "https://cf.example.test")
	if err != nil {
		t.Fatal(err)
	}
	e.srv.d.AgentSettings, e.svc.Settings = src, src
	e.listener.Names = func(ctx context.Context) ([]string, error) {
		st, err := src.Get(ctx)
		return st.Names(), err
	}
	body := gen.SettingsValue{"agentUrl": "https://agents.example.test:9443", "listenerNames": []string{"cf.lan"}}
	if _, err := e.srv.PutSettingsSection(e.as("admin"), gen.PutSettingsSectionRequestObject{Section: "agents", Body: &body}); err != nil {
		t.Fatal(err)
	}
	if info, _ := e.listener.Info(); !slices.Equal(info.Names, []string{"cf.lan", "agents.example.test"}) {
		t.Fatalf("listener names %v", info.Names)
	}
	en := e.newClient(t, "web-1")
	if !strings.HasPrefix(en.AgentURL, "https://agents.example.test:9443") {
		t.Fatalf("token agent URL %s", en.AgentURL)
	}
}

// Review Focus: a retire whose listener reload fails must not broadcast a
// trust bundle for a listener that was never actually re-signed, but the
// retire itself (already committed to the database) must still be audited.
func TestRetireCAReloadFailure(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	old, err := f.svc.CA.EnsureActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.CA.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	f.svc.Listener = failingReloader{}
	if err := f.svc.RetireCA(ctx, old.ID); err == nil {
		t.Fatal("expected the listener reload failure to surface")
	}
	if got, err := f.ca.Get(ctx, old.ID); err != nil || got.Status != "retired" {
		t.Fatalf("the retire itself should have committed: %+v %v", got, err)
	}
	if len(f.hub.broadcasts) != 0 {
		t.Fatal("must not broadcast a trust bundle when the reload failed")
	}
	if f.auditCount(t, "agent_ca.retire") != 1 {
		t.Fatal("the retire audit event should still be recorded")
	}
}

// Review Focus: unlike retire, a rotate whose listener reload fails is
// harmless (the listener still serves its unchanged, still-trusted CA), so
// it only logs and the trust bundle still broadcasts and the rotate itself
// still succeeds.
func TestRotateCAReloadFailureStillBroadcasts(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CA.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	f.svc.Listener = failingReloader{}
	ca, err := f.svc.RotateCA(ctx)
	if err != nil {
		t.Fatalf("rotate should still succeed despite the reload failure: %v", err)
	}
	if ca == nil || ca.Status != "active" {
		t.Fatalf("rotate result %+v", ca)
	}
	if len(f.hub.broadcasts) != 1 {
		t.Fatal("rotate should still broadcast the trust bundle despite the reload failure")
	}
	if f.auditCount(t, "agent_ca.rotate") != 1 {
		t.Fatal("the rotate audit event should still be recorded")
	}
}

// After rotate, renew and retire, an agent holding the updated bundle still
// verifies the signed REST responses and the sealed hello_ack: the responder
// identity now chains to the new CA only.
func TestAgentCARotationKeepsSignedProtocolVerifying(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	admin := e.as("admin")
	cert, _, _ := e.enrolledWithGrant(t, "rot-1", false)

	res, err := e.srv.ListAgentCAs(e.as("viewer"), gen.ListAgentCAsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	oldID := res.(gen.ListAgentCAs200JSONResponse).Items[0].Id
	if _, err := e.srv.RotateAgentCA(admin, gen.RotateAgentCARequestObject{}); err != nil {
		t.Fatal(err)
	}
	var rr agentproto.RenewResponse
	if code := e.post(t, e.httpClient(t, &cert), "/agent/v1/renew",
		agentproto.RenewRequest{CSR: csrPEM(t, cert.PrivateKey.(crypto.Signer))}, &rr); code != http.StatusOK {
		t.Fatalf("renew %d", code)
	}
	blk, _ := pem.Decode([]byte(rr.Certificate))
	renewed, _ := x509.ParseCertificate(blk.Bytes)
	renewedCert := tls.Certificate{Certificate: [][]byte{renewed.Raw}, PrivateKey: cert.PrivateKey, Leaf: renewed}
	if _, err := e.srv.RetireAgentCA(admin, gen.RetireAgentCARequestObject{Id: oldID}); err != nil {
		t.Fatal(err)
	}
	if err := e.listener.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	// e.identity reads the CA bundle as it is now: the new CA alone.
	hc := secureClient(e.identity(t, renewedCert), e.httpClient(t, nil).Transport)
	if code, err := doAgent(hc, http.MethodGet, e.ts.URL+"/agent/v1/assignments", nil, &agentproto.Assignments{}); err != nil || code != http.StatusOK {
		t.Fatalf("signed REST after rotation: %d %v", code, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws := dialWS(ctx, t, e, renewedCert)
	sendWS(ctx, t, ws, agentproto.Hello{AgentVersion: "1.0", Hostname: "h", OS: "linux", Arch: "amd64"})
	if _, ok := recvWS(ctx, t, ws).(agentproto.Welcome); !ok {
		t.Fatal("hello_ack did not verify after rotation")
	}
}
