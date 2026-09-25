//go:build integration

package api

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
)

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
	// The retired CA is gone from ClientCAs: its certificate fails the handshake.
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
