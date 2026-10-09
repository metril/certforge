//go:build integration

package api

import (
	"testing"

	"github.com/metril/certforge/internal/api/gen"
)

// Re-enrolling a client whose live grants carry a private key (key layout or
// any agent target) hands out a token that lets a new agent pull that key, so
// it needs keys:export, not just clients:write.
func TestReenrollKeyGrantNeedsKeysExport(t *testing.T) {
	f := newAgentFixture(t)
	op, admin := f.as("operator"), f.as("admin")
	certID, _ := f.currentCert(t, "web")
	plain := f.layout(t, "plain", "/etc/ssl/plain.pem")
	target := f.agentTarget(t, "traefik")
	cPlain, cKey := f.activeClient(t, "plain-1"), f.activeClient(t, "key-1")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: cPlain.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &plain}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.CreateGrant(admin, gen.CreateGrantRequestObject{OrgId: f.org, Id: cKey.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), DeployTargetId: &target}}); err != nil {
		t.Fatal(err)
	}
	_, err := f.srv.ReenrollClient(op, gen.ReenrollClientRequestObject{OrgId: f.org, Id: cKey.ID})
	wantStatus(t, err, 403)
	if _, err := f.srv.ReenrollClient(op, gen.ReenrollClientRequestObject{OrgId: f.org, Id: cPlain.ID}); err != nil {
		t.Fatalf("operator reenroll cert-only: %v", err)
	}
	if _, err := f.srv.ReenrollClient(admin, gen.ReenrollClientRequestObject{OrgId: f.org, Id: cKey.ID}); err != nil {
		t.Fatalf("admin reenroll: %v", err)
	}
}
