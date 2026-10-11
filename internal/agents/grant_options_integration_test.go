//go:build integration

package agents

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/delivery"
)

func optsJSON(s string) json.RawMessage { return json.RawMessage(s) }

func (f *syncFixture) grantOpts(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var b []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT target_options FROM client_cert_grants WHERE id = $1`, id).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGrantTargetOptionsAssignmentAndDigests(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	certID := f.cert(t, "web")
	f.setCurrent(t, certID, f.version(t, certID, 70, true))
	plainCert := f.cert(t, "plain")
	f.setCurrent(t, plainCert, f.version(t, plainCert, 71, true))
	tid := f.target(t, "traefik", delivery.TraefikConfig{Dir: "/etc/traefik/dynamic"})
	c := f.client(t, "c1")

	gid, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: certID, Delivery: "pull", TargetID: &tid, TargetOptions: optsJSON(`{"defaultCert":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: plainCert, Delivery: "pull", TargetID: &tid})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.grantOpts(t, pid); got != "{}" {
		t.Fatalf("plain grant options = %s", got)
	}
	cl, err := f.q.GetClientByID(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	asg, err := f.svc.Assignments(ctx, cl)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range asg.Grants {
		switch a.ID {
		case gid:
			if string(a.Target.GrantOptions) != `{"defaultCert": true}` && string(a.Target.GrantOptions) != `{"defaultCert":true}` {
				t.Fatalf("grantOptions = %s", a.Target.GrantOptions)
			}
		case pid:
			if len(a.Target.GrantOptions) != 0 {
				t.Fatalf("plain grantOptions = %s", a.Target.GrantOptions)
			}
		}
	}
	// Expected digests include the default-cert block.
	var specs string
	if err := f.pool.QueryRow(ctx, `SELECT expected::text FROM deployments WHERE grant_id = $1`, gid).Scan(&specs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(specs, "certforge-web.yml") {
		t.Fatalf("expected %s", specs)
	}
	m, err := f.certs.Material(ctx, certID, *mustCurrent(t, f, certID), true)
	if err != nil {
		t.Fatal(err)
	}
	mat, err := delivery.TargetMaterial(m)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"web.example.test"}
	for _, file := range delivery.RenderTraefik("web", names, delivery.TraefikConfig{Dir: "/etc/traefik/dynamic"}, delivery.TraefikGrantOptions{DefaultCert: true}, mat.Fullchain, mat.Key) {
		sp := delivery.Specs([]delivery.File{file})[0]
		if !strings.Contains(specs, sp.SHA256) {
			t.Fatalf("digest of %s missing from expected %s", file.Path, specs)
		}
	}

	// Update replaces options.
	if err := f.svc.UpdateGrant(ctx, f.org, gid, GrantInput{Delivery: "pull", TargetID: &tid, TargetOptions: optsJSON(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if got := f.grantOpts(t, gid); got != "{}" {
		t.Fatalf("after update options = %s", got)
	}
	if err := f.svc.UpdateGrant(ctx, f.org, gid, GrantInput{Delivery: "pull", TargetID: &tid, TargetOptions: optsJSON(`{"defaultCert":true}`)}); err != nil {
		t.Fatal(err)
	}
	if got := f.grantOpts(t, gid); !strings.Contains(got, "defaultCert") {
		t.Fatalf("after update options = %s", got)
	}
}

func mustCurrent(t *testing.T, f *syncFixture, certID uuid.UUID) *uuid.UUID {
	t.Helper()
	var v *uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT current_version_id FROM certificates WHERE id = $1`, certID).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
