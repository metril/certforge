//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
)

func monitorInput(name, host string) *gen.MonitorInput {
	return &gen.MonitorInput{Name: name, Host: host}
}

// TestMonitorCRUDAndAuthz: full CRUD lifecycle with default values, plus
// the authz matrix (list/get need alerts:read; create/update/delete/check
// need alerts:write), and API-key scoping (same shape as
// TestChannelCRUD/TestChannelAuthzMatrix).
func TestMonitorCRUDAndAuthz(t *testing.T) {
	f := newMonitorFixture(t)

	res, err := f.srv.CreateMonitor(f.as("operator"), gen.CreateMonitorRequestObject{OrgId: f.org,
		Body: monitorInput("primary", "example.test")})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	created := res.(gen.CreateMonitor201JSONResponse)
	if created.Name != "primary" || created.Host != "example.test" {
		t.Fatalf("create = %+v", created)
	}
	if created.Port != 443 || created.IntervalSeconds != 3600 || !created.Enabled {
		t.Fatalf("defaults not applied: %+v", created)
	}
	if created.State != gen.Unknown {
		t.Fatalf("state = %q, want unknown", created.State)
	}
	if created.LastCheckedAt != nil || created.LastFingerprint != nil {
		t.Fatalf("fresh monitor already has check data: %+v", created)
	}
	if n := f.auditCount(t, "monitor.create"); n != 1 {
		t.Fatalf("monitor.create audit count = %d", n)
	}

	getRes, err := f.srv.GetMonitor(f.as("viewer"), gen.GetMonitorRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := gen.Monitor(getRes.(gen.GetMonitor200JSONResponse)); got.Id != created.Id {
		t.Fatalf("get = %+v", got)
	}

	listRes, err := f.srv.ListMonitors(f.as("viewer"), gen.ListMonitorsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if items := listRes.(gen.ListMonitors200JSONResponse); len(items) != 1 || items[0].Id != created.Id {
		t.Fatalf("list = %+v", items)
	}

	// A benign rename (name/enabled only, same host/port/sni/expectedCert)
	// must not touch state.
	renamed := monitorInput("primary-renamed", "example.test")
	updRes, err := f.srv.UpdateMonitor(f.as("operator"), gen.UpdateMonitorRequestObject{OrgId: f.org, Id: created.Id, Body: renamed})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	updated := updRes.(gen.UpdateMonitor200JSONResponse)
	if updated.Name != "primary-renamed" {
		t.Fatalf("update = %+v", updated)
	}
	if updated.State != gen.Unknown {
		t.Fatalf("state changed on a benign rename: %q", updated.State)
	}
	if n := f.auditCount(t, "monitor.update"); n != 1 {
		t.Fatalf("monitor.update audit count = %d", n)
	}

	if _, err := f.srv.DeleteMonitor(f.as("operator"), gen.DeleteMonitorRequestObject{OrgId: f.org, Id: created.Id}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n := f.auditCount(t, "monitor.delete"); n != 1 {
		t.Fatalf("monitor.delete audit count = %d", n)
	}
	_, err = f.srv.GetMonitor(f.as("viewer"), gen.GetMonitorRequestObject{OrgId: f.org, Id: created.Id})
	wantStatus(t, err, http.StatusNotFound)

	// ---- authz matrix ----
	seedRes, err := f.srv.CreateMonitor(f.as("admin"), gen.CreateMonitorRequestObject{OrgId: f.org, Body: monitorInput("seed", "seed.example.test")})
	if err != nil {
		t.Fatal(err)
	}
	seedID := seedRes.(gen.CreateMonitor201JSONResponse).Id
	missingID := uuid.New()

	canRead := map[string]bool{authz.RoleViewer: true, authz.RoleOperator: true, authz.RoleOrgAdmin: true, authz.RoleAdmin: true}
	canWrite := map[string]bool{authz.RoleViewer: false, authz.RoleOperator: true, authz.RoleOrgAdmin: true, authz.RoleAdmin: true}

	for _, role := range []string{authz.RoleViewer, authz.RoleOperator, authz.RoleOrgAdmin, authz.RoleAdmin} {
		ctx := f.as(role)

		_, err := f.srv.ListMonitors(ctx, gen.ListMonitorsRequestObject{OrgId: f.org})
		checkGate(t, role+"/list", err, canRead[role], http.StatusForbidden)

		_, err = f.srv.GetMonitor(ctx, gen.GetMonitorRequestObject{OrgId: f.org, Id: seedID})
		checkGate(t, role+"/get", err, canRead[role], http.StatusForbidden)

		_, err = f.srv.CreateMonitor(ctx, gen.CreateMonitorRequestObject{OrgId: f.org, Body: monitorInput("wh-"+role, role+".example.test")})
		checkGate(t, role+"/create", err, canWrite[role], http.StatusForbidden)

		_, err = f.srv.UpdateMonitor(ctx, gen.UpdateMonitorRequestObject{OrgId: f.org, Id: missingID, Body: monitorInput("x", "x.example.test")})
		checkGateEither(t, role+"/update", err, canWrite[role], http.StatusForbidden, http.StatusNotFound)

		_, err = f.srv.CheckMonitor(ctx, gen.CheckMonitorRequestObject{OrgId: f.org, Id: missingID})
		checkGateEither(t, role+"/check", err, canWrite[role], http.StatusForbidden, http.StatusNotFound)

		_, err = f.srv.DeleteMonitor(ctx, gen.DeleteMonitorRequestObject{OrgId: f.org, Id: missingID})
		checkGateEither(t, role+"/delete", err, canWrite[role], http.StatusForbidden, http.StatusNotFound)
	}

	roScoped := apiKeyPrincipal(f.org, []string{"alerts:read"})
	if _, err := f.srv.ListMonitors(roScoped, gen.ListMonitorsRequestObject{OrgId: f.org}); err != nil {
		t.Errorf("alerts:read key list: %v", err)
	}
	_, err = f.srv.CreateMonitor(roScoped, gen.CreateMonitorRequestObject{OrgId: f.org, Body: monitorInput("ro", "ro.example.test")})
	wantStatus(t, err, http.StatusForbidden)

	rwScoped := apiKeyPrincipal(f.org, []string{"alerts:write"})
	if _, err := f.srv.CreateMonitor(rwScoped, gen.CreateMonitorRequestObject{OrgId: f.org, Body: monitorInput("rw", "rw.example.test")}); err != nil {
		t.Errorf("alerts:write key create: %v", err)
	}
}

// TestUpdateResetsState: changing host resets state to unknown and
// nextCheckAt to now; changing only name/enabled does not (Shared
// contract, updateMonitor).
func TestUpdateResetsState(t *testing.T) {
	f := newMonitorFixture(t)
	res, err := f.srv.CreateMonitor(f.as("operator"), gen.CreateMonitorRequestObject{OrgId: f.org, Body: monitorInput("m", "old.example.test")})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateMonitor201JSONResponse).Id

	// Force the monitor into a non-unknown state with an old nextCheckAt,
	// as a real check would after its first run.
	past := time.Now().Add(-time.Hour)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE external_monitors SET state = 'ok', state_changed_at = now(), next_check_at = $2 WHERE id = $1`, id, past); err != nil {
		t.Fatal(err)
	}

	// A rename only: state and nextCheckAt survive untouched.
	renameOnly := monitorInput("m-renamed", "old.example.test")
	updRes, err := f.srv.UpdateMonitor(f.as("operator"), gen.UpdateMonitorRequestObject{OrgId: f.org, Id: id, Body: renameOnly})
	if err != nil {
		t.Fatal(err)
	}
	updated := updRes.(gen.UpdateMonitor200JSONResponse)
	if updated.State != gen.Ok {
		t.Fatalf("state after rename-only = %q, want ok (unchanged)", updated.State)
	}
	if updated.NextCheckAt == nil || updated.NextCheckAt.Sub(past).Abs() > time.Millisecond {
		t.Fatalf("nextCheckAt after rename-only = %v, want unchanged (~%v)", updated.NextCheckAt, past)
	}

	// A host change resets state to unknown and nextCheckAt to ~now.
	before := time.Now()
	hostChanged := monitorInput("m-renamed", "new.example.test")
	updRes, err = f.srv.UpdateMonitor(f.as("operator"), gen.UpdateMonitorRequestObject{OrgId: f.org, Id: id, Body: hostChanged})
	if err != nil {
		t.Fatal(err)
	}
	updated = updRes.(gen.UpdateMonitor200JSONResponse)
	if updated.State != gen.Unknown {
		t.Fatalf("state after host change = %q, want unknown", updated.State)
	}
	if updated.NextCheckAt == nil || updated.NextCheckAt.Before(before) {
		t.Fatalf("nextCheckAt after host change = %v, want >= %v", updated.NextCheckAt, before)
	}

	// A port change alone (same host) also resets.
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE external_monitors SET state = 'mismatch', state_changed_at = now(), next_check_at = $2 WHERE id = $1`, id, past); err != nil {
		t.Fatal(err)
	}
	portInput := &gen.MonitorInput{Name: "m-renamed", Host: "new.example.test", Port: ptr(8443)}
	updRes, err = f.srv.UpdateMonitor(f.as("operator"), gen.UpdateMonitorRequestObject{OrgId: f.org, Id: id, Body: portInput})
	if err != nil {
		t.Fatal(err)
	}
	updated = updRes.(gen.UpdateMonitor200JSONResponse)
	if updated.State != gen.Unknown {
		t.Fatalf("state after port change = %q, want unknown", updated.State)
	}
}
