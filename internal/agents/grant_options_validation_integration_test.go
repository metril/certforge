//go:build integration

package agents

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

func wantKind(t *testing.T, err error, kind Kind, field string) {
	t.Helper()
	var ae *Error
	if !errors.As(err, &ae) || ae.Kind != kind || ae.Field != field {
		t.Fatalf("err = %v, want kind %v field %q", err, kind, field)
	}
}

func TestGrantTargetOptionsValidation(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	a, b := f.cert(t, "a"), f.cert(t, "b")
	tid := f.target(t, "traefik", delivery.TraefikConfig{Dir: "/etc/traefik/dynamic"})
	ft := f.fileTarget(t, "file", t.TempDir(), nil)
	c := f.client(t, "c1")
	g := func(cert uuid.UUID, tgt *uuid.UUID, opts string) error {
		in := GrantInput{CertID: cert, Delivery: "pull", TargetID: tgt}
		if opts != "" {
			in.TargetOptions = optsJSON(opts)
		}
		_, err := f.svc.CreateGrant(ctx, f.org, c.ID, in)
		return err
	}

	wantKind(t, g(a, &ft, `{"defaultCert":true}`), KindInvalid, "targetOptions")
	wantKind(t, g(a, &tid, `{"bogus":1}`), KindInvalid, "targetOptions")
	wantKind(t, g(a, &tid, `{"certsDir":"/etc/traefik/dynamic"}`), KindInvalid, "targetOptions.certsDir")
	wantKind(t, g(a, &tid, `{"certsDir":"rel"}`), KindInvalid, "targetOptions.certsDir")
	if err := g(a, &tid, `{"certsDir":"/srv/tls"}`); err != nil {
		t.Fatal(err)
	}
	wantKind(t, g(b, &tid, `{"certsDir":"/srv/tls"}`), KindConflict, "")
	if err := g(b, &tid, `{}`); err != nil {
		t.Fatal(err)
	}
}

func TestGrantDefaultCertUniqueness(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	a, b, d := f.cert(t, "a"), f.cert(t, "b"), f.cert(t, "d")
	t1 := f.target(t, "t1", delivery.TraefikConfig{Dir: "/etc/traefik/dynamic"})
	t2 := f.target(t, "t2", delivery.TraefikConfig{Dir: "/etc/traefik/other"})
	c1, c2 := f.client(t, "c1"), f.client(t, "c2")
	create := func(c uuid.UUID, cert uuid.UUID, tgt uuid.UUID, opts string) (uuid.UUID, error) {
		return f.svc.CreateGrant(ctx, f.org, c, GrantInput{CertID: cert, Delivery: "pull", TargetID: &tgt, TargetOptions: optsJSON(opts)})
	}
	if _, err := create(c1.ID, a, t1, `{"defaultCert":true}`); err != nil {
		t.Fatal(err)
	}
	_, err := create(c1.ID, b, t1, `{"defaultCert":true}`)
	wantKind(t, err, KindConflict, "")
	if !strings.Contains(err.Error(), `Grants "a" and "b" on this client both set Traefik's default certificate for store "default" in /etc/traefik/dynamic. Only one grant may.`) {
		t.Fatalf("message: %v", err)
	}
	// another client, another dir, another store: fine
	if _, err := create(c2.ID, a, t1, `{"defaultCert":true}`); err != nil {
		t.Fatal(err)
	}
	if _, err := create(c1.ID, b, t2, `{"defaultCert":true}`); err != nil {
		t.Fatal(err)
	}
	gd, err := create(c1.ID, d, t1, `{"defaultCert":true,"stores":["internal"]}`)
	if err != nil {
		t.Fatal(err)
	}
	// update flipping a store onto the clash is refused
	wantKind(t, f.svc.UpdateGrant(ctx, f.org, gd, GrantInput{Delivery: "pull", TargetID: &t1, TargetOptions: optsJSON(`{"defaultCert":true}`)}), KindConflict, "")
	// and a grant without defaultCert flipped on is refused too
	gn, err := create(c1.ID, f.cert(t, "n"), t1, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	wantKind(t, f.svc.UpdateGrant(ctx, f.org, gn, GrantInput{Delivery: "pull", TargetID: &t1, TargetOptions: optsJSON(`{"defaultCert":true}`)}), KindConflict, "")
}

// A target PATCH that makes two default-certificate grants share a store is
// refused by the resync's checkPaths.
func TestTargetPatchDefaultCertConflict(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	a, b := f.cert(t, "a"), f.cert(t, "b")
	tid := f.target(t, "t1", delivery.TraefikConfig{Dir: "/etc/traefik/dynamic"})
	c := f.client(t, "c1")
	if _, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: a, Delivery: "pull", TargetID: &tid, TargetOptions: optsJSON(`{"defaultCert":true,"stores":["x"]}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: b, Delivery: "pull", TargetID: &tid, TargetOptions: optsJSON(`{"defaultCert":true}`)}); err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(delivery.TraefikConfig{Dir: "/etc/traefik/dynamic", Stores: []string{"x"}})
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := f.q.WithTx(tx)
	if _, err := q.UpdateDeployTarget(ctx, sqlcgen.UpdateDeployTargetParams{Name: "t1", Config: b2, ID: tid, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.Resync(ctx, q, RefTarget, tid)
	wantKind(t, err, KindConflict, "")
}
