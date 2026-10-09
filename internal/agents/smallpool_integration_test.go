//go:build integration

package agents

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

// onePool returns a service over a single-connection pool: any read through
// the pool while a transaction holds that connection deadlocks.
func onePool(t *testing.T, f *syncFixture) *Service {
	t.Helper()
	cfg := f.pool.Config()
	cfg.MaxConns = 1
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	svc := &Service{Pool: p, Q: sqlcgen.New(p), CA: agentca.NewStore(p, f.box), Certs: certstore.New(p, f.box), Box: f.box, Log: f.svc.Log, Reg: f.svc.Reg, Settings: f.svc.Settings}
	return svc
}

func TestOnVersionDoesNotNeedSecondConnection(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	certID := f.cert(t, "pool1")
	f.setCurrent(t, certID, f.version(t, certID, 1, true))
	targetID := f.target(t, "pool1-target", delivery.TraefikConfig{Dir: "/etc/traefik/dynamic"})
	c := f.client(t, "pool-1")
	gid, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: certID, Delivery: "pull", TargetID: &targetID})
	if err != nil {
		t.Fatal(err)
	}
	before := f.expected(t, gid)
	v2 := f.version(t, certID, 2, true)
	f.setCurrent(t, certID, v2)

	svc := onePool(t, f)
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	svc.OnVersion(tctx, certID, v2)
	if tctx.Err() != nil {
		t.Fatal("OnVersion blocked until its deadline (second pool connection needed)")
	}
	if bytes.Equal(before, f.expected(t, gid)) {
		t.Fatal("expected files unchanged after OnVersion")
	}
}

func TestEnrollDoesNotNeedSecondConnection(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	f.svc.Settings = StaticSettings(Settings{}, "https://cf.example.test")
	e, err := f.svc.CreateClient(ctx, f.org, "web-pool", nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := onePool(t, f)
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := svc.Enroll(tctx, agentproto.EnrollRequest{Token: e.Token, CSR: enrollCSR(t)}); err != nil {
		t.Fatalf("Enroll on a one-connection pool: %v", err)
	}
}
