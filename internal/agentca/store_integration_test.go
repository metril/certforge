//go:build integration

package agentca

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
)

func TestEnsureActiveCreatesOnce(t *testing.T) {
	pool, _ := dbtest.New(t)
	s := NewStore(pool, cryptotest.PrefixBox{})
	ctx := context.Background()
	ids := make([]uuid.UUID, 5)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ca, err := s.EnsureActive(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			ids[i] = ca.ID
		}(i)
	}
	wg.Wait()
	for _, id := range ids[1:] {
		if id != ids[0] {
			t.Fatalf("different CAs %v", ids)
		}
	}
	ca, err := s.Active(ctx)
	if err != nil || ca.Key == nil || !ca.Key.PublicKey.Equal(ca.Cert.PublicKey) {
		t.Fatalf("active %+v %v", ca, err)
	}
}

func TestRotateAndRetire(t *testing.T) {
	pool, _ := dbtest.New(t)
	s := NewStore(pool, cryptotest.PrefixBox{})
	ctx := context.Background()
	old, err := s.EnsureActive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Rotate(ctx)
	if err != nil || next.ID == old.ID || next.Status != "active" {
		t.Fatalf("rotate %+v %v", next, err)
	}
	trusted, _ := s.Trusted(ctx)
	if len(trusted) != 2 {
		t.Fatalf("trusted %d", len(trusted))
	}
	if oldest, err := s.Oldest(ctx); err != nil || oldest.ID != old.ID {
		t.Fatalf("oldest %v %v", oldest, err)
	}
	if err := s.Retire(ctx, next.ID); !errors.Is(err, ErrActive) {
		t.Fatalf("retire active: %v", err)
	}
	org := dbtest.Org(t, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO clients (org_id, name, status, agent_ca_id, agent_cert_not_after)
		VALUES ($1, 'c1', 'active', $2, now() + interval '1 day')`, org, old.ID); err != nil {
		t.Fatal(err)
	}
	var inUse *InUseError
	if err := s.Retire(ctx, old.ID); !errors.As(err, &inUse) || inUse.N != 1 {
		t.Fatalf("retire in use: %v", err)
	}
	list, _ := s.List(ctx)
	if len(list) != 2 || list[1].ID != old.ID || list[1].ActiveClientCerts != 1 || list[1].Status != "retiring" {
		t.Fatalf("list %+v", list)
	}
	if _, err := pool.Exec(ctx, `UPDATE clients SET status = 'revoked'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	if trusted, _ = s.Trusted(ctx); len(trusted) != 1 || !trusted[0].Equal(next.Cert) {
		t.Fatalf("trusted after retire %d", len(trusted))
	}
	if err := s.Retire(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retire unknown: %v", err)
	}
}
