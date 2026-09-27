//go:build integration

package certstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/signer"
)

func TestInsertAndMaterial(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)
	var certID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c', 'a.example.test') RETURNING id`, org).Scan(&certID); err != nil {
		t.Fatal(err)
	}
	s := New(pool, cryptotest.PrefixBox{})
	nb := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	iss := &signer.Issued{LeafDER: []byte("leaf"), ChainDER: [][]byte{[]byte("int")}, PrivateKeyPKCS8: []byte("key"),
		NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour), Serial: "0a"}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Insert(ctx, tx, certID, iss, "ec256", InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if len(v.SHA256) != 64 || v.Source != "issued" || v.KeyType != "ec256" || !v.HasKey || v.CAID != nil {
		t.Fatalf("version = %+v", v)
	}
	m, err := s.Material(ctx, certID, v.ID, false)
	if err != nil || m.PrivateKeyPKCS8 != nil || string(m.ChainDER[0]) != "int" {
		t.Fatalf("material without key = %+v %v", m, err)
	}
	m, _ = s.Material(ctx, certID, v.ID, true)
	if string(m.PrivateKeyPKCS8) != "key" {
		t.Fatal("key not decrypted")
	}
	if _, err := s.Get(ctx, uuid.New(), v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("version of another cert: %v", err)
	}
	vs, _ := s.List(ctx, certID)
	if len(vs) != 1 {
		t.Fatalf("list = %v", vs)
	}
}

// TestInsertKeylessVersion covers Phase 4A Task 1: a nil PrivateKeyPKCS8
// (an imported or uploaded certificate with no key) stores NULL rather than
// sealing empty bytes, Source and CAID round-trip, and HasKey is false.
// render.Render's own ErrNoKey (raised only once a key-bearing part is
// actually requested) is exercised directly against Material's result, per
// the brief.
func TestInsertKeylessVersion(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)
	var certID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c', 'a.example.test') RETURNING id`, org).Scan(&certID); err != nil {
		t.Fatal(err)
	}
	var caID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO cas (org_id, name, preset, directory_url) VALUES ($1, 'LE', 'letsencrypt', 'https://acme-v02.api.letsencrypt.org/directory') RETURNING id`, org).Scan(&caID); err != nil {
		t.Fatal(err)
	}
	s := New(pool, cryptotest.PrefixBox{})
	nb := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	iss := &signer.Issued{LeafDER: []byte("leaf"), ChainDER: [][]byte{[]byte("int")},
		NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour), Serial: "0b"} // PrivateKeyPKCS8 nil
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Insert(ctx, tx, certID, iss, "ec256", InsertOpts{Source: "imported", CAID: &caID})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if v.Source != "imported" || v.HasKey || v.CAID == nil || *v.CAID != caID {
		t.Fatalf("version = %+v", v)
	}
	m, err := s.Material(ctx, certID, v.ID, true)
	if err != nil || m.PrivateKeyPKCS8 != nil {
		t.Fatalf("material on a keyless version = %+v, %v", m, err)
	}
	if _, err := render.Render(m, []string{"key"}); !errors.Is(err, render.ErrNoKey) {
		t.Fatalf("Render([\"key\"]) = %v, want render.ErrNoKey", err)
	}
	if got, err := s.Get(ctx, certID, v.ID); err != nil || got.HasKey {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if _, _, err := s.PrivateKey(ctx, certID, v.ID); !errors.Is(err, render.ErrNoKey) {
		t.Fatalf("PrivateKey = %v, want render.ErrNoKey", err)
	}
}
