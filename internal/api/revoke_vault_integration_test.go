//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

// vaultRevokeFixture is a vaultpki CA over a fake Vault whose pki/revoke
// counts its calls and, like Vault for an already-revoked serial, answers
// 200 every time.
func vaultRevokeFixture(t *testing.T, delay time.Duration) (*apiFixture, certstore.Version, *atomic.Int32) {
	t.Helper()
	f := newAPIFixture(t)
	ctx := context.Background()
	ca := selfSignedTestCA(t, "vault issuing")
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/cert/ca", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"certificate": encodeCertPEMLocal(ca)}})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 3600, "policies": []string{"default"}, "renewable": false}})
	})
	mux.HandleFunc("/v1/pki/revoke", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(delay)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"revocation_time": 1, "revocation_time_rfc3339": "2026-01-01T00:00:00Z"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.setVaultSettings(t, `{"address":"`+srv.URL+`","authMethod":"token","token":"t1"}`)

	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Vault", Type: ptrT(gen.Vaultpki), Config: ptrT(map[string]interface{}{"role": "myrole"}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	caID := res.(gen.CreateCa201JSONResponse).Id
	leaf := selfSignedTestCA(t, "vault-leaf.example.test")
	c, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{Name: "vault-leaf", CommonName: "vault-leaf.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.certs.Insert(ctx, tx, c.ID, &signer.Issued{LeafDER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Serial: "07"},
		"ec256", certstore.InsertOpts{Source: "issued", CAID: &caID})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return f, v, &calls
}

func revokeReq(f *apiFixture, v certstore.Version) gen.RevokeCertificateVersionRequestObject {
	return gen.RevokeCertificateVersionRequestObject{OrgId: f.org, Id: v.CertID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{}}
}

// TestRevokeVaultVersionRecordRetry: Vault revokes but the local write
// fails -> 500 whose detail says retrying records it; the retry reaches
// Vault again (already revoked there, still 200) and records revoked_at.
func TestRevokeVaultVersionRecordRetry(t *testing.T) {
	f, v, calls := vaultRevokeFixture(t, 0)
	ctx := context.Background()
	for _, stmt := range []string{
		`CREATE FUNCTION cf_block_revoke() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'blocked'; END $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER cf_block_revoke BEFORE UPDATE OF revoked_at ON certificate_versions FOR EACH ROW EXECUTE FUNCTION cf_block_revoke()`,
	} {
		if _, err := f.pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	_, err := f.srv.RevokeCertificateVersion(f.as("operator"), revokeReq(f, v))
	wantStatus(t, err, http.StatusInternalServerError)
	var he *HTTPError
	if !errors.As(err, &he) || he.Detail != "The CA revoked the certificate but it could not be recorded; retry the request." || strings.Contains(err.Error(), "blocked") {
		t.Fatalf("err = %v, want a fixed detail with no database text", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("vault revoke calls = %d, want 1", calls.Load())
	}
	if _, err := f.pool.Exec(ctx, `DROP TRIGGER cf_block_revoke ON certificate_versions`); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.RevokeCertificateVersion(f.as("operator"), revokeReq(f, v))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if res.(gen.RevokeCertificateVersion200JSONResponse).RevokedAt == nil {
		t.Fatal("revokedAt not set after retry")
	}
	if calls.Load() != 2 {
		t.Fatalf("vault revoke calls = %d, want 2", calls.Load())
	}
}

// TestRevokeVaultVersionConcurrent: two simultaneous revokes of one version
// give exactly one success and one 409, never a 500.
func TestRevokeVaultVersionConcurrent(t *testing.T) {
	f, v, _ := vaultRevokeFixture(t, 200*time.Millisecond)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = f.srv.RevokeCertificateVersion(f.as("operator"), revokeReq(f, v))
		}()
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case problemStatus(err) == http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("ok = %d, conflict = %d, want 1, 1", ok, conflict)
	}
}
