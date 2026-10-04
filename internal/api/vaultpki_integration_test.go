//go:build integration

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api/gen"
)

// fakeVaultPKI is a minimal Vault PKI secrets engine stand-in: GET
// /v1/<mount>/cert/ca returns caPEM (createVaultPKICA's PKIReadCA), and
// every auth/renewal path a live *vault.Client's background loop touches
// answers something reasonable so it never errors loudly.
func fakeVaultPKI(t *testing.T, caPEM string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/cert/ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"certificate": caPEM}})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 3600, "policies": []string{"default"}, "renewable": false}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func selfSignedTestCA(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func encodeCertPEMLocal(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// TestVaultPKICACreate covers vaultpki CA create over a fake Vault: 422
// when the "vault" settings section is unconfigured, and once configured,
// trustBundlePem/notBefore/notAfter come from PKIReadCA and config holds
// the resolved mount/role/ttl.
func TestVaultPKICACreate(t *testing.T) {
	f := newAPIFixture(t)

	_, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Unconfigured", Type: ptrT(gen.Vaultpki), Config: ptrT(map[string]interface{}{"role": "myrole"}),
	}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	if !strings.Contains(err.Error(), "Vault") {
		t.Fatalf("err = %v, want it to mention Vault", err)
	}

	ca := selfSignedTestCA(t, "vault issuing")
	fv := fakeVaultPKI(t, encodeCertPEMLocal(ca))
	f.setVaultSettings(t, `{"address":"`+fv.URL+`","authMethod":"token","token":"t1"}`)

	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Vault", Type: ptrT(gen.Vaultpki), Config: ptrT(map[string]interface{}{"role": "myrole", "ttl": "2160h"}),
	}})
	if err != nil {
		t.Fatalf("CreateCa: %v", err)
	}
	out := res.(gen.CreateCa201JSONResponse)
	if out.TrustBundlePem != encodeCertPEMLocal(ca) {
		t.Fatalf("trustBundlePem = %q", out.TrustBundlePem)
	}
	if out.NotBefore == nil || out.NotAfter == nil || !out.NotBefore.Equal(ca.NotBefore) || !out.NotAfter.Equal(ca.NotAfter) {
		t.Fatalf("notBefore/notAfter = %v/%v, want %v/%v", out.NotBefore, out.NotAfter, ca.NotBefore, ca.NotAfter)
	}
	if out.Config["mount"] != "pki" || out.Config["role"] != "myrole" || out.Config["ttl"] != "2160h" {
		t.Fatalf("config = %+v", out.Config)
	}
	if len(out.StoredSecrets) != 0 {
		t.Fatalf("storedSecrets = %v, want none (vaultpki holds no secrets)", out.StoredSecrets)
	}

	// Update: mount/role/ttl change, trustBundlePem/notBefore/notAfter stay.
	upd, err := f.srv.UpdateCa(f.as("admin"), gen.UpdateCaRequestObject{OrgId: f.org, Id: out.Id, Body: &gen.CAInput{
		Name: "Vault", Type: ptrT(gen.Vaultpki), Config: ptrT(map[string]interface{}{"role": "otherrole"}),
	}})
	if err != nil {
		t.Fatalf("UpdateCa: %v", err)
	}
	updOut := upd.(gen.UpdateCa200JSONResponse)
	if updOut.Config["role"] != "otherrole" {
		t.Fatalf("updated config = %+v", updOut.Config)
	}
	if updOut.TrustBundlePem != out.TrustBundlePem {
		t.Fatalf("trustBundlePem changed on update: %q != %q", updOut.TrustBundlePem, out.TrustBundlePem)
	}
}

// TestVaultPKICACreateInvalidConfig covers config validation ahead of any
// Vault call: an empty role is 422 before the (unconfigured) Vault check
// would otherwise fire.
func TestVaultPKICACreateInvalidConfig(t *testing.T) {
	f := newAPIFixture(t)
	_, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "BadRole", Type: ptrT(gen.Vaultpki), Config: ptrT(map[string]interface{}{"role": ""}),
	}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	if !strings.Contains(err.Error(), "role") {
		t.Fatalf("err = %v, want it to mention role", err)
	}
}

// B2: changing a vaultpki CA's mount or role is a 409 once it has an issued
// live version; ttl and name stay editable.
func TestVaultPKICAMountRoleLockedWhileInUse(t *testing.T) {
	f := newAPIFixture(t)
	ca := selfSignedTestCA(t, "vault issuing")
	fv := fakeVaultPKI(t, encodeCertPEMLocal(ca))
	f.setVaultSettings(t, `{"address":"`+fv.URL+`","authMethod":"token","token":"t1"}`)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Vault", Type: ptrT(gen.Vaultpki), Config: ptrT(map[string]interface{}{"role": "myrole"}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateCa201JSONResponse).Id
	c, v := f.issuedCert(t, "vault-in-use")
	_ = c
	if _, err := f.pool.Exec(context.Background(), `UPDATE certificate_versions SET ca_id = $1 WHERE id = $2`, id, v.ID); err != nil {
		t.Fatal(err)
	}
	update := func(cfg map[string]interface{}) error {
		_, err := f.srv.UpdateCa(f.as("admin"), gen.UpdateCaRequestObject{OrgId: f.org, Id: id, Body: &gen.CAInput{
			Name: "Vault", Type: ptrT(gen.Vaultpki), Config: &cfg}})
		return err
	}
	wantStatus(t, update(map[string]interface{}{"role": "otherrole"}), http.StatusConflict)
	wantStatus(t, update(map[string]interface{}{"role": "myrole", "mount": "pki2"}), http.StatusConflict)
	if err := update(map[string]interface{}{"role": "myrole", "ttl": "2160h"}); err != nil {
		t.Fatalf("ttl-only change: %v", err)
	}
}
