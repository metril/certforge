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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/signer"
)

// insertACMEAccount inserts a decryptable (but never actually used to talk
// to a CA) ACME account against caID, for the Task 9 private-CA/account
// cross-check tests below, which only need an accountId that genuinely
// belongs to some ACME CA.
func insertACMEAccount(t *testing.T, f *apiFixture, caID uuid.UUID) issuance.Account {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := f.store.InsertAccount(context.Background(), f.org, caID,
		signer.AccountMaterial{Email: "ops@example.test", KeyPKCS8: der, RegistrationURI: "https://acme.test/acct/1"})
	if err != nil {
		t.Fatal(err)
	}
	return acct
}

// createACMECA and createLocalCA are thin CreateCa wrappers for the tests
// below, matching private_ca_integration_test.go's own conventions.
func createACMECA(t *testing.T, f *apiFixture, name string) gen.CreateCa201JSONResponse {
	t.Helper()
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: name, Preset: ptrT(gen.CAPresetCode("letsencrypt")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return res.(gen.CreateCa201JSONResponse)
}

func createLocalCA(t *testing.T, f *apiFixture, name string) gen.CreateCa201JSONResponse {
	t.Helper()
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: name, Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return res.(gen.CreateCa201JSONResponse)
}

// TestPrivateCAAccountOverride422 (Task 9): a certificate whose effective
// CA resolves to a private CA (inherited from org defaults) but which
// itself explicitly overrides accountId to an ACME account is rejected —
// EffectiveFor's private-CA rule only ever drops an *inherited* account;
// one set on the certificate's own overrides is a real conflict.
func TestPrivateCAAccountOverride422(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	local := createLocalCA(t, f, "PrivateOverride")
	acmeCA := createACMECA(t, f, "PrivateOverrideACME")
	acct := insertACMEAccount(t, f, acmeCA.Id)

	if err := f.store.PutOrgDefaults(ctx, f.org, issuance.Defaults{CAID: &local.Id}); err != nil {
		t.Fatal(err)
	}

	_, err := f.srv.CreateCertificate(f.as("operator"), gen.CreateCertificateRequestObject{OrgId: f.org, Body: &gen.CertificateInput{
		Name: "override", CommonName: "override.example.test",
		Overrides: &gen.IssuanceDefaults{AccountId: ptrT(acct.ID)},
	}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	if !strings.Contains(err.Error(), "account belongs to a different CA") {
		t.Fatalf("err = %v, want it to mention the CA mismatch", err)
	}

	// batch-4: the conflict must be caught inside the create transaction
	// (validateDefaultsTx), before any row is committed — not discovered
	// only once certOut's own EffectiveFor call renders the response.
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE org_id = $1 AND name = $2`, f.org, "override").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("certificate rows = %d, want 0 (a rejected create must not leave a row behind)", n)
	}
}

// TestInheritedAccountIgnoredForPrivate (Task 9): an ACME account inherited
// from a *different* level than the one that resolves the effective CA
// (global sets accountId, org sets caId to a private CA) is silently
// dropped — the certificate itself never asked for an ACME account, so
// creation succeeds and the response's effective accountId is nil.
func TestInheritedAccountIgnoredForPrivate(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	local := createLocalCA(t, f, "InheritedIgnored")
	acmeCA := createACMECA(t, f, "InheritedIgnoredACME")
	acct := insertACMEAccount(t, f, acmeCA.Id)

	// Global level: only accountId. Org level: only caId (the private CA).
	// Neither level alone triggers the existing same-level accountId/caId
	// mismatch check; only EffectiveFor's cross-level rule applies here.
	if err := f.settingsStore.Set(ctx, settings.SectionKey(issuance.SettingsKey), issuance.Defaults{AccountID: &acct.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.PutOrgDefaults(ctx, f.org, issuance.Defaults{CAID: &local.Id}); err != nil {
		t.Fatal(err)
	}

	res, err := f.srv.CreateCertificate(f.as("operator"), gen.CreateCertificateRequestObject{OrgId: f.org, Body: &gen.CertificateInput{
		Name: "inherited", CommonName: "inherited.example.test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.CreateCertificate201JSONResponse)
	if c.Effective.CaId == nil || c.Effective.CaId.Value == nil || *c.Effective.CaId.Value != local.Id {
		t.Fatalf("effective caId = %+v, want %s", c.Effective.CaId, local.Id)
	}
	if c.Effective.AccountId != nil && c.Effective.AccountId.Value != nil {
		t.Fatalf("effective accountId = %+v, want dropped (nil) for a private CA", c.Effective.AccountId)
	}
}

// TestGetCertificateSurvivesCADriftToPrivate (batch-4, finding 2): a
// certificate's own accountId override was valid when it was created (its
// caId, inherited from org defaults at the time, was still the account's
// own ACME CA); once org defaults later move to a private CA, GET must
// still succeed (200) with the now-incompatible account silently dropped —
// never a 422 on the read path, which would otherwise make an existing,
// once-valid certificate suddenly unreadable.
func TestGetCertificateSurvivesCADriftToPrivate(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	acmeCA := createACMECA(t, f, "DriftACME")
	acct := insertACMEAccount(t, f, acmeCA.Id)
	local := createLocalCA(t, f, "DriftLocal")

	if err := f.store.PutOrgDefaults(ctx, f.org, issuance.Defaults{CAID: &acmeCA.Id}); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.CreateCertificate(f.as("operator"), gen.CreateCertificateRequestObject{OrgId: f.org, Body: &gen.CertificateInput{
		Name: "drift", CommonName: "drift.example.test",
		Overrides: &gen.IssuanceDefaults{AccountId: ptrT(acct.ID)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	created := res.(gen.CreateCertificate201JSONResponse)

	// Org defaults now point at a private CA; the certificate's own
	// accountId override was never touched.
	if err := f.store.PutOrgDefaults(ctx, f.org, issuance.Defaults{CAID: &local.Id}); err != nil {
		t.Fatal(err)
	}

	got, err := f.srv.GetCertificate(f.as("operator"), gen.GetCertificateRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatalf("GetCertificate: %v (must not 422 on the read path)", err)
	}
	c := got.(gen.GetCertificate200JSONResponse)
	if c.Effective.CaId == nil || c.Effective.CaId.Value == nil || *c.Effective.CaId.Value != local.Id {
		t.Fatalf("effective caId = %+v, want %s", c.Effective.CaId, local.Id)
	}
	if c.Effective.AccountId != nil && c.Effective.AccountId.Value != nil {
		t.Fatalf("effective accountId = %+v, want dropped (nil) once the effective CA is private", c.Effective.AccountId)
	}
}

// TestListCertificatesDropsInheritedAccountForPrivate (batch-4, finding 3):
// ListCertificates must apply the same private-CA/account reconciliation
// GET does, not the raw issuance.Resolve merge — otherwise a listed
// certificate would show an ACME account that GET itself never shows.
func TestListCertificatesDropsInheritedAccountForPrivate(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	local := createLocalCA(t, f, "ListDropLocal")
	acmeCA := createACMECA(t, f, "ListDropACME")
	acct := insertACMEAccount(t, f, acmeCA.Id)

	if err := f.settingsStore.Set(ctx, settings.SectionKey(issuance.SettingsKey), issuance.Defaults{AccountID: &acct.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.PutOrgDefaults(ctx, f.org, issuance.Defaults{CAID: &local.Id}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.CreateCertificate(f.as("operator"), gen.CreateCertificateRequestObject{OrgId: f.org, Body: &gen.CertificateInput{
		Name: "listed", CommonName: "listed.example.test",
	}}); err != nil {
		t.Fatal(err)
	}

	res, err := f.srv.ListCertificates(f.as("operator"), gen.ListCertificatesRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	out := res.(gen.ListCertificates200JSONResponse)
	var found bool
	for _, item := range out.Items {
		if item.Name != "listed" {
			continue
		}
		found = true
		if item.Effective.AccountId != nil && item.Effective.AccountId.Value != nil {
			t.Fatalf("listed effective accountId = %+v, want dropped (nil) for a private CA", item.Effective.AccountId)
		}
	}
	if !found {
		t.Fatal("certificate not found in the list")
	}
}

// fakeVaultPKIRevoke is a fuller fake Vault PKI secrets engine than
// vaultpki_integration_test.go's fakeVaultPKI: it actually signs the CSR it
// is handed (over caKey) so vaultpki.Signer.Issue's own
// leaf-public-key-matches-CSR check passes, and it records every
// pki/revoke call's serial_number for TestRevokeVaultPKIVersion to inspect.
type vaultRevokeCapture struct {
	mu     sync.Mutex
	called bool
	serial string
}

func (c *vaultRevokeCapture) record(serial string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.called, c.serial = true, serial
}

func (c *vaultRevokeCapture) get() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.called, c.serial
}

func fakeVaultPKIRevoke(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*httptest.Server, *vaultRevokeCapture) {
	t.Helper()
	rc := &vaultRevokeCapture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/cert/ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"certificate": encodeCertPEMLocal(caCert)}})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 3600, "policies": []string{"default"}, "renewable": false}})
	})
	mux.HandleFunc("/v1/pki/sign/", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode([]byte(body.CSR))
		if blk == nil {
			t.Fatal("fake vault: no CSR PEM block")
		}
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: csr.Subject.CommonName},
			DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate": encodeCertPEMLocal(leaf),
			"issuing_ca":  encodeCertPEMLocal(caCert),
		}})
	})
	mux.HandleFunc("/v1/pki/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SerialNumber string `json:"serial_number"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		rc.record(body.SerialNumber)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, rc
}

// issueVaultLeaf issues one leaf through a vaultpki Signer (via
// issuance.SignerFactory, bypassing the issuance worker) and stores it, the
// vaultpki analogue of crl_integration_test.go's issueLocalLeaf.
func issueVaultLeaf(t *testing.T, f *apiFixture, caID uuid.UUID, name string) certstore.Version {
	t.Helper()
	ctx := context.Background()
	ca, err := f.store.GetCA(ctx, f.org, caID)
	if err != nil {
		t.Fatal(err)
	}
	factory := &issuance.SignerFactory{Store: f.store, Vault: f.srv.d.Vault, BaseURL: func(context.Context) string { return "" }}
	sig, err := factory.New(ctx, ca)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sig.Issue(ctx, signer.IssueRequest{Names: []string{name}, KeyType: signer.EC256})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{Name: name, CommonName: name})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.certs.Insert(ctx, tx, cert.ID, issued, "ec256", certstore.InsertOpts{Source: "issued", CAID: &caID})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return v
}

var colonHexSerialRe = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2})+$`)

// TestRevokeVaultPKIVersion (Task 9 acceptance): revoking a vaultpki-issued
// version goes through Vault's own pki/revoke, with the serial formatted
// the way Vault reports and expects it (colon-separated hex), not the
// leaf's plain hex serial.
func TestRevokeVaultPKIVersion(t *testing.T) {
	f := newAPIFixture(t)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "vault issuing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	fv, revoked := fakeVaultPKIRevoke(t, caCert, caKey)
	f.setVaultSettings(t, fmt.Sprintf(`{"address":%q,"authMethod":"token","token":"t1"}`, fv.URL))

	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "VaultRevoke", Type: ptrT(gen.Vaultpki), Config: ptrT(map[string]interface{}{"role": "myrole"}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)

	v := issueVaultLeaf(t, f, ca.Id, "vault-revoke.example.test")

	rres, err := f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
		OrgId: f.org, Id: v.CertID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{Reason: ptrT(gen.KeyCompromise)},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := rres.(gen.RevokeCertificateVersion200JSONResponse)
	if got.RevokedAt == nil {
		t.Fatal("revokedAt not set")
	}

	called, serial := revoked.get()
	if !called {
		t.Fatal("Vault pki/revoke was never called")
	}
	if !colonHexSerialRe.MatchString(serial) {
		t.Fatalf("serial_number = %q, want colon-separated hex", serial)
	}
}
