//go:build integration

package api

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

// issueLocalLeaf issues one leaf straight through a localca Signer (built
// via issuance.SignerFactory, bypassing the issuance worker) and stores it
// with certstore.Insert, exactly as the Task 7 brief's
// TestRevokeVersionFeedsCRL describes.
func issueLocalLeaf(t *testing.T, f *apiFixture, caID uuid.UUID, name string) (*x509.Certificate, certstore.Version) {
	t.Helper()
	ctx := context.Background()
	ca, err := f.store.GetCA(ctx, f.org, caID)
	if err != nil {
		t.Fatal(err)
	}
	factory := &issuance.SignerFactory{Store: f.store, BaseURL: func(context.Context) string { return "" }}
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
	leaf, err := x509.ParseCertificate(issued.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, v
}

func TestRevokeVersionFeedsCRL(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "RevokeCA", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)
	leaf, v := issueLocalLeaf(t, f, ca.Id, "revoke-me.example.test")

	rres, err := f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
		OrgId: f.org, Id: v.CertID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{Reason: ptrT(gen.KeyCompromise)},
	})
	if err != nil {
		t.Fatal(err)
	}
	revoked := rres.(gen.RevokeCertificateVersion200JSONResponse)
	if revoked.RevokedAt == nil {
		t.Fatal("revokedAt not set")
	}
	if n := f.auditCount(t, "certificate.revoked"); n != 1 {
		t.Fatalf("certificate.revoked audit count = %d", n)
	}

	// Revoking twice is a conflict.
	_, err = f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
		OrgId: f.org, Id: v.CertID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{},
	})
	wantStatus(t, err, http.StatusConflict)

	der, err := f.store.CRL(context.Background(), ca.Id, "")
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("revoked leaf's serial not present on the CRL")
	}
}

// TestRevokeACMEVersion422 covers the batch-3 review fix: the version must
// actually carry an acme CA's id, or the 422 comes from the "not issued by
// CertForge" branch (a nil ca_id, f.issuedCert's default) instead of the
// ACME one this test means to exercise.
func TestRevokeACMEVersion422(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "ACME", Preset: ptrT(gen.CAPresetCode("letsencrypt")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	acmeCA := res.(gen.CreateCa201JSONResponse)

	c, err := f.store.CreateCertificate(context.Background(), f.org, issuance.CertInput{Name: "acme-cert", CommonName: "acme-cert.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.certs.Insert(context.Background(), tx, c.ID, &signer.Issued{LeafDER: []byte("leaf"), NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), Serial: "01"}, "ec256", certstore.InsertOpts{Source: "issued", CAID: &acmeCA.Id})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, err = f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
		OrgId: f.org, Id: c.ID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{},
	})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "not supported for ACME CAs yet") {
		t.Fatalf("err = %v, want detail to mention ACME CAs are not supported yet", err)
	}
}

func TestCRLRoutes(t *testing.T) {
	f := newAPIFixture(t)
	httpSrv := httptest.NewServer(NewRouter(f.srv.d))
	defer httpSrv.Close()

	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "CRLRoutes", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)
	_, v := issueLocalLeaf(t, f, ca.Id, "crl-route.example.test")
	if _, err := f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
		OrgId: f.org, Id: v.CertID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{},
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("current issuer DER parses and lists the revocation", func(t *testing.T) {
		body := getCRL(t, httpSrv.Client(), httpSrv.URL+"/crl/"+ca.Id.String()+".crl", http.StatusOK)
		if _, err := x509.ParseRevocationList(body); err != nil {
			t.Fatalf("parse crl: %v", err)
		}
	})

	t.Run("unknown ca id is 404", func(t *testing.T) {
		getCRL(t, httpSrv.Client(), httpSrv.URL+"/crl/"+uuid.New().String()+".crl", http.StatusNotFound)
	})

	// Batch-3 review fix: the cache key includes crl_number, so a
	// revocation must be visible on the very next fetch, not only once the
	// 10-minute in-memory TTL happens to expire. Its own CA (not the outer
	// one already revoked against above) so crl_number starts at a known 0.
	t.Run("cache reflects a revocation immediately, not after a TTL wait", func(t *testing.T) {
		res3, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "CacheCA", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
		}})
		if err != nil {
			t.Fatal(err)
		}
		cacheCA := res3.(gen.CreateCa201JSONResponse)
		leaf2, v2 := issueLocalLeaf(t, f, cacheCA.Id, "cache-me.example.test")

		before := getCRL(t, httpSrv.Client(), httpSrv.URL+"/crl/"+cacheCA.Id.String()+".crl", http.StatusOK)
		beforeCRL, err := x509.ParseRevocationList(before)
		if err != nil {
			t.Fatal(err)
		}
		if len(beforeCRL.RevokedCertificateEntries) != 0 {
			t.Fatalf("fresh CA's CRL already lists a revocation: %v", beforeCRL.RevokedCertificateEntries)
		}

		if _, err := f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
			OrgId: f.org, Id: v2.CertID, Vid: v2.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{},
		}); err != nil {
			t.Fatal(err)
		}

		after := getCRL(t, httpSrv.Client(), httpSrv.URL+"/crl/"+cacheCA.Id.String()+".crl", http.StatusOK)
		afterCRL, err := x509.ParseRevocationList(after)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range afterCRL.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
				found = true
			}
		}
		if !found {
			t.Fatal("revocation not visible on the very next fetch: cache served a stale entry")
		}
	})

	t.Run("crl false is 404", func(t *testing.T) {
		res2, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "NoCRL", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "NoCRL"}, "crl": false,
			}),
		}})
		if err != nil {
			t.Fatal(err)
		}
		noCRL := res2.(gen.CreateCa201JSONResponse)
		getCRL(t, httpSrv.Client(), httpSrv.URL+"/crl/"+noCRL.Id.String()+".crl", http.StatusNotFound)
	})

	t.Run("retired issuer CRL after rotate", func(t *testing.T) {
		created, err := f.store.GetCA(context.Background(), f.org, ca.Id)
		if err != nil {
			t.Fatal(err)
		}
		oldIssuing, err := parseFirstCert(mustStringField(created.Config, "issuingPem"))
		if err != nil {
			t.Fatal(err)
		}
		rotRes, err := f.srv.RotateCa(f.as("admin"), gen.RotateCaRequestObject{OrgId: f.org, Id: ca.Id})
		if err != nil {
			t.Fatal(err)
		}
		_ = rotRes

		oldSerial := oldIssuing.SerialNumber.Text(16)
		body := getCRL(t, httpSrv.Client(), httpSrv.URL+"/crl/"+ca.Id.String()+"/"+oldSerial+".crl", http.StatusOK)
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			t.Fatalf("parse retired crl: %v", err)
		}
		if crl.Issuer.String() != oldIssuing.Subject.String() {
			t.Fatalf("retired crl issuer = %q, want %q", crl.Issuer, oldIssuing.Subject)
		}
	})
}

func mustStringField(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func getCRL(t *testing.T, client *http.Client, url string, wantStatus int) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req) //nolint:bodyclose // closed below
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s = %d, want %d", url, resp.StatusCode, wantStatus)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// countingBox counts Open calls, i.e. unseal attempts of a CA's secret_cfg.
type countingBox struct {
	crypto.Box
	opens atomic.Int32
}

func (b *countingBox) Open(ctx context.Context, s []byte) ([]byte, error) {
	b.opens.Add(1)
	return b.Box.Open(ctx, s)
}

// A5: an unknown issuer serial is rejected from the public config, before
// the CA's secret_cfg is unsealed.
func TestCRLUnknownIssuerSerialDoesNotUnseal(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "A5", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)
	cb := &countingBox{Box: f.box}
	store := issuance.NewStore(f.pool, cb, f.settingsStore)

	if _, err := store.CRL(context.Background(), ca.Id, "deadbeef"); !errors.Is(err, issuance.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if n := cb.opens.Load(); n != 0 {
		t.Fatalf("bogus serial unsealed the CA key %d time(s)", n)
	}
	if _, err := store.CRL(context.Background(), ca.Id, ""); err != nil {
		t.Fatal(err)
	}
	if cb.opens.Load() == 0 {
		t.Fatal("current issuer should unseal")
	}
}

// TestCRLDropsExpiredLeaves covers L2: a revoked leaf past its NotAfter is
// omitted from the CRL (the stored entry is still there until the next
// Revoke prunes it), and an entry without a stored NotAfter is kept.
func TestCRLDropsExpiredLeaves(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "ExpiryCA", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)
	revoke := func(name string) *x509.Certificate {
		leaf, v := issueLocalLeaf(t, f, ca.Id, name)
		if _, err := f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
			OrgId: f.org, Id: v.CertID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{},
		}); err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	live := revoke("live.example.test")

	// Append an expired entry and a legacy one (no notAfter) for the same issuer.
	_, err = f.pool.Exec(ctx, `UPDATE cas SET config = jsonb_set(config, '{revoked}', config->'revoked' || jsonb_build_array(
		jsonb_build_object('serial','aa01','issuerSerial',config->'revoked'->0->>'issuerSerial','at',now(),'reason',0,'notAfter',now() - interval '1 day'),
		jsonb_build_object('serial','bb02','issuerSerial',config->'revoked'->0->>'issuerSerial','at',now(),'reason',0)))
		WHERE id = $1`, ca.Id)
	if err != nil {
		t.Fatal(err)
	}
	serials := func() map[string]bool {
		der, err := f.store.CRL(ctx, ca.Id, "")
		if err != nil {
			t.Fatal(err)
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, e := range crl.RevokedCertificateEntries {
			out[e.SerialNumber.Text(16)] = true
		}
		return out
	}
	got := serials()
	if len(got) != 2 || !got[live.SerialNumber.Text(16)] || !got["bb02"] || got["aa01"] {
		t.Fatalf("CRL serials = %v, want the live and legacy entries only", got)
	}

	// The next revocation prunes the expired entry from the stored config.
	revoke("live2.example.test")
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT jsonb_array_length(config->'revoked') FROM cas WHERE id = $1`, ca.Id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("stored revoked entries = %d, want 3 (expired one pruned)", n)
	}
}

// Revoking a managed certificate's current version must pull next_renew_at
// forward so the scheduler replaces the revoked leaf.
func TestRevokeCurrentVersionTriggersRenewal(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "RenewCA", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)
	_, v := issueLocalLeaf(t, f, ca.Id, "renew-me.example.test")
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE certificates SET current_version_id = $2, managed = true, status = 'active', next_renew_at = now() + interval '30 days' WHERE id = $1`, v.CertID, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
		OrgId: f.org, Id: v.CertID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{Reason: ptrT(gen.KeyCompromise)},
	}); err != nil {
		t.Fatal(err)
	}
	var due bool
	if err := f.pool.QueryRow(ctx, `SELECT next_renew_at <= now() FROM certificates WHERE id = $1`, v.CertID).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if !due {
		t.Fatal("next_renew_at not pulled forward after revoking the current version")
	}
}
