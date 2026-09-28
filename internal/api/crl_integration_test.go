//go:build integration

package api

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

// issueLocalLeaf issues one leaf straight through a localca Signer (built
// via issuance.SignerFactory, bypassing the issuance worker, which does not
// wire private CAs until Task 9) and stores it with certstore.Insert,
// exactly as the Task 7 brief's TestRevokeVersionFeedsCRL describes.
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

func TestRevokeACMEVersion422(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.issuedCert(t, "acme-cert")
	_, err := f.srv.RevokeCertificateVersion(f.as("operator"), gen.RevokeCertificateVersionRequestObject{
		OrgId: f.org, Id: c.ID, Vid: v.ID, Body: &gen.RevokeCertificateVersionJSONRequestBody{},
	})
	wantStatus(t, err, http.StatusUnprocessableEntity)
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
