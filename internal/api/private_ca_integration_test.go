//go:build integration

package api

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/signer/localca"
)

func localCASubjectConfig() map[string]interface{} {
	return map[string]interface{}{"subject": map[string]interface{}{"commonName": "Test Root"}}
}

func encodeCertPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func encodeKeyPEM(t *testing.T, key crypto.Signer) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, key)}))
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLocalCACRUDMatrix(t *testing.T) {
	f := newAPIFixture(t)

	t.Run("generate", func(t *testing.T) {
		res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "Local", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
		}})
		if err != nil {
			t.Fatal(err)
		}
		ca := res.(gen.CreateCa201JSONResponse)
		if ca.TrustBundlePem == "" || !strings.Contains(ca.TrustBundlePem, "CERTIFICATE") {
			t.Fatalf("trustBundlePem = %q", ca.TrustBundlePem)
		}
		root, err := parseFirstCert(ca.TrustBundlePem)
		if err != nil {
			t.Fatal(err)
		}
		issuingPem, _ := ca.Config["issuingPem"].(string)
		issuing, err := parseFirstCert(issuingPem)
		if err != nil {
			t.Fatalf("issuingPem: %v", err)
		}
		if root.SerialNumber.Cmp(issuing.SerialNumber) == 0 {
			t.Fatal("trustBundlePem should be the root, not the issuing certificate")
		}
		if ca.NotBefore == nil || ca.NotAfter == nil || !ca.NotAfter.Equal(issuing.NotAfter) {
			t.Fatalf("notBefore/notAfter = %v/%v, want issuing validity %v", ca.NotBefore, ca.NotAfter, issuing.NotAfter)
		}
		if n, ok := ca.Config["revokedCount"].(int); !ok || n != 0 {
			t.Fatalf("revokedCount = %v", ca.Config["revokedCount"])
		}
		if _, ok := ca.Config["revoked"]; ok {
			t.Fatal("config leaks internal revoked[] array")
		}
	})

	t.Run("import with chain", func(t *testing.T) {
		mat, _, err := localca.Generate(localca.Config{Subject: localca.Subject{CommonName: "Import Root"},
			KeyType: signer.EC256, RootValidityYears: 10, IssuingValidityYears: 3, MaxLeafDays: 397, CRL: true}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		issuingKeyPKCS8 := mustMarshalPKCS8(t, mat.IssuingKey)
		certPEM := encodeCertPEM(mat.Issuing.Raw) + encodeCertPEM(mat.Root.Raw)
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuingKeyPKCS8}))

		res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "Imported", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "Imported"}, "importPem": certPEM, "importKeyPem": keyPEM,
			}),
		}})
		if err != nil {
			t.Fatal(err)
		}
		ca := res.(gen.CreateCa201JSONResponse)
		got, err := parseFirstCert(ca.TrustBundlePem)
		if err != nil {
			t.Fatal(err)
		}
		if got.SerialNumber.Cmp(mat.Root.SerialNumber) != 0 {
			t.Fatalf("trustBundlePem should be the last importPem cert (the root)")
		}
		if imported, _ := ca.Config["imported"].(bool); !imported {
			t.Fatal("imported should be true")
		}
		if len(ca.StoredSecrets) != 1 || ca.StoredSecrets[0] != "importKeyPem" {
			t.Fatalf("storedSecrets = %v", ca.StoredSecrets)
		}
	})

	t.Run("chainless import gives issuing cert as trust bundle", func(t *testing.T) {
		mat, _, err := localca.Generate(localca.Config{Subject: localca.Subject{CommonName: "Chainless"},
			KeyType: signer.EC256, RootValidityYears: 10, IssuingValidityYears: 3, MaxLeafDays: 397, CRL: true}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		issuingKeyPKCS8 := mustMarshalPKCS8(t, mat.IssuingKey)
		certPEM := encodeCertPEM(mat.Issuing.Raw)
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuingKeyPKCS8}))

		res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "Chainless", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "Chainless"}, "importPem": certPEM, "importKeyPem": keyPEM,
			}),
		}})
		if err != nil {
			t.Fatal(err)
		}
		ca := res.(gen.CreateCa201JSONResponse)
		got, err := parseFirstCert(ca.TrustBundlePem)
		if err != nil {
			t.Fatal(err)
		}
		if got.SerialNumber.Cmp(mat.Issuing.SerialNumber) != 0 {
			t.Fatal("chainless import should give the issuing certificate as the trust bundle")
		}
	})

	t.Run("eab on localca is 422", func(t *testing.T) {
		_, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "BadEAB", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()), EabKid: ptrT("kid"),
		}})
		wantStatus(t, err, http.StatusUnprocessableEntity)
	})

	t.Run("bad pem is 422", func(t *testing.T) {
		_, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "BadPEM", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "Bad"}, "importPem": "not a pem", "importKeyPem": "also not a pem",
			}),
		}})
		wantStatus(t, err, http.StatusUnprocessableEntity)
	})

	t.Run("import lacking crlsign with crl true is 422", func(t *testing.T) {
		certPEM, keyPEM := issuingWithoutCRLSign(t)
		_, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "NoCRLSign", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "NoCRLSign"}, "importPem": certPEM, "importKeyPem": keyPEM, "crl": true,
			}),
		}})
		wantStatus(t, err, http.StatusUnprocessableEntity)
	})

	t.Run("type change is 422", func(t *testing.T) {
		res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "TypeChange", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
		}})
		if err != nil {
			t.Fatal(err)
		}
		ca := res.(gen.CreateCa201JSONResponse)
		_, err = f.srv.UpdateCa(f.as("admin"), gen.UpdateCaRequestObject{OrgId: f.org, Id: ca.Id, Body: &gen.CAInput{
			Name: "TypeChange", Type: ptrT(gen.Acme), Preset: ptrT(gen.CAPresetCode("letsencrypt")),
		}})
		wantStatus(t, err, http.StatusUnprocessableEntity)
	})

	t.Run("immutable field change is 422, editable fields apply", func(t *testing.T) {
		res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "Immutable", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
		}})
		if err != nil {
			t.Fatal(err)
		}
		ca := res.(gen.CreateCa201JSONResponse)
		_, err = f.srv.UpdateCa(f.as("admin"), gen.UpdateCaRequestObject{OrgId: f.org, Id: ca.Id, Body: &gen.CAInput{
			Name: "Immutable", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "Changed"},
			}),
		}})
		wantStatus(t, err, http.StatusUnprocessableEntity)

		res2, err := f.srv.UpdateCa(f.as("admin"), gen.UpdateCaRequestObject{OrgId: f.org, Id: ca.Id, Body: &gen.CAInput{
			Name: "Immutable", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "Test Root"}, "maxLeafDays": 30, "crl": false,
			}),
		}})
		if err != nil {
			t.Fatal(err)
		}
		updated := res2.(gen.UpdateCa200JSONResponse)
		if v, _ := updated.Config["maxLeafDays"].(float64); v != 30 {
			t.Fatalf("maxLeafDays = %v, want 30", updated.Config["maxLeafDays"])
		}
		if updated.CrlUrl != nil {
			t.Fatal("crlUrl should be absent once crl is disabled")
		}
	})
}

func TestLocalCASecretsNeverInCA(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Secrets", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ca := res.(gen.CreateCa201JSONResponse)
	b := mustJSON(t, ca)
	if strings.Contains(b, "PRIVATE KEY") {
		t.Fatalf("GET body contains a private key:\n%s", b)
	}
}

func TestRotateCAKeepsTrust(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Rotate", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	created := res.(gen.CreateCa201JSONResponse)
	oldIssuingPem, _ := created.Config["issuingPem"].(string)
	oldIssuing, err := parseFirstCert(oldIssuingPem)
	if err != nil {
		t.Fatal(err)
	}

	rotRes, err := f.srv.RotateCa(f.as("admin"), gen.RotateCaRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatal(err)
	}
	rotated := rotRes.(gen.RotateCa200JSONResponse)
	if rotated.TrustBundlePem != created.TrustBundlePem {
		t.Fatal("trustBundlePem changed across rotate")
	}
	newIssuingPem, _ := rotated.Config["issuingPem"].(string)
	newIssuing, err := parseFirstCert(newIssuingPem)
	if err != nil {
		t.Fatal(err)
	}
	if newIssuing.SerialNumber.Cmp(oldIssuing.SerialNumber) == 0 {
		t.Fatal("rotate produced the same issuing serial")
	}
	if rotated.NotAfter == nil || !rotated.NotAfter.Equal(newIssuing.NotAfter) {
		t.Fatalf("notAfter = %v, want new issuer's %v", rotated.NotAfter, newIssuing.NotAfter)
	}
	retired, ok := rotated.Config["retired"].([]interface{})
	if !ok || len(retired) != 1 {
		t.Fatalf("retired = %v", rotated.Config["retired"])
	}
	entry := retired[0].(map[string]interface{})
	if entry["serial"] != oldIssuing.SerialNumber.Text(16) {
		t.Fatalf("retired serial = %v, want %s", entry["serial"], oldIssuing.SerialNumber.Text(16))
	}
	if rotated.CrlUrl != nil {
		if _, ok := entry["crlUrl"]; !ok {
			t.Fatal("retired entry should carry crlUrl when the CA's own crlUrl is present")
		}
	} else if _, ok := entry["crlUrl"]; ok {
		t.Fatal("retired entry should not carry crlUrl when the CA's own crlUrl is absent")
	}

	if n := f.auditCount(t, "ca.rotate"); n != 1 {
		t.Fatalf("ca.rotate audit count = %d", n)
	}

	// Import can't rotate: no held root key.
	mat, _, err := localca.Generate(localca.Config{Subject: localca.Subject{CommonName: "ImpRoot"},
		KeyType: signer.EC256, RootValidityYears: 10, IssuingValidityYears: 3, MaxLeafDays: 397, CRL: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	issuingKeyPKCS8 := mustMarshalPKCS8(t, mat.IssuingKey)
	certPEM := encodeCertPEM(mat.Issuing.Raw) + encodeCertPEM(mat.Root.Raw)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuingKeyPKCS8}))
	impRes, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Imp", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
			"subject": map[string]interface{}{"commonName": "Imp"}, "importPem": certPEM, "importKeyPem": keyPEM,
		}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	imp := impRes.(gen.CreateCa201JSONResponse)
	_, err = f.srv.RotateCa(f.as("admin"), gen.RotateCaRequestObject{OrgId: f.org, Id: imp.Id})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

func TestMetaSchemasSigners(t *testing.T) {
	f := newAPIFixture(t)
	f.srv.d.Meta = meta.NewRegistry()
	localca.AddToMeta(f.srv.d.Meta)

	res, err := f.srv.GetMetaSchemas(f.as("viewer"), gen.GetMetaSchemasRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	out := res.(gen.GetMetaSchemas200JSONResponse)
	if len(out.Signers) != 1 || out.Signers[0].Code != "localca" {
		t.Fatalf("signers = %+v", out.Signers)
	}
	var schema struct {
		Properties map[string]struct {
			Secret bool `json:"secret"`
		} `json:"properties"`
	}
	b, err := json.Marshal(out.Signers[0].Schema)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	if !schema.Properties["importKeyPem"].Secret {
		t.Fatal("importKeyPem should be marked secret")
	}
	if schema.Properties["importPem"].Secret {
		t.Fatal("importPem is public, should not be marked secret")
	}
}

// --- shared test helpers ---

func parseFirstCert(s string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(s))
	return x509.ParseCertificate(blk.Bytes)
}

func mustMarshalPKCS8(t *testing.T, key interface{}) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ptrT[T any](v T) *T { return &v }

// issuingWithoutCRLSign builds a root plus an issuing certificate that
// lacks the CRLSign key usage bit, so Import(crl:true) rejects it
// (localca.ErrCannotSignCRL) — localca.Generate always sets CRLSign
// (TestGeneratedCertsCanSignCRLs in the localca package), so this rebuilds
// the issuing certificate by hand under the same root.
func issuingWithoutCRLSign(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	mat, rootKeyPKCS8, err := localca.Generate(localca.Config{Subject: localca.Subject{CommonName: "NoCRL"},
		KeyType: signer.EC256, RootValidityYears: 10, IssuingValidityYears: 3, MaxLeafDays: 397, CRL: false}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rootKeyAny, err := x509.ParsePKCS8PrivateKey(rootKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	rootKey := rootKeyAny.(crypto.Signer)
	tmpl := &x509.Certificate{SerialNumber: mat.Issuing.SerialNumber, Subject: mat.Issuing.Subject,
		NotBefore: mat.Issuing.NotBefore, NotAfter: mat.Issuing.NotAfter, KeyUsage: x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, mat.Root, mat.IssuingKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return encodeCertPEM(der) + encodeCertPEM(mat.Root.Raw), encodeKeyPEM(t, mat.IssuingKey)
}
