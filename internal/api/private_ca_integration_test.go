//go:build integration

package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
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

// TestLocalCASecretsNeverInCA checks GetCa's actual response (not just the
// create response) for a leaked private key three ways: the PEM marker
// itself, secret_cfg's own root/issuing/import key fields decrypted and
// checked by their exact base64, and the issuing key CASecret hands back
// to a caller re-marshalled to PKCS8 — so a leak of any of the individual
// byte fields (not just a stray "PRIVATE KEY" PEM string) would fail this.
// assertLocalCASecretsNeverInGetCa fetches caID with GetCa and checks its
// response three ways: no "PRIVATE KEY" PEM marker, no base64 of any of
// secret_cfg's own key fields (decrypted directly), and no base64 of the
// issuing key CASecret hands back re-marshalled to PKCS8. requireFields
// lists which secret_cfg fields this CA is expected to actually hold (so a
// field that is empty for a generated CA, say importKeyPem, still gets a
// real check on an imported one instead of silently no-op'ing).
func assertLocalCASecretsNeverInGetCa(t *testing.T, f *apiFixture, caID uuid.UUID, requireFields ...string) {
	t.Helper()
	getRes, err := f.srv.GetCa(f.as("admin"), gen.GetCaRequestObject{OrgId: f.org, Id: caID})
	if err != nil {
		t.Fatal(err)
	}
	got := getRes.(gen.GetCa200JSONResponse)
	body := mustJSON(t, got)
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("GET body contains a private key:\n%s", body)
	}

	ctx := context.Background()
	q := sqlcgen.New(f.pool)
	row, err := q.GetCAByID(ctx, caID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.box.Open(ctx, row.SecretCfg)
	if err != nil {
		t.Fatal(err)
	}
	var sc map[string]interface{}
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatal(err)
	}
	for _, field := range requireFields {
		if v, _ := sc[field].(string); v == "" {
			t.Fatalf("secret_cfg.%s is empty; this check would vacuously pass", field)
		}
	}
	for _, field := range []string{"rootKey", "issuingKey", "importKeyPem"} {
		v, _ := sc[field].(string)
		if v == "" {
			continue
		}
		if strings.Contains(body, v) {
			t.Fatalf("GET body leaks secret_cfg.%s", field)
		}
	}

	mat, _, err := f.store.CASecret(ctx, row, "")
	if err != nil {
		t.Fatal(err)
	}
	issuingPKCS8 := mustMarshalPKCS8(t, mat.IssuingKey)
	if strings.Contains(body, base64.StdEncoding.EncodeToString(issuingPKCS8)) {
		t.Fatal("GET body leaks the issuing key (from CASecret)")
	}
}

// TestLocalCASecretsNeverInCA covers both key-holding shapes a localca CA
// can have: a generated CA (rootKey + issuingKey) and an imported one
// (issuingKey + importKeyPem, no root key) — the batch-3 re-review found
// the import case untested, so importKeyPem's own leak check was silently
// skipped every run.
func TestLocalCASecretsNeverInCA(t *testing.T) {
	f := newAPIFixture(t)

	t.Run("generated", func(t *testing.T) {
		res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "Secrets", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
		}})
		if err != nil {
			t.Fatal(err)
		}
		created := res.(gen.CreateCa201JSONResponse)
		assertLocalCASecretsNeverInGetCa(t, f, created.Id, "rootKey", "issuingKey")
	})

	t.Run("imported", func(t *testing.T) {
		mat, _, err := localca.Generate(localca.Config{Subject: localca.Subject{CommonName: "Import Secrets"},
			KeyType: signer.EC256, RootValidityYears: 10, IssuingValidityYears: 3, MaxLeafDays: 397, CRL: true}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		certPEM := encodeCertPEM(mat.Issuing.Raw) + encodeCertPEM(mat.Root.Raw)
		keyPEM := encodeKeyPEM(t, mat.IssuingKey)
		res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
			Name: "SecretsImported", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "Import Secrets"}, "importPem": certPEM, "importKeyPem": keyPEM,
			}),
		}})
		if err != nil {
			t.Fatal(err)
		}
		created := res.(gen.CreateCa201JSONResponse)
		assertLocalCASecretsNeverInGetCa(t, f, created.Id, "issuingKey", "importKeyPem")
	})
}

// TestUpdateLocalCAConcurrentRotateNotLost covers the batch-3 review fix:
// updateLocalCA now locks the CA row FOR UPDATE for its whole
// read-check-write, the same lock Rotate takes, so an update and a
// concurrent rotate can never clobber each other — both effects must be
// present once both calls return, regardless of which ran first.
func TestUpdateLocalCAConcurrentRotateNotLost(t *testing.T) {
	f := newAPIFixture(t)
	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Concurrent", Type: ptrT(gen.Localca), Config: ptrT(localCASubjectConfig()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	created := res.(gen.CreateCa201JSONResponse)
	origIssuingPem, _ := created.Config["issuingPem"].(string)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := f.srv.UpdateCa(f.as("admin"), gen.UpdateCaRequestObject{OrgId: f.org, Id: created.Id, Body: &gen.CAInput{
			Name: "Concurrent", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
				"subject": map[string]interface{}{"commonName": "Test Root"}, "maxLeafDays": 45, "crl": true,
			}),
		}})
		errs <- err
	}()
	go func() {
		defer wg.Done()
		_, err := f.srv.RotateCa(f.as("admin"), gen.RotateCaRequestObject{OrgId: f.org, Id: created.Id})
		errs <- err
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := f.srv.GetCa(f.as("admin"), gen.GetCaRequestObject{OrgId: f.org, Id: created.Id})
	if err != nil {
		t.Fatal(err)
	}
	ca := got.(gen.GetCa200JSONResponse)
	if v, _ := ca.Config["maxLeafDays"].(float64); v != 45 {
		t.Fatalf("update lost: maxLeafDays = %v, want 45", ca.Config["maxLeafDays"])
	}
	newIssuingPem, _ := ca.Config["issuingPem"].(string)
	if newIssuingPem == "" || newIssuingPem == origIssuingPem {
		t.Fatal("rotate lost: issuingPem unchanged")
	}
	retired, ok := ca.Config["retired"].([]interface{})
	if !ok || len(retired) != 1 {
		t.Fatalf("rotate lost: retired = %v", ca.Config["retired"])
	}
}

// buildChainCert signs a CA certificate for cn under parent/parentKey
// (nil/nil for a self-signed root), for TestImportPreservesFullChain.
func buildChainCert(t *testing.T, parent *x509.Certificate, parentKey crypto.Signer, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	signParent, signKey := parent, parentKey
	if signParent == nil {
		signParent, signKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signParent, key.Public(), signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// TestImportPreservesFullChain covers the batch-3 review fix: importing a
// certificate whose chain has more than one certificate above the issuing
// certificate (issuing -> mid -> root, an intermediate genuinely between
// the issuing certificate and the self-signed root) used to lose "mid"
// entirely — only the root ever got persisted. A leaf issued afterward
// must carry the full chain (issuing + mid) in its ChainDER and verify
// through it up to the root.
func TestImportPreservesFullChain(t *testing.T) {
	f := newAPIFixture(t)
	root, rootKey := buildChainCert(t, nil, nil, "Root")
	mid, midKey := buildChainCert(t, root, rootKey, "Mid")
	issuing, issuingKey := buildChainCert(t, mid, midKey, "Issuing")

	certPEM := encodeCertPEM(issuing.Raw) + encodeCertPEM(mid.Raw) + encodeCertPEM(root.Raw)
	keyPEM := encodeKeyPEM(t, issuingKey)

	res, err := f.srv.CreateCa(f.as("admin"), gen.CreateCaRequestObject{OrgId: f.org, Body: &gen.CAInput{
		Name: "Chain", Type: ptrT(gen.Localca), Config: ptrT(map[string]interface{}{
			"subject": map[string]interface{}{"commonName": "Chain"}, "importPem": certPEM, "importKeyPem": keyPEM, "crl": false,
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
	if got.SerialNumber.Cmp(root.SerialNumber) != 0 {
		t.Fatal("trustBundlePem should be the last importPem certificate (the root)")
	}

	ctx := context.Background()
	domCA, err := f.store.GetCA(ctx, f.org, ca.Id)
	if err != nil {
		t.Fatal(err)
	}
	factory := &issuance.SignerFactory{Store: f.store, BaseURL: func(context.Context) string { return "" }}
	sig, err := factory.New(ctx, domCA)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sig.Issue(ctx, signer.IssueRequest{Names: []string{"leaf.example.test"}, KeyType: signer.EC256})
	if err != nil {
		t.Fatal(err)
	}
	if len(issued.ChainDER) != 2 {
		t.Fatalf("chainDER = %d entries, want 2 (issuing + mid)", len(issued.ChainDER))
	}
	midInChain, err := x509.ParseCertificate(issued.ChainDER[1])
	if err != nil {
		t.Fatal(err)
	}
	if midInChain.SerialNumber.Cmp(mid.SerialNumber) != 0 {
		t.Fatal("chainDER's second entry should be the intermediate (mid), not lost")
	}

	leaf, err := x509.ParseCertificate(issued.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	for _, c := range issued.ChainDER {
		cc, err := x509.ParseCertificate(c)
		if err != nil {
			t.Fatal(err)
		}
		inters.AddCert(cc)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf does not verify through the full chain: %v", err)
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
