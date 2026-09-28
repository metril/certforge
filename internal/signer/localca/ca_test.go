package localca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/signer"
)

func testCfg(kt signer.KeyType) Config {
	return Config{
		Subject:              Subject{CommonName: "Test Root", Organization: "Test Org", Country: "US"},
		KeyType:              kt,
		RootValidityYears:    10,
		IssuingValidityYears: 3,
		MaxLeafDays:          397,
		CRL:                  true,
	}
}

func encodeCertPEM(t *testing.T, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func encodeKeyPEM(t *testing.T, pkcs8 []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
}

func TestGenerateRootAndIssuing(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, kt := range []signer.KeyType{signer.EC256, signer.EC384, signer.RSA2048, signer.RSA4096} {
		t.Run(string(kt), func(t *testing.T) {
			cfg := testCfg(kt)
			mat, rootKeyPKCS8, err := Generate(cfg, now)
			if err != nil {
				t.Fatal(err)
			}
			if mat.Root == nil || !mat.Root.IsCA {
				t.Fatal("root is not a CA")
			}
			if mat.Root.MaxPathLen != 1 || mat.Root.MaxPathLenZero {
				t.Fatalf("root path len = %d/%v, want 1/false", mat.Root.MaxPathLen, mat.Root.MaxPathLenZero)
			}
			if mat.Root.KeyUsage&x509.KeyUsageCertSign == 0 || mat.Root.KeyUsage&x509.KeyUsageCRLSign == 0 {
				t.Fatal("root missing CertSign/CRLSign")
			}
			if len(mat.Root.SubjectKeyId) == 0 {
				t.Fatal("root missing SubjectKeyId")
			}
			if mat.Root.NotAfter.Year()-mat.Root.NotBefore.Year() < cfg.RootValidityYears-1 {
				t.Fatalf("root validity too short: %v to %v", mat.Root.NotBefore, mat.Root.NotAfter)
			}

			if mat.Issuing == nil || !mat.Issuing.IsCA {
				t.Fatal("issuing is not a CA")
			}
			if !mat.Issuing.MaxPathLenZero {
				t.Fatal("issuing is not MaxPathLenZero")
			}
			if mat.Issuing.KeyUsage&x509.KeyUsageCertSign == 0 || mat.Issuing.KeyUsage&x509.KeyUsageCRLSign == 0 {
				t.Fatal("issuing missing CertSign/CRLSign")
			}
			if len(mat.Issuing.SubjectKeyId) == 0 {
				t.Fatal("issuing missing SubjectKeyId")
			}
			if !bytes.Equal(mat.Issuing.AuthorityKeyId, mat.Root.SubjectKeyId) {
				t.Fatal("issuing AuthorityKeyId does not match root SubjectKeyId")
			}
			if !strings.Contains(mat.Issuing.Subject.CommonName, "Issuing CA 2026-01") {
				t.Fatalf("issuing cn = %q, want suffix 'Issuing CA 2026-01'", mat.Issuing.Subject.CommonName)
			}

			gotKT, err := signer.KeyTypeOf(mat.IssuingKey.Public())
			if err != nil || gotKT != kt {
				t.Fatalf("issuing key type = %v, %v; want %v", gotKT, err, kt)
			}
			if _, err := x509.ParsePKCS8PrivateKey(rootKeyPKCS8); err != nil {
				t.Fatalf("root key pkcs8: %v", err)
			}

			roots := x509.NewCertPool()
			roots.AddCert(mat.Root)
			if _, err := mat.Issuing.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Fatalf("issuing does not verify against root: %v", err)
			}
		})
	}
}

func TestGeneratedCertsCanSignCRLs(t *testing.T) {
	mat, _, err := Generate(testCfg(signer.EC256), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*x509.Certificate{"root": mat.Root, "issuing": mat.Issuing} {
		if c.KeyUsage&x509.KeyUsageCRLSign == 0 {
			t.Errorf("%s: missing CRLSign key usage", name)
		}
		if len(c.SubjectKeyId) == 0 {
			t.Errorf("%s: missing SubjectKeyId", name)
		}
	}
}

func TestImportIssuingAndChain(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mat, _, err := Generate(testCfg(signer.EC256), now)
	if err != nil {
		t.Fatal(err)
	}
	issuingKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(mat.IssuingKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := encodeCertPEM(t, mat.Issuing.Raw) + encodeCertPEM(t, mat.Root.Raw)
	keyPEM := encodeKeyPEM(t, issuingKeyPKCS8)

	t.Run("valid", func(t *testing.T) {
		got, err := Import(certPEM, keyPEM, true, now)
		if err != nil {
			t.Fatal(err)
		}
		if got.Root == nil || got.Root.SerialNumber.Cmp(mat.Root.SerialNumber) != 0 {
			t.Fatal("root not recognized as the last self-signed chain entry")
		}
		if got.Issuing.SerialNumber.Cmp(mat.Issuing.SerialNumber) != 0 {
			t.Fatal("issuing certificate mismatch")
		}
		if len(got.Chain) != 1 || got.Chain[0].SerialNumber.Cmp(mat.Root.SerialNumber) != 0 {
			t.Fatalf("chain = %v, want [root]", got.Chain)
		}
		if got.IssuingKey == nil {
			t.Fatal("issuing key not set")
		}
	})

	t.Run("key mismatch rejected", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		otherPKCS8, err := x509.MarshalPKCS8PrivateKey(other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Import(certPEM, encodeKeyPEM(t, otherPKCS8), true, now); err == nil {
			t.Fatal("want error for mismatched key")
		}
	})

	t.Run("non-CA cert rejected", func(t *testing.T) {
		leafPEM, leafKeyPEM := selfSignedNonCA(t, now)
		if _, err := Import(leafPEM, leafKeyPEM, false, now); err == nil {
			t.Fatal("want error for non-CA certificate")
		}
	})

	t.Run("expired cert rejected", func(t *testing.T) {
		expiredPEM, expiredKeyPEM := expiredIssuingCA(t, now)
		if _, err := Import(expiredPEM, expiredKeyPEM, false, now); err == nil {
			t.Fatal("want error for expired certificate")
		}
	})
}

func TestImportWithoutCRLSignRejected(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	certPEM, keyPEM := issuingWithoutCRLSign(t, now)

	_, err := Import(certPEM, keyPEM, true, now)
	if !errors.Is(err, ErrCannotSignCRL) {
		t.Fatalf("crl:true got %v, want ErrCannotSignCRL", err)
	}

	if _, err := Import(certPEM, keyPEM, false, now); err != nil {
		t.Fatalf("crl:false should not require CRLSign: %v", err)
	}
}

func TestRotateKeepsOldLeavesVerifying(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(signer.EC256)
	mat, rootKeyPKCS8, err := Generate(cfg, now)
	if err != nil {
		t.Fatal(err)
	}

	s := New(mat, cfg, noopRecorder{}, Opts{Now: func() time.Time { return now }})
	issued, err := s.Issue(context.Background(), signer.IssueRequest{Names: []string{"old.example.com"}, KeyType: signer.EC256})
	if err != nil {
		t.Fatal(err)
	}
	oldLeaf, err := x509.ParseCertificate(issued.LeafDER)
	if err != nil {
		t.Fatal(err)
	}

	rootKeyPKCS8Copy := append([]byte(nil), rootKeyPKCS8...)
	later := now.AddDate(1, 0, 0)
	newMat, err := Rotate(mat.Root, rootKeyPKCS8Copy, cfg, later)
	if err != nil {
		t.Fatal(err)
	}
	if newMat.Issuing.SerialNumber.Cmp(mat.Issuing.SerialNumber) == 0 {
		t.Fatal("rotate produced the same issuing serial")
	}

	roots := x509.NewCertPool()
	roots.AddCert(mat.Root)
	oldInters := x509.NewCertPool()
	oldInters.AddCert(mat.Issuing)
	if _, err := oldLeaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: oldInters, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("old leaf no longer verifies after rotation: %v", err)
	}

	s2 := New(newMat, cfg, noopRecorder{}, Opts{Now: func() time.Time { return later }})
	issued2, err := s2.Issue(context.Background(), signer.IssueRequest{Names: []string{"new.example.com"}, KeyType: signer.EC256})
	if err != nil {
		t.Fatal(err)
	}
	newLeaf, err := x509.ParseCertificate(issued2.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	newInters := x509.NewCertPool()
	newInters.AddCert(newMat.Issuing)
	if _, err := newLeaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: newInters, CurrentTime: later, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("new leaf does not verify: %v", err)
	}
}

// --- test helpers shared by the localca test files ---

type noopRecorder struct{}

func (noopRecorder) Revoke(ctx context.Context, serial, issuerSerial string, reason int, at time.Time) error {
	return nil
}

func selfSignedNonCA(t *testing.T, now time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encodeCertPEM(t, der), encodeKeyPEM(t, pkcs8)
}

func expiredIssuingCA(t *testing.T, now time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "expired issuing"},
		NotBefore:             now.Add(-2 * 365 * 24 * time.Hour),
		NotAfter:              now.Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encodeCertPEM(t, der), encodeKeyPEM(t, pkcs8)
}

func issuingWithoutCRLSign(t *testing.T, now time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "issuing without crlsign"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encodeCertPEM(t, der), encodeKeyPEM(t, pkcs8)
}
