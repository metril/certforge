package localca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/metril/certforge/internal/signer"
)

// policyCert builds a CA certificate for cn over pub, signed by parent/
// parentKey (self-signed when parent is nil) with alg (0 = default).
func policyCert(t *testing.T, cn string, pub crypto.PublicKey, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer, alg x509.SignatureAlgorithm, now time.Time) *x509.Certificate {
	t.Helper()
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, SignatureAlgorithm: alg,
	}
	signParent, signKey := parent, parentKey
	if parent == nil {
		signParent, signKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signParent, pub, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyPEMOf(t *testing.T, k crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return encodeKeyPEM(t, der)
}

func TestImportChainPolicy(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rootKey := ecKey(t)
	root := policyCert(t, "Root", rootKey.Public(), rootKey, nil, nil, 0, now)
	issKey := ecKey(t)
	iss := policyCert(t, "Issuing", issKey.Public(), issKey, root, rootKey, 0, now)

	t.Run("valid bundle passes", func(t *testing.T) {
		if _, err := Import(encodeCertPEM(t, iss.Raw)+encodeCertPEM(t, root.Raw), keyPEMOf(t, issKey), false, now); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unrelated root refused", func(t *testing.T) {
		otherKey := ecKey(t)
		other := policyCert(t, "Other Root", otherKey.Public(), otherKey, nil, nil, 0, now)
		if _, err := Import(encodeCertPEM(t, iss.Raw)+encodeCertPEM(t, other.Raw), keyPEMOf(t, issKey), false, now); err == nil {
			t.Fatal("want error for a chain that did not sign the issuing certificate")
		}
	})

	t.Run("RSA-1024 refused", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		c := policyCert(t, "Weak RSA", k.Public(), k, nil, nil, 0, now)
		if _, err := Import(encodeCertPEM(t, c.Raw), keyPEMOf(t, k), false, now); err == nil {
			t.Fatal("want error for an RSA-1024 key")
		}
	})

	t.Run("SHA-1 signature refused", func(t *testing.T) {
		c := policyCert(t, "SHA1 Issuing", issKey.Public(), issKey, root, rootKey, x509.ECDSAWithSHA1, now)
		if _, err := Import(encodeCertPEM(t, c.Raw)+encodeCertPEM(t, root.Raw), keyPEMOf(t, issKey), false, now); err == nil {
			t.Fatal("want error for a SHA-1 signed issuing certificate")
		}
	})
}

func TestRotateRefusesExpiredRoot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(signer.EC256)
	mat, rootKey, err := Generate(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(mat.Root, append([]byte(nil), rootKey...), cfg, mat.Root.NotAfter); err == nil {
		t.Fatal("want error rotating under an expired root")
	}
}

func TestRotationsInOneMonthGetDistinctNames(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(signer.EC256)
	mat, rootKey, err := Generate(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Rotate(mat.Root, append([]byte(nil), rootKey...), cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Rotate(mat.Root, append([]byte(nil), rootKey...), cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuing.Subject.CommonName == b.Issuing.Subject.CommonName {
		t.Fatalf("both rotations got CN %q", a.Issuing.Subject.CommonName)
	}
}

func TestParsePrivateKeyPEMSkipsECParameters(t *testing.T) {
	k := ecKey(t)
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	// prime256v1 OID 1.2.840.10045.3.1.7
	params := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}})
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	got, err := parsePrivateKeyPEM(string(params) + string(body))
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(got.(*ecdsa.PrivateKey).Public(), k.Public()) {
		t.Fatal("wrong key parsed")
	}
}
