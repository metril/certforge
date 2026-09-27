package issuance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/metril/certforge/internal/signer"
)

// genCert returns a self-signed leaf's DER and its signing key. pub/priv let
// the caller drive the key algorithm (RSA, EC, ed25519); serial makes
// distinct certificates for chain-order tests.
func genCert(t *testing.T, cn string, serial int64, pub any, priv any) []byte {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func ecCert(t *testing.T, cn string, serial int64) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return genCert(t, cn, serial, &key.PublicKey, key), key
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func certPEM(der []byte) []byte { return pemBlock("CERTIFICATE", der) }

func TestParseUploadPEM(t *testing.T) {
	leafDER, key := ecCert(t, "leaf.example.test", 1)
	chain1DER, _ := ecCert(t, "intermediate-1.example.test", 2)
	chain2DER, _ := ecCert(t, "intermediate-2.example.test", 3)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(append(certPEM(leafDER), certPEM(chain1DER)...), certPEM(chain2DER)...)

	iss, kt, err := ParseUpload(UploadInput{CertificatePEM: bundle, PrivateKeyPEM: pemBlock("PRIVATE KEY", pkcs8)})
	if err != nil {
		t.Fatal(err)
	}
	if string(iss.LeafDER) != string(leafDER) {
		t.Fatal("leaf mismatch")
	}
	if len(iss.ChainDER) != 2 || string(iss.ChainDER[0]) != string(chain1DER) || string(iss.ChainDER[1]) != string(chain2DER) {
		t.Fatalf("chain order wrong: %d entries", len(iss.ChainDER))
	}
	if kt != signer.EC256 {
		t.Fatalf("key type = %s", kt)
	}
	if len(iss.PrivateKeyPKCS8) == 0 {
		t.Fatal("expected a stored key")
	}

	// Keyless: no PrivateKeyPEM at all.
	iss2, kt2, err := ParseUpload(UploadInput{CertificatePEM: certPEM(leafDER)})
	if err != nil {
		t.Fatal(err)
	}
	if len(iss2.PrivateKeyPKCS8) != 0 {
		t.Fatal("keyless upload stored a key")
	}
	if kt2 != signer.EC256 {
		t.Fatalf("keyless key type = %s", kt2)
	}
}

func TestParseUploadPKCS12(t *testing.T) {
	leafDER, key := ecCert(t, "p12.example.test", 10)
	chainDER, _ := ecCert(t, "p12-int.example.test", 11)
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chainCert, err := x509.ParseCertificate(chainDER)
	if err != nil {
		t.Fatal(err)
	}
	p12, err := pkcs12.Modern2023.Encode(key, leaf, []*x509.Certificate{chainCert}, "s3cret!")
	if err != nil {
		t.Fatal(err)
	}

	iss, kt, err := ParseUpload(UploadInput{PKCS12: p12, Password: "s3cret!"})
	if err != nil {
		t.Fatal(err)
	}
	if string(iss.LeafDER) != string(leafDER) {
		t.Fatal("leaf mismatch")
	}
	if len(iss.ChainDER) != 1 || string(iss.ChainDER[0]) != string(chainDER) {
		t.Fatalf("chain = %d entries", len(iss.ChainDER))
	}
	if len(iss.PrivateKeyPKCS8) == 0 {
		t.Fatal("expected a stored key")
	}
	if kt != signer.EC256 {
		t.Fatalf("key type = %s", kt)
	}
}

func TestParseUploadKeyMismatch(t *testing.T) {
	leafDER, _ := ecCert(t, "leaf.example.test", 20)
	_, other := ecCert(t, "other.example.test", 21)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ParseUpload(UploadInput{CertificatePEM: certPEM(leafDER), PrivateKeyPEM: pemBlock("PRIVATE KEY", pkcs8)})
	var ve *ValidationError
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.As(err, &ve) || ve.Field != "privateKeyPem" {
		t.Fatalf("err = %v", err)
	}
}

func TestParseUploadKeyEncodings(t *testing.T) {
	t.Run("pkcs1", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		leafDER := genCert(t, "rsa.example.test", 30, &rk.PublicKey, rk)
		iss, kt, err := ParseUpload(UploadInput{CertificatePEM: certPEM(leafDER), PrivateKeyPEM: pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk))})
		if err != nil {
			t.Fatal(err)
		}
		if kt != signer.RSA2048 || len(iss.PrivateKeyPKCS8) == 0 {
			t.Fatalf("kt=%s key=%d", kt, len(iss.PrivateKeyPKCS8))
		}
	})
	t.Run("sec1", func(t *testing.T) {
		leafDER, key := ecCert(t, "ec-sec1.example.test", 31)
		sec1, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		iss, kt, err := ParseUpload(UploadInput{CertificatePEM: certPEM(leafDER), PrivateKeyPEM: pemBlock("EC PRIVATE KEY", sec1)})
		if err != nil {
			t.Fatal(err)
		}
		if kt != signer.EC256 || len(iss.PrivateKeyPKCS8) == 0 {
			t.Fatalf("kt=%s key=%d", kt, len(iss.PrivateKeyPKCS8))
		}
	})
	t.Run("pkcs8", func(t *testing.T) {
		leafDER, key := ecCert(t, "ec-pkcs8.example.test", 32)
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		iss, kt, err := ParseUpload(UploadInput{CertificatePEM: certPEM(leafDER), PrivateKeyPEM: pemBlock("PRIVATE KEY", pkcs8)})
		if err != nil {
			t.Fatal(err)
		}
		if kt != signer.EC256 || len(iss.PrivateKeyPKCS8) == 0 {
			t.Fatalf("kt=%s key=%d", kt, len(iss.PrivateKeyPKCS8))
		}
	})
}

func TestParseUploadUnsupportedKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER := genCert(t, "ed25519.example.test", 40, pub, priv)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ParseUpload(UploadInput{CertificatePEM: certPEM(leafDER), PrivateKeyPEM: pemBlock("PRIVATE KEY", pkcs8)})
	var ve *ValidationError
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v (not a ValidationError)", err)
	}
}
