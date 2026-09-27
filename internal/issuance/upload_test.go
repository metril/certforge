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
	"strings"
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

// chainKit is a real leaf -> intermediate -> root signing chain: unlike
// genCert/ecCert's independent self-signed certificates, each link here
// actually satisfies CheckSignatureFrom against the one above it, so it
// exercises ParseUpload's chain validation (fix round 1) rather than
// tripping over it.
type chainKit struct {
	leafDER, intDER, rootDER []byte
	leafKey                  *ecdsa.PrivateKey
}

func buildChain(t *testing.T, cn string) chainKit {
	t.Helper()
	now := time.Now()
	caTpl := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
			IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTpl := caTpl(100, "Test Root")
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTpl := caTpl(101, "Test Intermediate")
	intDER, err := x509.CreateCertificate(rand.Reader, intTpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), DNSNames: []string{cn}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatal(err)
	}
	return chainKit{leafDER: leafDER, intDER: intDER, rootDER: rootDER, leafKey: leafKey}
}

func TestParseUploadPEM(t *testing.T) {
	ck := buildChain(t, "leaf.example.test")
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ck.leafKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(append(certPEM(ck.leafDER), certPEM(ck.intDER)...), certPEM(ck.rootDER)...)

	iss, kt, err := ParseUpload(UploadInput{CertificatePEM: bundle, PrivateKeyPEM: pemBlock("PRIVATE KEY", pkcs8)})
	if err != nil {
		t.Fatal(err)
	}
	if string(iss.LeafDER) != string(ck.leafDER) {
		t.Fatal("leaf mismatch")
	}
	if len(iss.ChainDER) != 2 || string(iss.ChainDER[0]) != string(ck.intDER) || string(iss.ChainDER[1]) != string(ck.rootDER) {
		t.Fatalf("chain order wrong: %d entries", len(iss.ChainDER))
	}
	if kt != signer.EC256 {
		t.Fatalf("key type = %s", kt)
	}
	if len(iss.PrivateKeyPKCS8) == 0 {
		t.Fatal("expected a stored key")
	}

	// Keyless: no PrivateKeyPEM at all.
	iss2, kt2, err := ParseUpload(UploadInput{CertificatePEM: certPEM(ck.leafDER)})
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

// TestParseUploadChainReordered is fix round 1: a chain submitted out of
// signing order (root before intermediate) is reordered by issuer, not
// stored as submitted.
func TestParseUploadChainReordered(t *testing.T) {
	ck := buildChain(t, "reordered.example.test")
	bundle := append(append(certPEM(ck.leafDER), certPEM(ck.rootDER)...), certPEM(ck.intDER)...)
	iss, _, err := ParseUpload(UploadInput{CertificatePEM: bundle})
	if err != nil {
		t.Fatal(err)
	}
	if len(iss.ChainDER) != 2 || string(iss.ChainDER[0]) != string(ck.intDER) || string(iss.ChainDER[1]) != string(ck.rootDER) {
		t.Fatalf("chain not reordered by issuer: %d entries", len(iss.ChainDER))
	}
}

// TestParseUploadChainDropsRepeatedLeaf is fix round 1: a leaf repeated in
// the chain (some tools emit the leaf again when building a "fullchain"
// bundle) is dropped, not kept as a redundant chain entry.
func TestParseUploadChainDropsRepeatedLeaf(t *testing.T) {
	ck := buildChain(t, "repeat.example.test")
	bundle := append(append(append(certPEM(ck.leafDER), certPEM(ck.leafDER)...), certPEM(ck.intDER)...), certPEM(ck.rootDER)...)
	iss, _, err := ParseUpload(UploadInput{CertificatePEM: bundle})
	if err != nil {
		t.Fatal(err)
	}
	if len(iss.ChainDER) != 2 || string(iss.ChainDER[0]) != string(ck.intDER) || string(iss.ChainDER[1]) != string(ck.rootDER) {
		t.Fatalf("leaf not dropped from chain: %d entries", len(iss.ChainDER))
	}
}

// TestParseUploadChainMustSignLeaf is fix round 1: a chain entry whose
// Subject matches the leaf's Issuer (so it looks like the right next
// link) but never actually signed it is a 422, not silently accepted.
func TestParseUploadChainMustSignLeaf(t *testing.T) {
	ck := buildChain(t, "wrongchain.example.test")
	fakeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fakeTpl := &x509.Certificate{SerialNumber: big.NewInt(777), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	fakeDER, err := x509.CreateCertificate(rand.Reader, fakeTpl, fakeTpl, &fakeKey.PublicKey, fakeKey)
	if err != nil {
		t.Fatal(err)
	}

	bundle := append(certPEM(ck.leafDER), certPEM(fakeDER)...)
	_, _, err = ParseUpload(UploadInput{CertificatePEM: bundle})
	var ve *ValidationError
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.As(err, &ve) || ve.Field != "certificatePem" || !strings.Contains(ve.Msg, "did not sign") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseUploadPKCS12(t *testing.T) {
	ck := buildChain(t, "p12.example.test")
	leaf, err := x509.ParseCertificate(ck.leafDER)
	if err != nil {
		t.Fatal(err)
	}
	intCert, err := x509.ParseCertificate(ck.intDER)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(ck.rootDER)
	if err != nil {
		t.Fatal(err)
	}
	// caCerts given to the encoder in reverse (bag) order: root before
	// intermediate, so a correct reorder-by-issuer is what makes this pass.
	p12, err := pkcs12.Modern2023.Encode(ck.leafKey, leaf, []*x509.Certificate{rootCert, intCert}, "s3cret!")
	if err != nil {
		t.Fatal(err)
	}

	iss, kt, err := ParseUpload(UploadInput{PKCS12: p12, Password: "s3cret!"})
	if err != nil {
		t.Fatal(err)
	}
	if string(iss.LeafDER) != string(ck.leafDER) {
		t.Fatal("leaf mismatch")
	}
	if len(iss.ChainDER) != 2 || string(iss.ChainDER[0]) != string(ck.intDER) || string(iss.ChainDER[1]) != string(ck.rootDER) {
		t.Fatalf("chain not reordered by issuer from PKCS#12 bag order: %d entries", len(iss.ChainDER))
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
