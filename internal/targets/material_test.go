package targets_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/metril/certforge/internal/targets"
)

// selfSignedPair returns a leaf certificate DER, its PKCS8 key DER, and the
// two PEM-encoded so MaterialFromPEM can parse them back.
func selfSignedPair(t *testing.T, cn string) (leafDER, keyPKCS8 []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return der, pk8
}

func TestMaterialFromPEMRoundTrip(t *testing.T) {
	leafDER, keyDER := selfSignedPair(t, "leaf.example.test")
	chainDER, _ := selfSignedPair(t, "chain.example.test")

	var fullchain bytes.Buffer
	fullchain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	fullchain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chainDER}))
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	m, err := targets.MaterialFromPEM(fullchain.Bytes(), keyPEM)
	if err != nil {
		t.Fatalf("MaterialFromPEM: %v", err)
	}
	if !bytes.Equal(m.LeafDER, leafDER) {
		t.Errorf("LeafDER mismatch")
	}
	if len(m.ChainDER) != 1 || !bytes.Equal(m.ChainDER[0], chainDER) {
		t.Errorf("ChainDER = %v, want [chainDER]", m.ChainDER)
	}
	if !bytes.Equal(m.PrivateKeyPKCS8, keyDER) {
		t.Errorf("PrivateKeyPKCS8 mismatch")
	}
}

func TestMaterialFromPEMNoCertificate(t *testing.T) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(mustKey(t))
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := targets.MaterialFromPEM([]byte("not pem"), keyPEM); err == nil {
		t.Fatal("MaterialFromPEM did not fail with no certificate block")
	}
}

func TestMaterialFromPEMNoKey(t *testing.T) {
	leafDER, _ := selfSignedPair(t, "leaf.example.test")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	if _, err := targets.MaterialFromPEM(certPEM, []byte("not pem")); err == nil {
		t.Fatal("MaterialFromPEM did not fail with no key block")
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}
