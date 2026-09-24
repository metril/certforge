package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, cn string, serial int64) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func TestIssuedFromPEM(t *testing.T) {
	leafDER, key := selfSigned(t, "a.example.test", 0xbeef)
	chainDER, _ := selfSigned(t, "Test Intermediate", 2)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chainDER})...)
	sec1, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})

	got, err := IssuedFromPEM(bundle, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.LeafDER) != string(leafDER) || len(got.ChainDER) != 1 || string(got.ChainDER[0]) != string(chainDER) {
		t.Fatal("leaf/chain split wrong")
	}
	if got.Serial != "beef" {
		t.Fatalf("serial = %q", got.Serial)
	}
	if !got.NotAfter.Equal(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("notAfter = %v", got.NotAfter)
	}
	k, err := x509.ParsePKCS8PrivateKey(got.PrivateKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	if !k.(*ecdsa.PrivateKey).Equal(key) {
		t.Fatal("key mismatch")
	}
}

func TestIssuedFromPEMRejectsEmpty(t *testing.T) {
	if _, err := IssuedFromPEM([]byte("junk"), nil); err == nil {
		t.Fatal("want error")
	}
}

func TestErrorShortType(t *testing.T) {
	e := &Error{Type: "urn:ietf:params:acme:error:rateLimited"}
	if e.ShortType() != "rateLimited" {
		t.Fatal(e.ShortType())
	}
}
