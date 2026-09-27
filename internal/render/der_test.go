package render

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// realMaterial builds Material with a real, parseable self-signed leaf,
// one chain cert, and a PKCS#8 key, for renderers (DER/PKCS12/JKS) that
// parse their input rather than treating it as opaque bytes.
func realMaterial(t *testing.T, cn string, serial int64) Material {
	t.Helper()
	leafDER, key := selfSignedCert(t, cn, serial, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	chainDER, _ := selfSignedCert(t, "Test Intermediate", serial+1000, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Material{LeafDER: leafDER, ChainDER: [][]byte{chainDER}, PrivateKeyPKCS8: pkcs8}
}

func selfSignedCert(t *testing.T, cn string, serial int64, notBefore time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notBefore.AddDate(0, 3, 0),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func TestDERParts(t *testing.T) {
	m := realMaterial(t, "a.example.test", 1)

	files, err := DER{}.Render(m, OutputOpts{Parts: []string{"cert", "chain", "key"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d files, want 3", len(files))
	}
	if files[0].Name != "cert.der" {
		t.Fatalf("cert file name = %q", files[0].Name)
	}
	leaf, err := x509.ParseCertificate(files[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "a.example.test" {
		t.Fatalf("cert.der parsed to %q", leaf.Subject.CommonName)
	}
	if files[1].Name != "chain-1.der" {
		t.Fatalf("chain file name = %q", files[1].Name)
	}
	if _, err := x509.ParseCertificate(files[1].Data); err != nil {
		t.Fatal(err)
	}
	if files[2].Name != "privkey.der" || !files[2].Secret {
		t.Fatalf("key file = %+v", files[2])
	}
	if _, err := x509.ParsePKCS8PrivateKey(files[2].Data); err != nil {
		t.Fatal(err)
	}

	if _, err := (DER{}).Render(m, OutputOpts{Parts: []string{"fullchain"}}); !errors.Is(err, ErrNotDER) {
		t.Fatalf("fullchain: %v", err)
	}
	if _, err := (DER{}).Render(m, OutputOpts{Parts: []string{"combined"}}); !errors.Is(err, ErrNotDER) {
		t.Fatalf("combined: %v", err)
	}
}

func TestDERMultipleChainCerts(t *testing.T) {
	m := realMaterial(t, "b.example.test", 2)
	extra, _ := selfSignedCert(t, "Root", 999, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	m.ChainDER = append(m.ChainDER, extra)

	files, err := DER{}.Render(m, OutputOpts{Parts: []string{"chain"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Name != "chain-1.der" || files[1].Name != "chain-2.der" {
		t.Fatalf("chain files: %+v", files)
	}
}

func TestDERNoKey(t *testing.T) {
	m := realMaterial(t, "c.example.test", 3)
	m.PrivateKeyPKCS8 = nil
	if _, err := (DER{}).Render(m, OutputOpts{Parts: []string{"key"}}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("key without material: %v", err)
	}
}
