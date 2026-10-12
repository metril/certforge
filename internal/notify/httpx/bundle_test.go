package httpx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertPEM(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestNormalizeCABundle(t *testing.T) {
	c := testCertPEM(t)
	if out, err := NormalizeCABundle(""); err != nil || out != "" {
		t.Fatalf("empty: %q %v", out, err)
	}
	out, err := NormalizeCABundle("  " + strings.ReplaceAll(c+c, "\n", "\r\n") + "\n")
	if err != nil || strings.Contains(out, "\r") || strings.Count(out, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("crlf/two: %q %v", out, err)
	}
	bad := []string{"hello", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})), c + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}
	for _, b := range bad {
		if _, err := NormalizeCABundle(b); err == nil {
			t.Fatalf("accepted %q", b)
		}
	}
}
