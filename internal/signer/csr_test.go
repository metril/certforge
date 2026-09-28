package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net"
	"testing"
)

func TestSplitNames(t *testing.T) {
	dns, ips := SplitNames([]string{"example.com", "10.0.0.1", "*.example.com", "::1"})
	wantDNS := []string{"example.com", "*.example.com"}
	if len(dns) != len(wantDNS) {
		t.Fatalf("dns = %v, want %v", dns, wantDNS)
	}
	for i, d := range wantDNS {
		if dns[i] != d {
			t.Fatalf("dns[%d] = %q, want %q", i, dns[i], d)
		}
	}
	if len(ips) != 2 {
		t.Fatalf("ips = %v, want 2 entries", ips)
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.1")) || !ips[1].Equal(net.ParseIP("::1")) {
		t.Fatalf("ips = %v", ips)
	}
}

func TestNewKeyAndCSRGeneratesPerKeyType(t *testing.T) {
	for _, kt := range []KeyType{RSA2048, RSA3072, RSA4096, EC256, EC384} {
		t.Run(string(kt), func(t *testing.T) {
			key, pkcs8, csrDER, err := NewKeyAndCSR(IssueRequest{Names: []string{"example.com", "10.0.0.9"}, KeyType: kt})
			if err != nil {
				t.Fatal(err)
			}
			if key == nil {
				t.Fatal("nil key returned")
			}
			got, err := KeyTypeOf(key.Public())
			if err != nil || got != kt {
				t.Fatalf("key type = %v, %v; want %v", got, err, kt)
			}
			if _, err := x509.ParsePKCS8PrivateKey(pkcs8); err != nil {
				t.Fatalf("parse pkcs8: %v", err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatalf("parse csr: %v", err)
			}
			if err := csr.CheckSignature(); err != nil {
				t.Fatalf("csr signature: %v", err)
			}
			if csr.Subject.CommonName != "example.com" {
				t.Fatalf("cn = %q", csr.Subject.CommonName)
			}
			if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "example.com" {
				t.Fatalf("dns names = %v", csr.DNSNames)
			}
			if len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(net.ParseIP("10.0.0.9")) {
				t.Fatalf("ip addresses = %v", csr.IPAddresses)
			}
		})
	}
}

// TestNewKeyAndCSRReuse covers the ReuseKeyPKCS8 path: the returned key and
// the CSR's public key must be the caller-supplied key, not a freshly
// generated one.
func TestNewKeyAndCSRReuse(t *testing.T) {
	want, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantPKCS8, err := x509.MarshalPKCS8PrivateKey(want)
	if err != nil {
		t.Fatal(err)
	}
	reuse := append([]byte(nil), wantPKCS8...)

	key, pkcs8, csrDER, err := NewKeyAndCSR(IssueRequest{
		Names:         []string{"reused.example.com"},
		KeyType:       EC256,
		ReuseKeyPKCS8: reuse,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := key.(*ecdsa.PrivateKey)
	if !ok || !got.Equal(want) {
		t.Fatalf("returned key is not the reused key")
	}
	if len(pkcs8) == 0 {
		t.Fatal("empty pkcs8")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&want.PublicKey) {
		t.Fatal("csr public key does not match the reused key")
	}
}

func TestNewKeyAndCSRRequiresNames(t *testing.T) {
	if _, _, _, err := NewKeyAndCSR(IssueRequest{KeyType: EC256}); err == nil {
		t.Fatal("want error for no names")
	}
}
