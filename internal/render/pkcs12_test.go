package render

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestPKCS12RoundTrip(t *testing.T) {
	m := realMaterial(t, "p12.example.test", 10)
	extra := realMaterial(t, "extra.example.test", 20)

	for _, encoding := range []string{"modern", "legacy"} {
		files, err := PKCS12{}.Render(m, OutputOpts{Password: "hunter2", Encoding: encoding, BaseName: "bundle", Extras: []Material{extra}})
		if err != nil {
			t.Fatalf("%s: %v", encoding, err)
		}
		if len(files) != 1 || files[0].Name != "bundle.p12" || !files[0].Secret {
			t.Fatalf("%s: files = %+v", encoding, files)
		}
		key, leaf, caCerts, err := pkcs12.DecodeChain(files[0].Data, "hunter2")
		if err != nil {
			t.Fatalf("%s: decode: %v", encoding, err)
		}
		if !bytes.Equal(leaf.Raw, m.LeafDER) {
			t.Fatalf("%s: leaf mismatch", encoding)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("%s: key type %T", encoding, key)
		}
		wantKeyAny, err := x509.ParsePKCS8PrivateKey(m.PrivateKeyPKCS8)
		if err != nil {
			t.Fatal(err)
		}
		if !ecKey.Equal(wantKeyAny.(*ecdsa.PrivateKey)) {
			t.Fatalf("%s: key mismatch", encoding)
		}
		if !containsRaw(caCerts, m.ChainDER[0]) {
			t.Fatalf("%s: chain cert not among CA certs", encoding)
		}
		if !containsRaw(caCerts, extra.LeafDER) || !containsRaw(caCerts, extra.ChainDER[0]) {
			t.Fatalf("%s: extra leaf/chain not among CA certs", encoding)
		}
	}
}

func TestPKCS12EmptyPassword(t *testing.T) {
	m := realMaterial(t, "p12.example.test", 11)
	if _, err := (PKCS12{}).Render(m, OutputOpts{Password: "", BaseName: "bundle"}); !errors.Is(err, ErrPassword) {
		t.Fatalf("empty password: %v", err)
	}
}

func TestPKCS12NoKey(t *testing.T) {
	m := realMaterial(t, "p12.example.test", 12)
	m.PrivateKeyPKCS8 = nil
	if _, err := (PKCS12{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle"}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
}

func containsRaw(certs []*x509.Certificate, raw []byte) bool {
	for _, c := range certs {
		if bytes.Equal(c.Raw, raw) {
			return true
		}
	}
	return false
}
