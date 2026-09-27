package render

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestJKSRoundTrip(t *testing.T) {
	m := realMaterial(t, "jks.example.test", 30)
	extra := realMaterial(t, "extra.example.test", 40)

	files, err := (JKS{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle", Extras: []Material{extra}})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != "bundle.jks" || !files[0].Secret {
		t.Fatalf("files = %+v", files)
	}

	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(files[0].Data), []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	pke, err := ks.GetPrivateKeyEntry("bundle", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pke.PrivateKey, m.PrivateKeyPKCS8) {
		t.Fatal("key mismatch")
	}
	if len(pke.CertificateChain) != 2 || !bytes.Equal(pke.CertificateChain[0].Content, m.LeafDER) ||
		!bytes.Equal(pke.CertificateChain[1].Content, m.ChainDER[0]) {
		t.Fatalf("chain = %+v", pke.CertificateChain)
	}
	if !ks.IsTrustedCertificateEntry("extra-1") {
		t.Fatal("extra-1 not trusted")
	}
	tce, err := ks.GetTrustedCertificateEntry("extra-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tce.Certificate.Content, extra.LeafDER) {
		t.Fatal("extra-1 content mismatch")
	}
}

func TestJKSShortPasswordRejected(t *testing.T) {
	m := realMaterial(t, "jks.example.test", 31)
	if _, err := (JKS{}).Render(m, OutputOpts{Password: "abcde", BaseName: "bundle"}); !errors.Is(err, ErrPassword) {
		t.Fatalf("5-char password: %v", err)
	}
}

// TestJKSPasswordMustBeASCII: keystore-go's password hashing maps each
// UTF-8 byte to one (0, byte) pair rather than one pair per UTF-16 code
// unit, so a non-ASCII password produces a JKS Java/keytool cannot open
// with the same password. Reject it instead of silently producing an
// incompatible file.
func TestJKSPasswordMustBeASCII(t *testing.T) {
	m := realMaterial(t, "jks.example.test", 34)
	if _, err := (JKS{}).Render(m, OutputOpts{Password: "hüntér2", BaseName: "bundle"}); !errors.Is(err, ErrPassword) {
		t.Fatalf("non-ASCII password: %v", err)
	}
}

func TestJKSSixCharASCIIPasswordOK(t *testing.T) {
	m := realMaterial(t, "jks.example.test", 35)
	if _, err := (JKS{}).Render(m, OutputOpts{Password: "abcdef", BaseName: "bundle"}); err != nil {
		t.Fatalf("6-char ASCII password: %v", err)
	}
}

// TestJKSExtraChainEntries: PEM's extra part and the PKCS12 renderer both
// carry an extra certificate's chain, not just its leaf; JKS must match,
// as extra-<n>-<m> trusted entries.
func TestJKSExtraChainEntries(t *testing.T) {
	m := realMaterial(t, "jks.example.test", 36)
	extra := realMaterial(t, "extra.example.test", 37)

	files, err := (JKS{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle", Extras: []Material{extra}})
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(files[0].Data), []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	if !ks.IsTrustedCertificateEntry("extra-1-1") {
		t.Fatal("extra-1-1 not trusted")
	}
	tce, err := ks.GetTrustedCertificateEntry("extra-1-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tce.Certificate.Content, extra.ChainDER[0]) {
		t.Fatal("extra-1-1 content mismatch")
	}
}

func TestJKSNoKey(t *testing.T) {
	m := realMaterial(t, "jks.example.test", 32)
	m.PrivateKeyPKCS8 = nil
	if _, err := (JKS{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle"}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
}

func TestJKSCreationTimeIsNotBefore(t *testing.T) {
	m := realMaterial(t, "jks.example.test", 33)
	files, err := (JKS{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle"})
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(files[0].Data), []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	pke, err := ks.GetPrivateKeyEntry("bundle", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(m.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if !pke.CreationTime.Equal(leaf.NotBefore) {
		t.Fatalf("creationTime = %v, want %v", pke.CreationTime, leaf.NotBefore)
	}
}

func TestKeystoresDeterministicWithDetRand(t *testing.T) {
	m := realMaterial(t, "det.example.test", 50)

	p12A, err := (PKCS12{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle", Rand: DetRand([]byte("seed-a"))})
	if err != nil {
		t.Fatal(err)
	}
	p12B, err := (PKCS12{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle", Rand: DetRand([]byte("seed-a"))})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p12A[0].Data, p12B[0].Data) {
		t.Fatal("p12: same seed produced different bytes")
	}
	p12C, err := (PKCS12{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle", Rand: DetRand([]byte("seed-b"))})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(p12A[0].Data, p12C[0].Data) {
		t.Fatal("p12: different seeds produced identical bytes")
	}

	jksA, err := (JKS{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle", Rand: DetRand([]byte("seed-a"))})
	if err != nil {
		t.Fatal(err)
	}
	jksB, err := (JKS{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle", Rand: DetRand([]byte("seed-a"))})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jksA[0].Data, jksB[0].Data) {
		t.Fatal("jks: same seed produced different bytes")
	}
	jksC, err := (JKS{}).Render(m, OutputOpts{Password: "hunter2", BaseName: "bundle", Rand: DetRand([]byte("seed-b"))})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(jksA[0].Data, jksC[0].Data) {
		t.Fatal("jks: different seeds produced identical bytes")
	}
}
