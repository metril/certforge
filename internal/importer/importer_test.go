package importer

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"testing/fstest"
)

func findByName(items []ImportedCert, name string) (ImportedCert, bool) {
	for _, ic := range items {
		if ic.Name == name {
			return ic, true
		}
	}
	return ImportedCert{}, false
}

// TestAcmeShImport covers Task 14's brief: an RSA fullchain.cer item and an
// _ecc one both parse with their key, a fullchain.cer item with no .key
// file parses with hasKey false, and the <domain>.cer + ca.cer fallback
// works too.
func TestAcmeShImport(t *testing.T) {
	fsys := os.DirFS("testdata/acmesh")
	if !AcmeSh.Detect(fsys) {
		t.Fatal("Detect = false on testdata/acmesh")
	}
	items, err := AcmeSh.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	rsa, ok := findByName(items, "rsa.acmesh.example.test")
	if !ok {
		t.Fatal("rsa.acmesh.example.test not found")
	}
	if rsa.Source != SourceAcmeSh {
		t.Fatalf("source = %s", rsa.Source)
	}
	if len(rsa.KeyPKCS8) == 0 {
		t.Fatal("rsa item: hasKey should be true")
	}
	leaf, err := x509.ParseCertificate(rsa.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "rsa.acmesh.example.test" {
		t.Fatalf("leaf CN = %q", leaf.Subject.CommonName)
	}

	ecc, ok := findByName(items, "ecc.acmesh.example.test")
	if !ok {
		t.Fatal("ecc.acmesh.example.test (from the _ecc directory) not found")
	}
	if len(ecc.KeyPKCS8) == 0 {
		t.Fatal("ecc item: hasKey should be true")
	}

	nokey, ok := findByName(items, "nokey.acmesh.example.test")
	if !ok {
		t.Fatal("nokey.acmesh.example.test not found")
	}
	if len(nokey.KeyPKCS8) != 0 {
		t.Fatal("nokey item: hasKey should be false")
	}

	split, ok := findByName(items, "split.acmesh.example.test")
	if !ok {
		t.Fatal("split.acmesh.example.test (<domain>.cer + ca.cer style) not found")
	}
	if len(split.KeyPKCS8) == 0 {
		t.Fatal("split item: hasKey should be true")
	}
	if len(split.ChainDER) == 0 {
		t.Fatal("split item: expected a chain from ca.cer")
	}
}

// TestAcmeShDetectNested covers detecting a .acme.sh top-level directory
// (an archive of a whole home directory), not just a bare root.
func TestAcmeShDetectNested(t *testing.T) {
	fsys := fstest.MapFS{
		".acme.sh/example.test/fullchain.cer": &fstest.MapFile{Data: []byte("x")},
	}
	if !AcmeSh.Detect(fsys) {
		t.Fatal("Detect = false on a nested .acme.sh/ tree")
	}
	if AcmeSh.Detect(fstest.MapFS{"README.txt": &fstest.MapFile{Data: []byte("x")}}) {
		t.Fatal("Detect = true on an unrelated tree")
	}
}

// TestCertbotImport covers the brief: archive/<name> at the highest N wins
// over an older generation, and a name that exists only under live/ is
// still found.
func TestCertbotImport(t *testing.T) {
	fsys := os.DirFS("testdata/certbot")
	if !Certbot.Detect(fsys) {
		t.Fatal("Detect = false on testdata/certbot")
	}
	items, err := Certbot.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}

	latest, ok := findByName(items, "example.certbot.example.test")
	if !ok {
		t.Fatal("example.certbot.example.test not found")
	}
	leaf, err := x509.ParseCertificate(latest.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Int64() != 202 {
		t.Fatalf("serial = %d, want 202 (the highest generation, N=2)", leaf.SerialNumber.Int64())
	}
	if len(latest.KeyPKCS8) == 0 {
		t.Fatal("expected a key from privkey2.pem")
	}

	live, ok := findByName(items, "onlylive.certbot.example.test")
	if !ok {
		t.Fatal("onlylive.certbot.example.test (live/ fallback) not found")
	}
	liveLeaf, err := x509.ParseCertificate(live.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if liveLeaf.SerialNumber.Int64() != 301 {
		t.Fatalf("serial = %d, want 301", liveLeaf.SerialNumber.Int64())
	}
}

// TestCertbotDetectNested mirrors TestAcmeShDetectNested for certbot's own
// top-level directory name.
func TestCertbotDetectNested(t *testing.T) {
	fsys := fstest.MapFS{
		"letsencrypt/live/example.test/cert.pem": &fstest.MapFile{Data: []byte("x")},
	}
	if !Certbot.Detect(fsys) {
		t.Fatal("Detect = false on a nested letsencrypt/ tree")
	}
}

// TestAcmeShCorruptLeafNotDropped covers a fix-round finding: a directory
// whose fullchain.cer exists but holds no decodable CERTIFICATE block must
// still surface as an ImportedCert (LeafDER carrying the raw, undecodable
// bytes, so issuance.ImportCertificates' own x509.ParseCertificate reports
// why and the entry becomes a "skip" with a reason) rather than silently
// vanishing from Import's results.
func TestAcmeShCorruptLeafNotDropped(t *testing.T) {
	fsys := fstest.MapFS{
		"bad.example.test/fullchain.cer": &fstest.MapFile{Data: []byte("not a certificate")},
	}
	items, err := AcmeSh.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	ic, ok := findByName(items, "bad.example.test")
	if !ok {
		t.Fatal("bad.example.test vanished instead of surfacing as an item")
	}
	if len(ic.LeafDER) == 0 {
		t.Fatal("LeafDER is empty; want the raw undecodable file content")
	}
	if _, err := x509.ParseCertificate(ic.LeafDER); err == nil {
		t.Fatal("LeafDER unexpectedly parses as a certificate")
	}
}

// TestAcmeShCorruptKeyNotSilentlyDropped covers the same principle for a
// key file that exists but cannot be decoded: KeyPKCS8 must carry the raw
// bytes (hasKey true, later reported "cannot parse key"), not silently
// report this certificate as keyless.
func TestAcmeShCorruptKeyNotSilentlyDropped(t *testing.T) {
	leafPEM := genSelfSigned(t, "badkey.example.test", 501, false).leafPEM
	fsys := fstest.MapFS{
		"badkey.example.test/fullchain.cer":           &fstest.MapFile{Data: leafPEM},
		"badkey.example.test/badkey.example.test.key": &fstest.MapFile{Data: []byte("not a key")},
	}
	items, err := AcmeSh.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	ic, ok := findByName(items, "badkey.example.test")
	if !ok {
		t.Fatal("badkey.example.test not found")
	}
	if len(ic.KeyPKCS8) == 0 {
		t.Fatal("KeyPKCS8 is empty; want the raw undecodable key bytes (hasKey should read true, not silently false)")
	}
	if _, err := x509.ParsePKCS8PrivateKey(ic.KeyPKCS8); err == nil {
		t.Fatal("KeyPKCS8 unexpectedly parses as a valid PKCS#8 key")
	}
}

// TestCertbotCorruptLeafNotDropped mirrors TestAcmeShCorruptLeafNotDropped
// for certbot's archive/<name> layout.
func TestCertbotCorruptLeafNotDropped(t *testing.T) {
	fsys := fstest.MapFS{
		"archive/bad.certbot.example.test/fullchain1.pem": &fstest.MapFile{Data: []byte("not a certificate")},
	}
	items, err := Certbot.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	ic, ok := findByName(items, "bad.certbot.example.test")
	if !ok {
		t.Fatal("bad.certbot.example.test vanished instead of surfacing as an item")
	}
	if len(ic.LeafDER) == 0 {
		t.Fatal("LeafDER is empty; want the raw undecodable file content")
	}
	if _, err := x509.ParseCertificate(ic.LeafDER); err == nil {
		t.Fatal("LeafDER unexpectedly parses as a certificate")
	}
}

// TestCertbotCorruptKeyNotSilentlyDropped mirrors
// TestAcmeShCorruptKeyNotSilentlyDropped for certbot.
func TestCertbotCorruptKeyNotSilentlyDropped(t *testing.T) {
	leafPEM := genSelfSigned(t, "badkey.certbot.example.test", 502, false).leafPEM
	fsys := fstest.MapFS{
		"archive/badkey.certbot.example.test/fullchain1.pem": &fstest.MapFile{Data: leafPEM},
		"archive/badkey.certbot.example.test/privkey1.pem":   &fstest.MapFile{Data: []byte("not a key")},
	}
	items, err := Certbot.Import(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	ic, ok := findByName(items, "badkey.certbot.example.test")
	if !ok {
		t.Fatal("badkey.certbot.example.test not found")
	}
	if len(ic.KeyPKCS8) == 0 {
		t.Fatal("KeyPKCS8 is empty; want the raw undecodable key bytes (hasKey should read true, not silently false)")
	}
	if _, err := x509.ParsePKCS8PrivateKey(ic.KeyPKCS8); err == nil {
		t.Fatal("KeyPKCS8 unexpectedly parses as a valid PKCS#8 key")
	}
}
