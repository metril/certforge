package importer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// update regenerates testdata/ when set: `go test ./internal/importer -run
// TestFixtures -update`. Fixture certificates are self-signed with a
// 100-year validity so this suite never needs regenerating just because
// time passed.
var update = flag.Bool("update", false, "regenerate testdata/ fixtures")

type genCert struct {
	leafPEM, chainPEM, keyPEM []byte
	notAfter                  time.Time
}

// genSelfSigned builds a self-signed leaf (its own chain entry too, so
// tests that only care about parsing/splitting logic have something
// non-empty to find in a "chain" position) plus its PKCS#8 key, all PEM
// encoded. serial varies notAfter slightly so fixtures with different
// serials are distinguishable by validity as well as by content.
func genSelfSigned(t *testing.T, cn string, serial int64, ecc bool) genCert {
	t.Helper()
	var signer crypto.Signer
	var err error
	if ecc {
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(100, 0, 0).Add(time.Duration(serial) * time.Second)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{cn}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return genCert{leafPEM: leafPEM, chainPEM: leafPEM, keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), notAfter: notAfter}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFixtures generates testdata/acmesh and testdata/certbot when run with
// -update; it is a no-op read-only sanity check otherwise (so `go test
// ./...` never overwrites checked-in fixtures).
func TestFixtures(t *testing.T) {
	if !*update {
		if _, err := os.Stat("testdata/acmesh"); err != nil {
			t.Skip("testdata/ fixtures missing; run with -update to generate them")
		}
		return
	}
	root := "testdata"
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}

	// acme.sh: fullchain.cer style (RSA), fullchain.cer style (_ecc), a
	// fullchain.cer entry with no key, and a <domain>.cer + ca.cer style.
	rsa1 := genSelfSigned(t, "rsa.acmesh.example.test", 101, false)
	writeFile(t, filepath.Join(root, "acmesh/rsa.acmesh.example.test/fullchain.cer"), rsa1.leafPEM)
	writeFile(t, filepath.Join(root, "acmesh/rsa.acmesh.example.test/rsa.acmesh.example.test.key"), rsa1.keyPEM)

	ecc1 := genSelfSigned(t, "ecc.acmesh.example.test", 102, true)
	writeFile(t, filepath.Join(root, "acmesh/ecc.acmesh.example.test_ecc/fullchain.cer"), ecc1.leafPEM)
	writeFile(t, filepath.Join(root, "acmesh/ecc.acmesh.example.test_ecc/ecc.acmesh.example.test.key"), ecc1.keyPEM)

	nokey := genSelfSigned(t, "nokey.acmesh.example.test", 103, false)
	writeFile(t, filepath.Join(root, "acmesh/nokey.acmesh.example.test/fullchain.cer"), nokey.leafPEM)

	split := genSelfSigned(t, "split.acmesh.example.test", 104, false)
	writeFile(t, filepath.Join(root, "acmesh/split.acmesh.example.test/split.acmesh.example.test.cer"), split.leafPEM)
	writeFile(t, filepath.Join(root, "acmesh/split.acmesh.example.test/ca.cer"), split.chainPEM)
	writeFile(t, filepath.Join(root, "acmesh/split.acmesh.example.test/split.acmesh.example.test.key"), split.keyPEM)

	// certbot: two generations under archive/ (N=2 must win), plus a name
	// that exists only under live/.
	gen1 := genSelfSigned(t, "example.certbot.example.test", 201, false)
	writeFile(t, filepath.Join(root, "certbot/archive/example.certbot.example.test/cert1.pem"), gen1.leafPEM)
	writeFile(t, filepath.Join(root, "certbot/archive/example.certbot.example.test/chain1.pem"), gen1.chainPEM)
	writeFile(t, filepath.Join(root, "certbot/archive/example.certbot.example.test/fullchain1.pem"), append(append([]byte{}, gen1.leafPEM...), gen1.chainPEM...))
	writeFile(t, filepath.Join(root, "certbot/archive/example.certbot.example.test/privkey1.pem"), gen1.keyPEM)

	gen2 := genSelfSigned(t, "example.certbot.example.test", 202, false)
	writeFile(t, filepath.Join(root, "certbot/archive/example.certbot.example.test/cert2.pem"), gen2.leafPEM)
	writeFile(t, filepath.Join(root, "certbot/archive/example.certbot.example.test/chain2.pem"), gen2.chainPEM)
	writeFile(t, filepath.Join(root, "certbot/archive/example.certbot.example.test/fullchain2.pem"), append(append([]byte{}, gen2.leafPEM...), gen2.chainPEM...))
	writeFile(t, filepath.Join(root, "certbot/archive/example.certbot.example.test/privkey2.pem"), gen2.keyPEM)

	live := genSelfSigned(t, "onlylive.certbot.example.test", 301, false)
	writeFile(t, filepath.Join(root, "certbot/live/onlylive.certbot.example.test/cert.pem"), live.leafPEM)
	writeFile(t, filepath.Join(root, "certbot/live/onlylive.certbot.example.test/chain.pem"), live.chainPEM)
	writeFile(t, filepath.Join(root, "certbot/live/onlylive.certbot.example.test/fullchain.pem"), append(append([]byte{}, live.leafPEM...), live.chainPEM...))
	writeFile(t, filepath.Join(root, "certbot/live/onlylive.certbot.example.test/privkey.pem"), live.keyPEM)

	t.Logf("wrote fixtures under %s (gen2 notAfter %s, gen1 notAfter %s)", root, gen2.notAfter, gen1.notAfter)
}
