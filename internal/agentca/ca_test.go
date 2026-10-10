package agentca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var now0 = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func testCA(t *testing.T) *CA {
	t.Helper()
	cert, key, err := NewCA(now0)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{ID: uuid.New(), Status: "active", Cert: cert, Key: key}
}

func csrFor(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestNewCAIsSelfSignedP256(t *testing.T) {
	ca := testCA(t)
	if !ca.Cert.IsCA || ca.Cert.CheckSignatureFrom(ca.Cert) != nil {
		t.Fatal("not a self-signed CA")
	}
	if ca.Key.Curve != elliptic.P256() || ca.Cert.NotAfter.Sub(now0) < 3649*24*time.Hour {
		t.Fatalf("curve %v notAfter %v", ca.Key.Curve.Params().Name, ca.Cert.NotAfter)
	}
	if len(Fingerprint(ca.Cert.Raw)) != 64 {
		t.Fatal("fingerprint")
	}
}

func TestSignClientHasURIAndClientAuth(t *testing.T) {
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := ParseCSR(csrFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	cert, err := SignClient(ca, csr, id, 90*24*time.Hour, now0)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now0.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if got, err := ClientIDFromCert(cert); err != nil || got != id {
		t.Fatalf("client id %v %v", got, err)
	}
	if len(cert.DNSNames) != 0 || cert.URIs[0].String() != "urn:certforge:client:"+id.String() {
		t.Fatalf("SANs %v %v", cert.DNSNames, cert.URIs)
	}
	if SerialHex(cert) == "" || cert.NotAfter.Sub(now0) != 90*24*time.Hour {
		t.Fatalf("serial %s notAfter %v", SerialHex(cert), cert.NotAfter)
	}
}

func TestSignServerNamesAndIPs(t *testing.T) {
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := SignServer(ca, &key.PublicKey, []string{"agents.example.test", "10.0.0.5"}, now0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("SANs %v %v", cert.DNSNames, cert.IPAddresses)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "agents.example.test", Roots: roots, CurrentTime: now0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := SignServer(ca, &key.PublicKey, nil, now0); err == nil {
		t.Fatal("no names accepted")
	}
}

func TestParseCSRRejects(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	good, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tampered := csrFor(t, good)
	blk, _ := pem.Decode(tampered)
	blk.Bytes[len(blk.Bytes)-3] ^= 0xff
	for name, in := range map[string][]byte{
		"garbage":  []byte("nope"),
		"rsa1024":  csrFor(t, small),
		"tampered": pem.EncodeToMemory(blk),
		"cert pem": CertPEM(testCA(t).Cert.Raw),
	} {
		if _, err := ParseCSR(in); !errors.Is(err, ErrBadCSR) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestClientIDFromCertRejectsForeign(t *testing.T) {
	ca := testCA(t)
	if _, err := ClientIDFromCert(ca.Cert); !errors.Is(err, ErrNotClient) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientIDFromCertRejectsNonCanonicalUUID(t *testing.T) {
	id := uuid.New()
	u, err := url.Parse(clientURIPrefix + strings.ToUpper(id.String()))
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{URIs: []*url.URL{u}}
	if _, err := ClientIDFromCert(cert); !errors.Is(err, ErrNotClient) {
		t.Fatalf("err = %v", err)
	}
}

func TestSignResponderHasOnlyResponderEKU(t *testing.T) {
	ca := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, err := SignResponder(ca, &key.PublicKey, now0)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageOCSPSigning || len(c.UnknownExtKeyUsage) != 0 ||
		len(c.Subject.OrganizationalUnit) != 1 || c.Subject.OrganizationalUnit[0] != ResponderMarker {
		t.Fatalf("eku %v %v ou %v", c.ExtKeyUsage, c.UnknownExtKeyUsage, c.Subject.OrganizationalUnit)
	}
	if d := c.NotAfter.Sub(now0); d != ResponderLifetime {
		t.Fatalf("lifetime %v", d)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := VerifyResponder(c, roots, now0); err != nil {
		t.Fatal(err)
	}
	for _, u := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now0, KeyUsages: []x509.ExtKeyUsage{u}}); err == nil {
			t.Errorf("responder certificate valid for TLS usage %v", u)
		}
	}
	if _, err := VerifyResponder(c, roots, now0.Add(25*time.Hour)); err == nil {
		t.Error("expired responder accepted")
	}
	if _, err := VerifyResponder(c, x509.NewCertPool(), now0); err == nil {
		t.Error("untrusted responder accepted")
	}
	other := testCA(t)
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(other.Cert)
	if _, err := VerifyResponder(c, otherRoots, now0); err == nil {
		t.Error("responder from another CA accepted")
	}
	// A TLS server or client certificate must not pass as a responder.
	srv, err := SignServer(ca, &key.PublicKey, []string{"a.test"}, now0)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := ParseCSR(csrFor(t, key))
	cli, err := SignClient(ca, csr, uuid.New(), time.Hour, now0)
	if err != nil {
		t.Fatal(err)
	}
	for name, cert := range map[string]*x509.Certificate{"server": srv, "client": cli} {
		if _, err := VerifyResponder(cert, roots, now0); err == nil {
			t.Errorf("%s certificate accepted as responder", name)
		}
	}
}
