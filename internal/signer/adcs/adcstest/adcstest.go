// Package adcstest is an in-process fake AD CS (enrollment policy and
// enrollment web services over TLS) for other packages' tests.
package adcstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Template is the template name the fake publishes.
const Template = "CertForgeWeb"

// Username and Password are the only credentials the fake accepts.
const (
	Username = "svc"
	Password = "s3cret"
)

// Fake is a running fake AD CS.
type Fake struct {
	// CEPURL and CESURL are the fake's service URLs.
	CEPURL, CESURL string
	// TLSCAPEM is the PEM of the fake's TLS certificate, to trust.
	TLSCAPEM string
	// CAPEM is the PEM of the fake's issuing CA certificate.
	CAPEM string
	// Issued counts successful enrolments.
	Issued atomic.Int32

	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

var (
	bstRe  = regexp.MustCompile(`<o:BinarySecurityToken[^>]*>([^<]*)</o:BinarySecurityToken>`)
	passRe = regexp.MustCompile(`<o:Password [^>]*>([^<]*)</o:Password>`)
)

// New starts a fake AD CS, closed with t.
func New(t *testing.T) *Fake {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake AD CS CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	f := &Fake{ca: ca, caKey: key, CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	mux := http.NewServeMux()
	mux.HandleFunc("/cep", f.cep)
	mux.HandleFunc("/ces", f.ces)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	f.CEPURL, f.CESURL = srv.URL+"/cep", srv.URL+"/ces"
	f.TLSCAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return f
}

func authed(w http.ResponseWriter, body string) bool {
	m := passRe.FindStringSubmatch(body)
	if m == nil || m[1] != Password || !strings.Contains(body, "<o:Username>"+Username+"</o:Username>") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (f *Fake) cep(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	if !authed(w, string(b)) {
		return
	}
	fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><response><policies><policy><policyOIDReference>0</policyOIDReference><cAs><cAReference>0</cAReference></cAs><attributes><commonName>%s</commonName><permission><enroll>true</enroll></permission><privateKeyAttributes><minimalKeyLength>2048</minimalKeyLength></privateKeyAttributes></attributes></policy></policies></response><oIDs><oID><value>1.3.6.1.4.1.311.21.8.1.2</value><oIDReferenceID>0</oIDReferenceID></oID></oIDs><cAs><cA><uris><cAURI><clientAuthentication>4</clientAuthentication><uri>%s</uri><priority>1</priority></cAURI></uris><certificate>%s</certificate><cAReferenceID>0</cAReferenceID></cA></cAs></GetPoliciesResponse></s:Body></s:Envelope>`,
		Template, f.CESURL, base64.StdEncoding.EncodeToString(f.ca.Raw))
}

func (f *Fake) ces(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	body := string(b)
	if !authed(w, body) {
		return
	}
	m := bstRe.FindStringSubmatch(body)
	der, _ := base64.StdEncoding.DecodeString(m[1])
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	leaf, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: csr.Subject.CommonName},
		DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}, f.ca, csr.PublicKey, f.caKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.Issued.Add(1)
	p7 := pkcs7(leaf, f.ca.Raw)
	fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><RequestSecurityTokenResponse><DispositionMessage>Issued</DispositionMessage><RequestedSecurityToken><BinarySecurityToken xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">%s</BinarySecurityToken></RequestedSecurityToken><RequestID>1</RequestID></RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection></s:Body></s:Envelope>`,
		base64.StdEncoding.EncodeToString(p7))
}

// pkcs7 encodes a certs-only SignedData holding certs.
func pkcs7(certs ...[]byte) []byte {
	m := func(v any) []byte { b, _ := asn1.Marshal(v); return b }
	var set []byte
	for _, c := range certs {
		set = append(set, c...)
	}
	cat := func(bs ...[]byte) []byte {
		var o []byte
		for _, b := range bs {
			o = append(o, b...)
		}
		return o
	}
	empty := m(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 17, IsCompound: true})
	sd := m(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 16, IsCompound: true, Bytes: cat(
		m(1), empty, m(struct{ T asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}}),
		m(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: set}), empty)})
	return m(struct {
		T asn1.ObjectIdentifier
		C asn1.RawValue
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
}
