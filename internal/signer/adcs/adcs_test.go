package adcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/signer"
)

func mkCert(t *testing.T, cn string, serial int64, pub any, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, dns []string, ips ...net.IP) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if pub == nil {
		pub = &key.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: ca, BasicConstraintsValid: true, DNSNames: dns, IPAddresses: ips,
	}
	signTmpl, signKey := parent, parentKey
	if parent == nil {
		signTmpl, signKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signTmpl, pub, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// buildPKCS7 encodes a certs-only SignedData.
func buildPKCS7(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var set []byte
	for _, c := range certs {
		set = append(set, c.Raw...)
	}
	mustMarshal := func(v any, params string) []byte {
		b, err := asn1.MarshalWithParams(v, params)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	version := mustMarshal(1, "")
	digests := mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 17, IsCompound: true}, "")
	encap := mustMarshal(struct{ T asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}}, "")
	certsRV := mustMarshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: set}, "")
	signers := mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 17, IsCompound: true}, "")
	sd := mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 16, IsCompound: true,
		Bytes: concat(version, digests, encap, certsRV, signers)}, "")
	ci := mustMarshal(struct {
		T asn1.ObjectIdentifier
		C asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}}, "")
	return ci
}

func concat(bs ...[]byte) []byte {
	var out []byte
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}

func TestParseCertsOnlyPKCS7(t *testing.T) {
	root, rk := mkCert(t, "root", 1, nil, nil, nil, true, nil)
	leaf, _ := mkCert(t, "leaf", 2, nil, root, rk, false, nil)
	got, err := parseCertsOnlyPKCS7(buildPKCS7(t, leaf, root))
	if err != nil || len(got) != 2 || got[0].Subject.CommonName != "leaf" || got[1].Subject.CommonName != "root" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := parseCertsOnlyPKCS7([]byte("junk")); err == nil {
		t.Fatal("want error for junk")
	}
}

// fakeAD is a TLS fake CEP + CES.
type fakeAD struct {
	t        *testing.T
	root     *x509.Certificate
	issuing  *x509.Certificate
	issKey   *ecdsa.PrivateKey
	mode     string
	cepBody  string
	cesBody  string
	template string
	srv      *httptest.Server
}

var csrRe = regexp.MustCompile(`<o:BinarySecurityToken[^>]*>([^<]*)</o:BinarySecurityToken>`)

func newFake(t *testing.T, mode string) *fakeAD {
	f := &fakeAD{t: t, mode: mode, template: "CertForgeWeb"}
	var rk *ecdsa.PrivateKey
	f.root, rk = mkCert(t, "root", 1, nil, nil, nil, true, nil)
	f.issuing, f.issKey = mkCert(t, "issuing", 2, nil, f.root, rk, true, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/cep", f.cep)
	mux.HandleFunc("/ces", f.ces)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAD) client() *httpx.Client {
	pemCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}))
	hc, err := httpx.New(httpx.Options{CAPEM: pemCA, AllowLoopback: true, MaxBody: MaxBody})
	if err != nil {
		f.t.Fatal(err)
	}
	return hc
}

func (f *fakeAD) signer() *Signer {
	return New(Config{
		CEPURL: f.srv.URL + "/cep", CESURL: f.srv.URL + "/ces", Template: f.template, Username: "svc",
		CABundlePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuing.Raw})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw})),
		Timeout: 10 * time.Second,
	}, "s3cret", f.client())
}

const soapHead = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>`
const soapTail = `</s:Body></s:Envelope>`

func (f *fakeAD) cep(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.cepBody = string(b)
	if f.mode == "401" {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	issuer := base64.StdEncoding.EncodeToString(f.issuing.Raw)
	fmt.Fprintf(w, soapHead+`<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
<response><policyID/><policies><policy><policyOIDReference>0</policyOIDReference><cAs><cAReference>0</cAReference></cAs>
<attributes><commonName>%s</commonName><enrollmentFlags>2</enrollmentFlags><policySchema>2</policySchema><permission><enroll>true</enroll><autoEnroll>false</autoEnroll></permission>
<privateKeyAttributes><minimalKeyLength>2048</minimalKeyLength></privateKeyAttributes></attributes></policy></policies></response>
<oIDs><oID><value>1.3.6.1.4.1.311.21.8.1.2</value><group>9</group><oIDReferenceID>0</oIDReferenceID><defaultName>x</defaultName></oID></oIDs>
<cAs><cA><uris><cAURI><clientAuthentication>4</clientAuthentication><uri>%s</uri><priority>1</priority><renewalOnly>false</renewalOnly></cAURI>
<cAURI><clientAuthentication>2</clientAuthentication><uri>https://kerberos.invalid/ces</uri><priority>0</priority></cAURI></uris>
<certificate>%s</certificate><enrollPermission>true</enrollPermission><cAReferenceID>0</cAReferenceID></cA></cAs></GetPoliciesResponse>`+soapTail,
		f.template, f.srv.URL+"/ces", issuer)
}

func (f *fakeAD) ces(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.cesBody = string(b)
	switch f.mode {
	case "401":
		http.Error(w, "no", http.StatusUnauthorized)
		return
	case "fault":
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, soapHead+`<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>a:InternalServiceFault</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="en">boom</s:Text></s:Reason></s:Fault>`+soapTail)
		return
	case "pending":
		fmt.Fprint(w, rstResp("Taken Under Submission", "77", ""))
		return
	case "denied":
		fmt.Fprint(w, rstResp("Denied by Policy Module", "78", ""))
		return
	}
	m := csrRe.FindStringSubmatch(f.cesBody)
	der, _ := base64.StdEncoding.DecodeString(m[1])
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		f.t.Error(err)
		return
	}
	pub := any(csr.PublicKey)
	if f.mode == "wrongkey" {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &k.PublicKey
	}
	dns := csr.DNSNames
	if f.mode == "badsan" {
		dns = []string{"other.example.test"}
	}
	leaf, _ := mkCert(f.t, csr.Subject.CommonName, 99, pub, f.issuing, f.issKey, false, dns, csr.IPAddresses...)
	var p7 []byte
	if f.mode == "leafonly" {
		p7 = buildPKCS7(f.t, leaf)
	} else {
		p7 = buildPKCS7(f.t, f.root, leaf, f.issuing)
	}
	fmt.Fprint(w, rstResp("Issued", "55", base64.StdEncoding.EncodeToString(p7)))
}

func rstResp(disp, id, p7 string) string {
	tok := ""
	if p7 != "" {
		tok = `<RequestedSecurityToken><BinarySecurityToken ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#PKCS7" EncodingType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.0#Base64Binary" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">` + p7 + `</BinarySecurityToken></RequestedSecurityToken>`
	}
	return soapHead + `<RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><RequestSecurityTokenResponse><TokenType>x</TokenType><DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">` + disp + `</DispositionMessage>` + tok + `<RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">` + id + `</RequestID></RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection>` + soapTail
}

var maskRes = []*regexp.Regexp{
	regexp.MustCompile(`(<a:MessageID>)[^<]*`),
	regexp.MustCompile(`(<a:To [^>]*>https://127.0.0.1:)\d+`),
	regexp.MustCompile(`(<o:Nonce [^>]*>)[^<]*`),
	regexp.MustCompile(`(<u:Created>)[^<]*`),
	regexp.MustCompile(`(<u:Expires>)[^<]*`),
	regexp.MustCompile(`(<o:BinarySecurityToken [^>]*>)[^<]*`),
	regexp.MustCompile(`(UsernameToken u:Id=")[^"]*`),
}

func normalize(s string) string {
	s = regexp.MustCompile(`>\s+<`).ReplaceAllString(strings.TrimSpace(s), "><")
	for _, re := range maskRes {
		s = re.ReplaceAllString(s, "${1}MASKED")
	}
	return s
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	if os.Getenv("ADCS_UPDATE") != "" { // regenerate goldens: ADCS_UPDATE=1 go test
		if err := os.WriteFile("testdata/"+name, []byte(normalize(got)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if normalize(got) != normalize(string(want)) {
		t.Fatalf("%s mismatch:\n got: %s\nwant: %s", name, normalize(got), normalize(string(want)))
	}
}

func TestPolicies(t *testing.T) {
	f := newFake(t, "issued")
	res, err := f.signer().Policies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "getpolicies_request.xml", f.cepBody)
	tpl, err := res.Template("certforgeweb")
	if err != nil {
		t.Fatal(err)
	}
	if !tpl.RequiresApproval() {
		t.Fatalf("flags = %d", tpl.EnrollmentFlags)
	}
	if tpl.OID != "1.3.6.1.4.1.311.21.8.1.2" || tpl.MinKeySize != 2048 || !tpl.CanEnroll || len(tpl.CAs) != 1 {
		t.Fatalf("template = %+v", tpl)
	}
	ca := tpl.CAs[0]
	if len(ca.CESURLs) != 1 || ca.CESURLs[0] != f.srv.URL+"/ces" || len(ca.Certs) != 1 || ca.Certs[0].Subject.CommonName != "issuing" {
		t.Fatalf("ca = %+v", ca)
	}
}

func TestPoliciesUnknownTemplate(t *testing.T) {
	f := newFake(t, "issued")
	res, err := f.signer().Policies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := res.Template("Nope"); !errors.Is(err, ErrTemplateUnknown) {
		t.Fatalf("err = %v", err)
	}
}

func TestIssue(t *testing.T) {
	names := []string{"leaf.example.test", "10.0.0.5"}
	cases := []struct {
		mode     string
		wantErr  func(error) bool
		chainLen int
	}{
		{"issued", nil, 2},
		{"leafonly", nil, 2},
		{"pending", func(e error) bool { var p ErrPending; return errors.As(e, &p) && p.RequestID == "77" }, 0},
		{"denied", func(e error) bool {
			var d ErrDenied
			return errors.As(e, &d) && strings.Contains(d.Disposition, "Denied")
		}, 0},
		{"401", func(e error) bool { return errors.Is(e, ErrAuth) }, 0},
		{"fault", func(e error) bool { var f *Fault; return errors.As(e, &f) && f.Subcode == "a:InternalServiceFault" }, 0},
		{"wrongkey", func(e error) bool { return e != nil && strings.Contains(e.Error(), "public key") }, 0},
		{"badsan", func(e error) bool { return e != nil && strings.Contains(e.Error(), "does not cover") }, 0},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			f := newFake(t, tc.mode)
			got, err := f.signer().Issue(context.Background(), signer.IssueRequest{Names: names, KeyType: signer.EC256})
			if tc.wantErr != nil {
				if !tc.wantErr(err) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			golden(t, "rst_request.xml", f.cesBody)
			leaf, _ := x509.ParseCertificate(got.LeafDER)
			if leaf.Subject.CommonName != names[0] || got.Serial != "63" || len(got.PrivateKeyPKCS8) == 0 {
				t.Fatalf("issued = %+v", got)
			}
			if len(got.ChainDER) != tc.chainLen {
				t.Fatalf("chain len = %d", len(got.ChainDER))
			}
			c0, _ := x509.ParseCertificate(got.ChainDER[0])
			c1, _ := x509.ParseCertificate(got.ChainDER[1])
			if c0.Subject.CommonName != "issuing" || c1.Subject.CommonName != "root" {
				t.Fatalf("chain order: %s, %s", c0.Subject.CommonName, c1.Subject.CommonName)
			}
			// CSR carried the template extension and password reached the wire.
			m := csrRe.FindStringSubmatch(f.cesBody)
			der, _ := base64.StdEncoding.DecodeString(m[1])
			csr, _ := x509.ParseCertificateRequest(der)
			ext, _ := templateNameExtension(f.template)
			found := false
			for _, e := range csr.Extensions {
				found = found || (e.Id.Equal(ext.Id) && string(e.Value) == string(ext.Value))
			}
			if !found {
				t.Fatal("template extension missing from CSR")
			}
		})
	}
}

func TestRevokeRenewalUnsupported(t *testing.T) {
	s := New(Config{}, "", nil)
	if err := s.Revoke(context.Background(), nil, 0); !errors.Is(err, signer.ErrNotSupported) {
		t.Fatal(err)
	}
	if _, err := s.RenewalInfo(context.Background(), nil); !errors.Is(err, signer.ErrNotSupported) {
		t.Fatal(err)
	}
}
