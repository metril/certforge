package adcs

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Namespaces, actions and token URIs of MS-XCEP / MS-WSTEP / WS-Trust /
// WS-Security. Everything wire-shaped that may need adjusting against a live
// CA lives in this file: these constants, the request builders and the
// response structs (which match by local element name only, so a namespace
// difference cannot break parsing).
const (
	nsSOAP = "http://www.w3.org/2003/05/soap-envelope"
	nsWSA  = "http://www.w3.org/2005/08/addressing"
	nsWSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	nsWSU  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	nsWST  = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	nsXCEP = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
	nsXSI  = "http://www.w3.org/2001/XMLSchema-instance"

	actionGetPolicies = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
	actionRST         = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"

	tokenTypePKCS10  = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#PKCS10"
	requestTypeIssue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
	encodingBase64   = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.0#Base64Binary"
	passwordText     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
	anonymousReplyTo = "http://www.w3.org/2005/08/addressing/anonymous"

	contentType = "application/soap+xml; charset=utf-8"

	// authUsername is XCEP's clientAuthentication value for
	// username/password (1 anonymous, 2 Kerberos, 4 username, 8 certificate).
	authUsername = 4
)

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func newUUID() string {
	h := randomHex(16)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// envelope wraps body (an element string) in a SOAP 1.2 envelope with
// WS-Addressing headers and a WS-Security Timestamp + UsernameToken.
func envelope(action, to, username, password, body string, now time.Time) []byte {
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
	var b strings.Builder
	fmt.Fprintf(&b, `<s:Envelope xmlns:s="%s" xmlns:a="%s" xmlns:u="%s" xmlns:o="%s" xmlns:wst="%s" xmlns:xsi="%s">`,
		nsSOAP, nsWSA, nsWSU, nsWSSE, nsWST, nsXSI)
	b.WriteString(`<s:Header>`)
	fmt.Fprintf(&b, `<a:Action s:mustUnderstand="1">%s</a:Action>`, esc(action))
	fmt.Fprintf(&b, `<a:MessageID>urn:uuid:%s</a:MessageID>`, newUUID())
	fmt.Fprintf(&b, `<a:To s:mustUnderstand="1">%s</a:To>`, esc(to))
	fmt.Fprintf(&b, `<a:ReplyTo><a:Address>%s</a:Address></a:ReplyTo>`, anonymousReplyTo)
	b.WriteString(`<o:Security s:mustUnderstand="1">`)
	fmt.Fprintf(&b, `<u:Timestamp u:Id="_0"><u:Created>%s</u:Created><u:Expires>%s</u:Expires></u:Timestamp>`,
		ts(now), ts(now.Add(5*time.Minute)))
	fmt.Fprintf(&b, `<o:UsernameToken u:Id="uuid-%s">`, newUUID())
	fmt.Fprintf(&b, `<o:Username>%s</o:Username>`, esc(username))
	fmt.Fprintf(&b, `<o:Password Type="%s">%s</o:Password>`, passwordText, esc(password))
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	fmt.Fprintf(&b, `<o:Nonce EncodingType="%s">%s</o:Nonce>`, encodingBase64, base64.StdEncoding.EncodeToString(nonce))
	fmt.Fprintf(&b, `<u:Created>%s</u:Created>`, ts(now))
	b.WriteString(`</o:UsernameToken></o:Security></s:Header>`)
	b.WriteString(`<s:Body>` + body + `</s:Body></s:Envelope>`)
	return []byte(b.String())
}

// getPoliciesRequest builds an XCEP GetPolicies request (no filter, no
// cached policy).
func getPoliciesRequest(cepURL, username, password string, now time.Time) []byte {
	body := fmt.Sprintf(`<GetPolicies xmlns="%s"><client><lastUpdate xsi:nil="true"/><preferredLanguage xsi:nil="true"/></client><requestFilter xsi:nil="true"/></GetPolicies>`, nsXCEP)
	return envelope(actionGetPolicies, cepURL, username, password, body, now)
}

// rstRequest builds a WSTEP RequestSecurityToken carrying csrDER as a
// PKCS#10 BinarySecurityToken.
func rstRequest(cesURL, username, password string, csrDER []byte, now time.Time) []byte {
	body := fmt.Sprintf(`<wst:RequestSecurityToken><wst:TokenType>%s</wst:TokenType><wst:RequestType>%s</wst:RequestType><o:BinarySecurityToken ValueType="%s" EncodingType="%s">%s</o:BinarySecurityToken></wst:RequestSecurityToken>`,
		tokenTypePKCS10, requestTypeIssue, tokenTypePKCS10, encodingBase64, base64.StdEncoding.EncodeToString(csrDER))
	return envelope(actionRST, cesURL, username, password, body, now)
}

// --- responses (matched by local name) ---

type respEnvelope struct {
	Body struct {
		Fault               *Fault               `xml:"Fault"`
		GetPoliciesResponse *getPoliciesResponse `xml:"GetPoliciesResponse"`
		RSTRC               *rstrc               `xml:"RequestSecurityTokenResponseCollection"`
		RSTR                *rstr                `xml:"RequestSecurityTokenResponse"`
	} `xml:"Body"`
}

// Fault is a SOAP 1.2 fault returned by CEP or CES.
type Fault struct {
	Code    string `xml:"Code>Value"`
	Subcode string `xml:"Code>Subcode>Value"`
	Reason  string `xml:"Reason>Text"`
	Detail  string `xml:"Detail"`
}

// Error implements error.
func (f *Fault) Error() string {
	msg := strings.TrimSpace(f.Reason)
	if d := strings.TrimSpace(f.Detail); d != "" {
		msg += " (" + d + ")"
	}
	if f.Subcode != "" {
		msg = f.Subcode + ": " + msg
	}
	return "adcs: soap fault: " + msg
}

func (f *Fault) isAuth() bool {
	s := strings.ToLower(f.Subcode + " " + f.Reason)
	return strings.Contains(s, "authentication") || strings.Contains(s, "invalidsecurity") ||
		strings.Contains(s, "failedcheck") || strings.Contains(s, "unauthorized")
}

type getPoliciesResponse struct {
	Policies []xcepPolicy `xml:"response>policies>policy"`
	OIDs     []xcepOID    `xml:"oIDs>oID"`
	CAs      []xcepCA     `xml:"cAs>cA"`
}

type xcepPolicy struct {
	OIDRef string `xml:"policyOIDReference"`
	CARefs []int  `xml:"cAs>cAReference"`
	Attrs  struct {
		CommonName string `xml:"commonName"`
		Schema     int    `xml:"policySchema"`
		Enroll     bool   `xml:"permission>enroll"`
		MinKeyLen  int    `xml:"privateKeyAttributes>minimalKeyLength"`
		EnrollFlag int    `xml:"enrollmentFlags"`
	} `xml:"attributes"`
}

type xcepOID struct {
	Value string `xml:"value"`
	RefID string `xml:"oIDReferenceID"`
}

type xcepCA struct {
	URIs []struct {
		Auth        int    `xml:"clientAuthentication"`
		URI         string `xml:"uri"`
		Priority    int    `xml:"priority"`
		RenewalOnly bool   `xml:"renewalOnly"`
	} `xml:"uris>cAURI"`
	Certificate string `xml:"certificate"`
	RefID       int    `xml:"cAReferenceID"`
}

type bst struct {
	ValueType string `xml:"ValueType,attr"`
	Value     string `xml:",chardata"`
}

type rstr struct {
	Disposition string `xml:"DispositionMessage"`
	RequestID   string `xml:"RequestID"`
	Token       []bst  `xml:"RequestedSecurityToken>BinarySecurityToken"`
	Loose       []bst  `xml:"BinarySecurityToken"`
}

type rstrc struct {
	Responses []rstr `xml:"RequestSecurityTokenResponse"`
}

func parseEnvelope(data []byte) (*respEnvelope, error) {
	var env respEnvelope
	if err := xml.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("adcs: parse soap response: %w", err)
	}
	return &env, nil
}
