// Package adcs implements signer.Signer over Microsoft Active Directory
// Certificate Services, enrolling leaf certificates through the Certificate
// Enrollment Policy Web Service (MS-XCEP) and Certificate Enrollment Web
// Service (MS-WSTEP) with username/password authentication. CertForge is not
// an intermediate CA: it submits a CSR and stores the returned leaf, chain
// and key, like vaultpki.
package adcs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/signer"
)

// Code is this signer's CaType/meta.Entry code.
const Code = "adcs"

// MaxBody is the response body cap a caller should build the httpx client
// with; Signer enforces it itself on every response.
const MaxBody = 1 << 20

var oidTemplateName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}

// Config is an adcs CA's signer config (issuance's adcsConfig, unsealed;
// the password is passed to New separately).
type Config struct {
	CEPURL, CESURL, Template, Username string
	// CABundlePEM is the trust bundle used as the chain when CES returns
	// the leaf alone.
	CABundlePEM string
	// Timeout bounds each CEP/CES call; zero means 30s.
	Timeout time.Duration
}

// Signer implements signer.Signer over AD CS. Revoke and RenewalInfo return
// signer.ErrNotSupported (CES has no revocation).
type Signer struct {
	cfg      Config
	password []byte
	hc       *httpx.Client
}

// New builds a Signer. hc should be built with MaxBody and the CA bundle.
func New(cfg Config, password string, hc *httpx.Client) *Signer {
	return &Signer{cfg: cfg, password: []byte(password), hc: hc}
}

// Kind returns Code.
func (s *Signer) Kind() string { return Code }

// Close zeroes the held password; the Signer must not be used afterwards.
func (s *Signer) Close() { clear(s.password) }

// Revoke is not supported: CES has no revocation.
func (s *Signer) Revoke(context.Context, *x509.Certificate, int) error { return signer.ErrNotSupported }

// RenewalInfo is not supported: there is no ACME ARI.
func (s *Signer) RenewalInfo(context.Context, *x509.Certificate) (*signer.Window, error) {
	return nil, signer.ErrNotSupported
}

// CAInfo is a certification authority published by the enrollment policy.
type CAInfo struct {
	// Certs are the CA certificate(s) published in the policy.
	Certs []*x509.Certificate
	// CESURLs are the username/password enrollment URIs, best priority first.
	CESURLs []string
}

// Template is a certificate template published by the enrollment policy.
type Template struct {
	// Name is the template's common name (the name sent in the CSR).
	Name string
	// OID is the template's object identifier, when published.
	OID string
	// MinKeySize is the template's minimal key length.
	MinKeySize int
	// EnrollmentFlags are the template's msPKI-Enrollment-Flag bits.
	EnrollmentFlags int
	// CanEnroll reports whether the authenticated user may enroll.
	CanEnroll bool
	// CAs are the authorities that issue the template.
	CAs []CAInfo
	// Schema is the template's policySchema (version).
	Schema int
	// SubjectFlags are the msPKI-Certificate-Name-Flag bits.
	SubjectFlags int
	// RASignatures is the number of authorized signatures required.
	RASignatures int
	// KeyAlgorithm is "RSA", "ECDSA_P256", "ECDSA_P384", or "" when unknown.
	KeyAlgorithm string
	// Providers are the allowed cryptographic service providers.
	Providers []string
	// EKUs are the template's extended key usage (or application policy) OIDs.
	EKUs []string

	algNil bool
}

const (
	oidRSA       = "1.2.840.113549.1.1.1"
	oidP256      = "1.2.840.10045.3.1.7"
	oidP384      = "1.3.132.0.34"
	oidEKU       = "2.5.29.37"
	oidAppPolicy = "1.3.6.1.4.1.311.21.10"
	oidServer    = "1.3.6.1.5.5.7.3.1"
	oidAnyEKU    = "2.5.29.37.0"
)

// FlagEnrolleeSuppliesSubject is CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT.
const FlagEnrolleeSuppliesSubject = 0x1

// SuppliesSubject reports whether the request may carry its own subject.
func (t Template) SuppliesSubject() bool { return t.SubjectFlags&FlagEnrolleeSuppliesSubject != 0 }

// LegacyCSP reports whether the template is a legacy CSP template (schema 1
// or 2, no algorithm reference, or no Key Storage Provider listed).
func (t Template) LegacyCSP() bool {
	if t.Schema < 3 || t.algNil {
		return true
	}
	for _, p := range t.Providers {
		if strings.Contains(p, "Key Storage Provider") {
			return false
		}
	}
	return true
}

// ServerAuthOK reports whether the template allows server authentication.
func (t Template) ServerAuthOK() bool {
	if len(t.EKUs) == 0 {
		return true
	}
	for _, e := range t.EKUs {
		if e == oidServer || e == oidAnyEKU {
			return true
		}
	}
	return false
}

// AllowedKeyTypes lists the CertForge key types the template accepts.
func (t Template) AllowedKeyTypes() []string {
	switch t.KeyAlgorithm {
	case "RSA":
		var out []string
		for _, k := range []struct {
			name string
			bits int
		}{{"rsa2048", 2048}, {"rsa3072", 3072}, {"rsa4096", 4096}} {
			if k.bits >= t.MinKeySize {
				out = append(out, k.name)
			}
		}
		return out
	case "ECDSA_P256":
		return []string{"ec256"}
	case "ECDSA_P384":
		return []string{"ec384"}
	}
	return nil
}

// parseEKUs reads an extended key usage (2.5.29.37) or MS application
// policies (1.3.6.1.4.1.311.21.10) extension value.
func parseEKUs(oid string, der []byte) []string {
	var seq []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) != 0 {
		return nil
	}
	var out []string
	for _, e := range seq {
		var id asn1.ObjectIdentifier
		switch {
		case e.Tag == asn1.TagOID && e.Class == asn1.ClassUniversal:
			if _, err := asn1.Unmarshal(e.FullBytes, &id); err != nil {
				continue
			}
		case oid == oidAppPolicy && e.Tag == asn1.TagSequence:
			if _, err := asn1.Unmarshal(e.Bytes, &id); err != nil {
				continue
			}
		default:
			continue
		}
		out = append(out, id.String())
	}
	return out
}

func keyAlgorithm(oid, name string) string {
	switch oid {
	case oidRSA:
		return "RSA"
	case oidP256:
		return "ECDSA_P256"
	case oidP384:
		return "ECDSA_P384"
	}
	switch {
	case strings.Contains(name, "ECDSA_P256"):
		return "ECDSA_P256"
	case strings.Contains(name, "ECDSA_P384"):
		return "ECDSA_P384"
	case strings.EqualFold(name, "RSA"):
		return "RSA"
	}
	return ""
}

// PolicyResult is the parsed GetPolicies response.
type PolicyResult struct {
	Templates []Template
	CAs       []CAInfo
}

// Template returns the named template (case-insensitive) or
// ErrTemplateUnknown.
func (r *PolicyResult) Template(name string) (*Template, error) {
	for i := range r.Templates {
		if strings.EqualFold(r.Templates[i].Name, name) {
			return &r.Templates[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrTemplateUnknown, name)
}

// FlagPendAllRequests is CT_FLAG_PEND_ALL_REQUESTS: the CA holds every
// request for manager approval.
const FlagPendAllRequests = 0x2

// RequiresApproval reports whether the template holds all requests for CA
// manager approval.
func (t Template) RequiresApproval() bool { return t.EnrollmentFlags&FlagPendAllRequests != 0 }

// Policies runs XCEP GetPolicies against the CEP URL and returns the
// published templates and CAs.
func (s *Signer) Policies(ctx context.Context) (*PolicyResult, error) {
	body := getPoliciesRequest(s.cfg.CEPURL, s.cfg.Username, string(s.password), time.Now())
	env, err := s.post(ctx, s.cfg.CEPURL, body)
	if err != nil {
		return nil, err
	}
	gp := env.Body.GetPoliciesResponse
	if gp == nil {
		return nil, errors.New("adcs: no GetPoliciesResponse in reply")
	}
	oids, names := map[string]string{}, map[string]string{}
	for _, o := range gp.OIDs {
		ref := strings.TrimSpace(o.RefID)
		oids[ref], names[ref] = strings.TrimSpace(o.Value), strings.TrimSpace(o.DefaultName)
	}
	cas := map[int]CAInfo{}
	res := &PolicyResult{}
	for _, c := range gp.CAs {
		info := CAInfo{}
		if der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Certificate), "")); err == nil {
			if cert, err := x509.ParseCertificate(der); err == nil {
				info.Certs = append(info.Certs, cert)
			}
		}
		uris := c.URIs
		sort.SliceStable(uris, func(i, j int) bool { return uris[i].Priority < uris[j].Priority })
		for _, u := range uris {
			if u.Auth&authUsername != 0 && !u.RenewalOnly && u.URI != "" {
				info.CESURLs = append(info.CESURLs, strings.TrimSpace(u.URI))
			}
		}
		cas[c.RefID] = info
		res.CAs = append(res.CAs, info)
	}
	for _, p := range gp.Policies {
		t := Template{
			Name: strings.TrimSpace(p.Attrs.CommonName), OID: oids[strings.TrimSpace(p.OIDRef)],
			MinKeySize: p.Attrs.MinKeyLen, CanEnroll: p.Attrs.Enroll, EnrollmentFlags: p.Attrs.EnrollFlag,
		}
		a := p.Attrs
		t.Schema, t.SubjectFlags, t.RASignatures = a.Schema, a.SubjectFlag, a.RASigs
		t.Providers = a.Providers
		ref := strings.TrimSpace(a.AlgRef.Value)
		nl := strings.TrimSpace(a.AlgRef.Nil)
		t.algNil = nl == "true" || nl == "1" || ref == ""
		switch {
		case nl == "true" || nl == "1":
			t.KeyAlgorithm = "RSA" // xsi:nil is a legacy RSA CSP
		case ref != "":
			t.KeyAlgorithm = keyAlgorithm(oids[ref], names[ref])
		}
		for _, e := range a.Extensions {
			id := oids[strconv.Itoa(e.OIDRef)]
			if id != oidEKU && id != oidAppPolicy {
				continue
			}
			if der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(e.Value), "")); err == nil {
				t.EKUs = append(t.EKUs, parseEKUs(id, der)...)
			}
		}
		for _, ref := range p.CARefs {
			if ci, ok := cas[ref]; ok {
				t.CAs = append(t.CAs, ci)
			}
		}
		res.Templates = append(res.Templates, t)
	}
	return res, nil
}

// post sends one SOAP request and returns the parsed envelope, mapping HTTP
// 401/403 and faults to ErrAuth/*Fault.
func (s *Signer) post(ctx context.Context, url string, body []byte) (*respEnvelope, error) {
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("adcs: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := s.hc.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("adcs: post: %w", errors.Unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, fmt.Errorf("adcs: read response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, s.authError(fmt.Sprintf("http %d", resp.StatusCode))
	}
	env, perr := parseEnvelope(data)
	if perr == nil && env.Body.Fault != nil {
		if env.Body.Fault.isAuth() {
			return nil, s.authError(env.Body.Fault.text())
		}
		if strings.Contains(strings.ToLower(env.Body.Fault.Reason), "denied") {
			return nil, ErrDenied{Disposition: env.Body.Fault.text()}
		}
		return nil, env.Body.Fault
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("adcs: http %d", resp.StatusCode)
	}
	return env, perr
}

// requestKeyBits is the size in bits of the key req will use, or 0 when
// unknown.
func requestKeyBits(req signer.IssueRequest) (bits int, isEC bool, label string) {
	if len(req.ReuseKeyPKCS8) > 0 {
		k, err := x509.ParsePKCS8PrivateKey(req.ReuseKeyPKCS8)
		if err != nil {
			return 0, false, ""
		}
		switch k := k.(type) {
		case *rsa.PrivateKey:
			return k.N.BitLen(), false, fmt.Sprintf("rsa%d", k.N.BitLen())
		case *ecdsa.PrivateKey:
			return k.Curve.Params().BitSize, true, fmt.Sprintf("ec%d", k.Curve.Params().BitSize)
		}
		return 0, false, ""
	}
	switch req.KeyType {
	case signer.RSA2048:
		return 2048, false, string(req.KeyType)
	case signer.RSA3072:
		return 3072, false, string(req.KeyType)
	case signer.RSA4096:
		return 4096, false, string(req.KeyType)
	case signer.EC256:
		return 256, true, string(req.KeyType)
	case signer.EC384:
		return 384, true, string(req.KeyType)
	}
	return 0, false, ""
}

// checkKeySize fails fast when the key is below the template's minimum. It is
// best-effort: any policy lookup problem skips the check.
func (s *Signer) checkKeySize(ctx context.Context, req signer.IssueRequest) error {
	if s.cfg.CEPURL == "" {
		return nil
	}
	bits, isEC, label := requestKeyBits(req)
	if bits == 0 {
		return nil
	}
	pr, err := s.Policies(ctx)
	if err != nil {
		return nil
	}
	tpl, err := pr.Template(s.cfg.Template)
	if err != nil {
		return nil
	}
	if want := tpl.KeyAlgorithm; want != "" {
		switch {
		case isEC && want == "RSA":
			return keyTooSmallError{fmt.Sprintf("adcs: key %s: template %q issues RSA keys only; use an RSA key or a template with an ECDSA key algorithm",
				label, s.cfg.Template)}
		case !isEC && want != "RSA":
			return keyTooSmallError{fmt.Sprintf("adcs: key %s: template %q issues %s keys only; use an ECDSA key or an RSA template",
				label, s.cfg.Template, strings.Replace(want, "_", " ", 1))}
		case isEC && want == "ECDSA_P256" && bits != 256, isEC && want == "ECDSA_P384" && bits != 384:
			return keyTooSmallError{fmt.Sprintf("adcs: key %s: template %q issues %s keys only",
				label, s.cfg.Template, strings.Replace(want, "_", " ", 1))}
		}
	}
	if tpl.MinKeySize <= bits {
		return nil
	}
	hint := fmt.Sprintf("use an RSA key of at least %d bits", tpl.MinKeySize)
	if isEC {
		hint += " or an ECDSA template"
	}
	return keyTooSmallError{fmt.Sprintf("adcs: key %s (%d bits) is below template %q minimum of %d bits; %s",
		label, bits, s.cfg.Template, tpl.MinKeySize, hint)}
}

// Issue enrolls a leaf: the CSR carries the template name extension, is sent
// to CES as a WSTEP RST, and the PKCS#7 reply is split into the leaf (the
// certificate matching the CSR key) and its chain. ErrPending and ErrDenied
// report non-issued dispositions.
func (s *Signer) Issue(ctx context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(req.Names) == 0 {
		return nil, errors.New("adcs: at least one name is required")
	}
	if s.cfg.CESURL == "" {
		return nil, errors.New("adcs: no CES URL configured")
	}
	if err := s.checkKeySize(ctx, req); err != nil {
		return nil, err
	}
	ext, err := templateNameExtension(s.cfg.Template)
	if err != nil {
		return nil, err
	}
	req.CSRExtensions = append(req.CSRExtensions, ext)
	_, pkcs8, csrDER, err := signer.NewKeyAndCSR(req)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("adcs: parse csr: %w", err)
	}
	env, err := s.post(ctx, s.cfg.CESURL, rstRequest(s.cfg.CESURL, s.cfg.Username, string(s.password), csrDER, time.Now()))
	if err != nil {
		return nil, err
	}
	var r *rstr
	switch {
	case env.Body.RSTR != nil:
		r = env.Body.RSTR
	case env.Body.RSTRC != nil && len(env.Body.RSTRC.Responses) > 0:
		r = &env.Body.RSTRC.Responses[0]
	default:
		return nil, errors.New("adcs: no RequestSecurityTokenResponse in reply")
	}
	// The outcome is decided by the RequestedSecurityToken (the issued
	// certificate) and the disposition; loose tokens (a CMC/PKCS7 reply, the
	// chain) are only a best-effort chain source.
	if len(r.Token) == 0 {
		d := strings.TrimSpace(r.Disposition)
		low := strings.ToLower(d)
		if strings.Contains(low, "under submission") || strings.Contains(low, "pending") {
			return nil, ErrPending{RequestID: strings.TrimSpace(r.RequestID)}
		}
		return nil, ErrDenied{Disposition: d}
	}
	var certs []*x509.Certificate
	for i, t := range append(append([]bst(nil), r.Token...), r.Loose...) {
		strict := i < len(r.Token)
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(t.Value), ""))
		if err != nil {
			if strict {
				return nil, fmt.Errorf("adcs: decode token: %w", err)
			}
			continue
		}
		if cs, err := parseCertsOnlyPKCS7(der); err == nil {
			certs = append(certs, cs...)
		} else if c, cerr := x509.ParseCertificate(der); cerr == nil {
			certs = append(certs, c)
		} else if strict {
			return nil, fmt.Errorf("adcs: parse issued token: %w", err)
		}
	}
	var leaf *x509.Certificate
	for _, c := range certs {
		if publicKeysEqual(c.PublicKey, csr.PublicKey) {
			leaf = c
			break
		}
	}
	if leaf == nil {
		return nil, errors.New("adcs: no issued certificate matches the CSR public key")
	}
	if err := checkNames(leaf, req.Names); err != nil {
		return nil, err
	}
	chain := orderChain(leaf, certs)
	if len(chain) == 0 {
		chain = orderChain(leaf, bundleCerts(s.cfg.CABundlePEM))
	}
	chainDER := make([][]byte, len(chain))
	for i, c := range chain {
		chainDER[i] = c.Raw
	}
	return &signer.Issued{
		LeafDER: leaf.Raw, ChainDER: chainDER, PrivateKeyPKCS8: pkcs8,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		Serial: fmt.Sprintf("%x", leaf.SerialNumber),
	}, nil
}

// templateNameExtension encodes name as the szOID_ENROLL_CERTTYPE_EXTENSION
// (1.3.6.1.4.1.311.20.2) BMPString.
func templateNameExtension(name string) (pkix.Extension, error) {
	u := utf16.Encode([]rune(name))
	b := make([]byte, 0, len(u)*2)
	for _, v := range u {
		b = append(b, byte(v>>8), byte(v))
	}
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 30, Bytes: b})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("adcs: encode template name: %w", err)
	}
	return pkix.Extension{Id: oidTemplateName, Value: der}, nil
}

// checkNames verifies leaf's SANs cover every requested name.
func checkNames(leaf *x509.Certificate, names []string) error {
	for _, n := range names {
		if err := leaf.VerifyHostname(n); err != nil {
			return fmt.Errorf("adcs: issued certificate does not cover %q", n)
		}
	}
	return nil
}

// orderChain returns the certificates above leaf drawn from pool, ordered
// leaf's issuer first up to the root.
func orderChain(leaf *x509.Certificate, pool []*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	cur := leaf
	for len(out) < len(pool) {
		var next *x509.Certificate
		for _, c := range pool {
			if c != cur && bytes.Equal(c.RawSubject, cur.RawIssuer) && !bytes.Equal(c.Raw, cur.Raw) && !bytes.Equal(c.Raw, leaf.Raw) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		out = append(out, next)
		if bytes.Equal(next.RawSubject, next.RawIssuer) {
			break
		}
		cur = next
	}
	return out
}

func bundleCerts(p string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(p)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return out
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	da, err1 := x509.MarshalPKIXPublicKey(a)
	db, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(da, db)
}

// authError builds the typed authentication error for detail, with the
// username-format hint when the configured username needs it.
func (s *Signer) authError(detail string) error {
	return &AuthError{Detail: detail, Hint: UsernameHint(s.cfg.Username)}
}
