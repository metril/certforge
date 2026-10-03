// Package localca is CertForge's built-in private certificate authority.
// It is pure certificate logic with no I/O and no persistence: Generate,
// Import and Rotate build Material (a certificate chain and the issuing
// private key); New turns Material into a signer.Signer that issues leaves
// and records revocations through a caller-supplied Recorder. Task 7 wires
// this package to the CA lifecycle API, the sealed secret store and the CRL
// routes.
package localca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/metril/certforge/internal/signer"
)

// clockSkew backdates NotBefore so a server clock a few minutes behind
// still accepts a freshly issued or rotated certificate immediately.
const clockSkew = 5 * time.Minute

// ErrCannotSignCRL is returned by Import when crl is requested but the
// issuing certificate cannot itself sign a CRL: it is missing the CRLSign
// key usage bit or a SubjectKeyId.
var ErrCannotSignCRL = errors.New("localca: issuing certificate cannot sign CRLs")

// Subject is the distinguished name used for a generated root and issuing
// intermediate.
type Subject struct {
	CommonName   string
	Organization string
	Country      string
}

// Config configures Generate, Rotate and a Signer built by New.
type Config struct {
	Subject              Subject
	KeyType              signer.KeyType
	RootValidityYears    int
	IssuingValidityYears int
	MaxLeafDays          int
	CRL                  bool
}

// Material is one CA's certificate chain and the private key needed to
// sign leaves. Root is nil for an import whose top-of-chain certificate is
// not itself self-signed — trust is then the top of Chain, not Root. Chain
// holds the certificates above Issuing, in order; for a generated or
// rotated CA that is just [Root].
type Material struct {
	Root       *x509.Certificate
	Issuing    *x509.Certificate
	IssuingKey crypto.Signer
	Chain      []*x509.Certificate
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// generateKey creates a fresh private key of the given type. Duplicated
// (deliberately, it is a handful of lines) from internal/signer's
// unexported equivalent so this package stays free of any dependency on
// signer beyond its public KeyType/IssueRequest/Issued types.
func generateKey(kt signer.KeyType) (crypto.Signer, error) {
	switch kt {
	case signer.RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case signer.RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case signer.RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case signer.EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case signer.EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, fmt.Errorf("localca: unsupported key type %q", kt)
	}
}

// serialSuffix is the first 8 hex digits of serial, zero-padded, so two
// issuing CAs minted in the same month still get distinct common names.
func serialSuffix(serial *big.Int) string {
	h := fmt.Sprintf("%032x", serial)
	return h[:8]
}

func pkixName(s Subject) pkix.Name {
	n := pkix.Name{CommonName: s.CommonName}
	if s.Organization != "" {
		n.Organization = []string{s.Organization}
	}
	if s.Country != "" {
		n.Country = []string{s.Country}
	}
	return n
}

// Generate creates a self-signed root and an issuing intermediate signed by
// it. Go's x509.CreateCertificate assigns both a SubjectKeyId (RFC 5280
// §4.2.1.2 method 1) since they are CA templates, and derives the
// intermediate's AuthorityKeyId from the root's SubjectKeyId. The root
// private key is returned as PKCS#8 for the caller to seal; Generate keeps
// no copy of it.
func Generate(cfg Config, now time.Time) (Material, []byte, error) {
	rootKey, err := generateKey(cfg.KeyType)
	if err != nil {
		return Material{}, nil, fmt.Errorf("localca: generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Material{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkixName(cfg.Subject),
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.AddDate(cfg.RootValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rootKey.Public(), rootKey)
	if err != nil {
		return Material{}, nil, fmt.Errorf("localca: create root: %w", err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return Material{}, nil, err
	}

	mat, err := issueIntermediate(root, rootKey, cfg, now)
	if err != nil {
		return Material{}, nil, err
	}
	rootKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		return Material{}, nil, fmt.Errorf("localca: marshal root key: %w", err)
	}
	return mat, rootKeyPKCS8, nil
}

// issueIntermediate signs a fresh issuing intermediate under root/rootKey,
// shared by Generate and Rotate. Its validity is min(IssuingValidityYears,
// root's own remaining life).
func issueIntermediate(root *x509.Certificate, rootKey crypto.Signer, cfg Config, now time.Time) (Material, error) {
	issuingKey, err := generateKey(cfg.KeyType)
	if err != nil {
		return Material{}, fmt.Errorf("localca: generate issuing key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Material{}, err
	}
	notAfter := now.AddDate(cfg.IssuingValidityYears, 0, 0)
	if notAfter.After(root.NotAfter) {
		notAfter = root.NotAfter
	}
	name := pkixName(cfg.Subject)
	name.CommonName = fmt.Sprintf("%s Issuing CA %s-%s", cfg.Subject.CommonName, now.UTC().Format("2006-01"), serialSuffix(serial))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               name,
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, issuingKey.Public(), rootKey)
	if err != nil {
		return Material{}, fmt.Errorf("localca: create issuing: %w", err)
	}
	issuing, err := x509.ParseCertificate(der)
	if err != nil {
		return Material{}, err
	}
	return Material{Root: root, Issuing: issuing, IssuingKey: issuingKey, Chain: []*x509.Certificate{root}}, nil
}

// Rotate signs a fresh issuing intermediate under the existing root,
// retiring the previous one (the caller keeps the retired certificate for
// its CRL until it expires, per ADR — outside this package). rootKeyPKCS8
// is the caller-unsealed root private key; Rotate zeroes its copy once the
// key is parsed.
func Rotate(root *x509.Certificate, rootKeyPKCS8 []byte, cfg Config, now time.Time) (Material, error) {
	defer clear(rootKeyPKCS8)
	if !now.Before(root.NotAfter) {
		return Material{}, errors.New("localca: root certificate has expired")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(rootKeyPKCS8)
	if err != nil {
		return Material{}, fmt.Errorf("localca: parse root key: %w", err)
	}
	rootKey, ok := parsed.(crypto.Signer)
	if !ok {
		return Material{}, fmt.Errorf("localca: root key of type %T is not a signer", parsed)
	}
	return issueIntermediate(root, rootKey, cfg, now)
}

// Import builds Material from an operator-supplied issuing certificate (and
// optional chain) and its private key. certPEM holds the issuing
// certificate first, then its chain in order; the root is the last entry
// when it is self-signed, else Root is left nil and trust is the top of
// Chain. keyPEM is the issuing certificate's private key (PKCS#1, SEC1 or
// PKCS#8). now checks the certificate is currently valid.
func Import(certPEM, keyPEM string, crl bool, now time.Time) (Material, error) {
	certs, err := parseCertChain(certPEM)
	if err != nil {
		return Material{}, err
	}
	if len(certs) == 0 {
		return Material{}, errors.New("localca: no certificate found in the import PEM")
	}
	issuing := certs[0]
	chain := certs[1:]

	if !issuing.IsCA || issuing.KeyUsage&x509.KeyUsageCertSign == 0 {
		return Material{}, errors.New("localca: issuing certificate is not a CA")
	}
	if now.Before(issuing.NotBefore) || now.After(issuing.NotAfter) {
		return Material{}, errors.New("localca: issuing certificate is not currently valid")
	}
	if crl && (issuing.KeyUsage&x509.KeyUsageCRLSign == 0 || len(issuing.SubjectKeyId) == 0) {
		return Material{}, ErrCannotSignCRL
	}

	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return Material{}, err
	}
	issuingKey, ok := key.(crypto.Signer)
	if !ok {
		return Material{}, fmt.Errorf("localca: imported key of type %T is not a signer", key)
	}
	if !publicKeysEqual(issuing.PublicKey, issuingKey.Public()) {
		return Material{}, errors.New("localca: imported key does not match the issuing certificate")
	}

	if err := checkImportChain(certs); err != nil {
		return Material{}, err
	}

	var root *x509.Certificate
	if n := len(chain); n > 0 {
		last := chain[n-1]
		if bytes.Equal(last.RawIssuer, last.RawSubject) && last.CheckSignatureFrom(last) == nil {
			root = last
		}
	}
	return Material{Root: root, Issuing: issuing, IssuingKey: issuingKey, Chain: chain}, nil
}

// checkImportChain enforces the import policy on certs (issuing first):
// every certificate's key is RSA >= 2048 or ECDSA P-256/P-384/P-521, no
// certificate is signed with MD5 or SHA-1 (a self-signed top of the bundle is exempt:
// its self-signature protects nothing), and each certificate was signed by
// the next one up (which must itself be a CA).
func checkImportChain(certs []*x509.Certificate) error {
	for i, c := range certs {
		switch pub := c.PublicKey.(type) {
		case *rsa.PublicKey:
			if pub.N.BitLen() < 2048 {
				return fmt.Errorf("localca: %s uses an RSA key shorter than 2048 bits", certLabel(i, c))
			}
		case *ecdsa.PublicKey:
			switch pub.Curve {
			case elliptic.P256(), elliptic.P384(), elliptic.P521():
			default:
				return fmt.Errorf("localca: %s uses an unsupported elliptic curve", certLabel(i, c))
			}
		default:
			return fmt.Errorf("localca: %s uses an unsupported key type", certLabel(i, c))
		}
		// Only the top of the bundle may be self-signed; a self-signed
		// certificate with anything after it has no link to that rest.
		top := i == len(certs)-1
		selfSigned := top && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
		switch c.SignatureAlgorithm {
		case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			if !selfSigned {
				return fmt.Errorf("localca: %s is signed with a weak algorithm (%s)", certLabel(i, c), c.SignatureAlgorithm)
			}
		}
		if selfSigned {
			continue
		}
		if i+1 < len(certs) {
			if err := c.CheckSignatureFrom(certs[i+1]); err != nil {
				return fmt.Errorf("localca: %s was not signed by the next certificate in the chain: %w", certLabel(i, c), err)
			}
		}
	}
	return nil
}

func certLabel(i int, c *x509.Certificate) string {
	if i == 0 {
		return "the issuing certificate"
	}
	return fmt.Sprintf("chain certificate %q", c.Subject.CommonName)
}

// parseCertChain decodes every CERTIFICATE PEM block in s, in order.
func parseCertChain(s string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(s)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("localca: parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// parsePrivateKeyPEM decodes the first PEM private key block (PKCS#1, SEC1
// or PKCS#8), skipping other blocks such as an EC PARAMETERS header.
func parsePrivateKeyPEM(s string) (any, error) {
	var blk *pem.Block
	rest := []byte(s)
	for {
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("localca: no private key PEM block")
		}
		if strings.HasSuffix(blk.Type, "PRIVATE KEY") {
			break
		}
	}
	switch blk.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	default:
		return x509.ParsePKCS8PrivateKey(blk.Bytes)
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	da, err1 := x509.MarshalPKIXPublicKey(a)
	db, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(da, db)
}
