// Package agentca runs CertForge's internal agent CA: an ECDSA P-256 root
// that signs agent client certificates (URI SAN urn:certforge:client:<id>,
// no DNS names) and the agent listener's server certificate. Several CAs
// are trusted at once, so rotation never strands an enrolled agent (ADR 0009).
package agentca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

// Lifetimes.
const (
	CALifetime       = 10 * 365 * 24 * time.Hour
	ListenerLifetime = 365 * 24 * time.Hour
	clockSkew        = 5 * time.Minute
	clientURIPrefix  = "urn:certforge:client:"
)

// Errors.
var (
	ErrBadCSR    = errors.New("agentca: invalid certificate request")
	ErrNotClient = errors.New("agentca: not a CertForge agent certificate")
)

// CA is one agent CA with its decrypted key.
type CA struct {
	ID        uuid.UUID
	Status    string
	Cert      *x509.Certificate
	Key       *ecdsa.PrivateKey
	CreatedAt time.Time
}

// Fingerprint is the lowercase hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string { return agentproto.CertFingerprint(der) }

// SerialHex is how client certificate serials are stored.
func SerialHex(c *x509.Certificate) string { return c.SerialNumber.Text(16) }

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewCA creates a self-signed ECDSA P-256 CA valid for ten years.
func NewCA(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "CertForge agent CA " + now.UTC().Format("2006-01-02"), Organization: []string{"CertForge"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(CALifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// ParseCSR decodes a PEM CSR, checks its signature, and accepts ECDSA
// P-256/P-384, Ed25519 or RSA of at least 2048 bits.
func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: not a PEM CERTIFICATE REQUEST", ErrBadCSR)
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, fmt.Errorf("%w: ECDSA keys must be P-256 or P-384", ErrBadCSR)
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("%w: RSA keys must be at least 2048 bits", ErrBadCSR)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrBadCSR, k)
	}
	return csr, nil
}

// ClientURI is the URI SAN identifying a client.
func ClientURI(id uuid.UUID) *url.URL {
	u, _ := url.Parse(clientURIPrefix + id.String())
	return u
}

// ClientIDFromCert returns the client id in an agent certificate's URI SAN.
func ClientIDFromCert(c *x509.Certificate) (uuid.UUID, error) {
	if len(c.URIs) != 1 || !strings.HasPrefix(c.URIs[0].String(), clientURIPrefix) {
		return uuid.Nil, ErrNotClient
	}
	id, err := uuid.Parse(strings.TrimPrefix(c.URIs[0].String(), clientURIPrefix))
	if err != nil {
		return uuid.Nil, ErrNotClient
	}
	return id, nil
}

func capped(ca *CA, notAfter time.Time) time.Time {
	if notAfter.After(ca.Cert.NotAfter) {
		return ca.Cert.NotAfter
	}
	return notAfter
}

// SignClient issues a clientAuth certificate for csr's key.
func SignClient(ca *CA, csr *x509.CertificateRequest, clientID uuid.UUID, lifetime time.Duration, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: clientID.String(), Organization: []string{"CertForge agent"}},
		URIs:         []*url.URL{ClientURI(clientID)},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     capped(ca, now.Add(lifetime)),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// SignServer issues the agent listener's serverAuth certificate.
func SignServer(ca *CA, pub crypto.PublicKey, names []string, now time.Time) (*x509.Certificate, error) {
	if len(names) == 0 {
		return nil, errors.New("agentca: the listener certificate needs at least one name")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"CertForge agent listener"}},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     capped(ca, now.Add(ListenerLifetime)),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CertPEM encodes one DER certificate.
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// BundlePEM concatenates certificates as PEM.
func BundlePEM(certs []*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		b.Write(CertPEM(c.Raw))
	}
	return b.Bytes()
}
