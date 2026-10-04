package localca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/signer"
)

// ErrIssuerExpiring means the issuing certificate has expired or has less
// than minIssuerRemaining of validity left, so a leaf signed under it would
// be useless almost at once.
var ErrIssuerExpiring = errors.New("localca: issuing certificate has expired or is about to")

// minIssuerRemaining is the least validity the issuing certificate must have
// left for Issue to sign a leaf under it.
const minIssuerRemaining = 24 * time.Hour

// Opts positions a Signer's leaf certificates in the API and CRL
// namespace. BaseURL is the server's public base URL (general.baseUrl);
// when empty, issued leaves carry no CRL distribution point. Now defaults
// to time.Now.
type Opts struct {
	CAID    uuid.UUID
	BaseURL string
	Now     func() time.Time
}

// Recorder persists a revocation so BuildCRL can include it (Task 7: backed
// by the certificate_versions table and the CA's crl_number column).
type Recorder interface {
	Revoke(ctx context.Context, serial, issuerSerial string, reason int, at, notAfter time.Time) error
}

// Signer implements signer.Signer over Material. It holds only Issuing's
// private key — never Root's — so day-to-day issuance and revocation never
// need the root key unsealed.
type Signer struct {
	mat  Material
	cfg  Config
	rec  Recorder
	opts Opts
}

// New builds a Signer that issues under mat.Issuing and records
// revocations through rec.
func New(mat Material, cfg Config, rec Recorder, opts Opts) *Signer {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Signer{mat: mat, cfg: cfg, rec: rec, opts: opts}
}

func (s *Signer) Kind() string { return "localca" }

// Issue signs a leaf under Issuing: NewKeyAndCSR builds the key (honouring
// req.ReuseKeyPKCS8 and req.KeyType), NotAfter is capped to the issuing
// certificate's own NotAfter (Issue refuses when under 24 h of it remain), and a CRL distribution point is added only
// when Opts.BaseURL is set.
func (s *Signer) Issue(ctx context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(req.Names) == 0 {
		return nil, errors.New("localca: at least one name is required")
	}

	_, pkcs8, csrDER, err := signer.NewKeyAndCSR(req)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("localca: parse csr: %w", err)
	}

	now := s.opts.Now()
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	if remaining := s.mat.Issuing.NotAfter.Sub(now); remaining < minIssuerRemaining {
		return nil, fmt.Errorf("%w (valid until %s)", ErrIssuerExpiring, s.mat.Issuing.NotAfter.UTC().Format(time.RFC3339))
	}
	notAfter := now.Add(time.Duration(s.cfg.MaxLeafDays) * 24 * time.Hour)
	if notAfter.After(s.mat.Issuing.NotAfter) {
		notAfter = s.mat.Issuing.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.Names[0]},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if s.opts.BaseURL != "" {
		tmpl.CRLDistributionPoints = []string{fmt.Sprintf(
			"%s/crl/%s/%s.crl",
			strings.TrimSuffix(s.opts.BaseURL, "/"), s.opts.CAID, s.mat.Issuing.SerialNumber.Text(16),
		)}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.mat.Issuing, csr.PublicKey, s.mat.IssuingKey)
	if err != nil {
		return nil, fmt.Errorf("localca: create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	chainDER := [][]byte{s.mat.Issuing.Raw}
	for _, c := range s.mat.Chain {
		if s.mat.Root != nil && bytes.Equal(c.Raw, s.mat.Root.Raw) {
			continue
		}
		chainDER = append(chainDER, c.Raw)
	}

	return &signer.Issued{
		LeafDER:         leaf.Raw,
		ChainDER:        chainDER,
		PrivateKeyPKCS8: pkcs8,
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter,
		Serial:          fmt.Sprintf("%x", leaf.SerialNumber),
	}, nil
}

// Revoke records cert's revocation through rec. issuerSerial is
// s.mat.Issuing's serial; when cert carries an AuthorityKeyId that does not
// match Issuing's SubjectKeyId, cert was not issued by this Signer's
// issuing certificate (a different, possibly retired, issuer — Task 7
// builds a Signer over that issuer's own Material to revoke against it).
func (s *Signer) Revoke(ctx context.Context, cert *x509.Certificate, reason int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.rec == nil {
		return errors.New("localca: no recorder configured")
	}
	if len(cert.AuthorityKeyId) > 0 && len(s.mat.Issuing.SubjectKeyId) > 0 &&
		!bytes.Equal(cert.AuthorityKeyId, s.mat.Issuing.SubjectKeyId) {
		return errors.New("localca: certificate was not issued by this signer's issuing certificate")
	}
	issuerSerial := s.mat.Issuing.SerialNumber.Text(16)
	serial := fmt.Sprintf("%x", cert.SerialNumber)
	return s.rec.Revoke(ctx, serial, issuerSerial, reason, s.opts.Now(), cert.NotAfter)
}

// RenewalInfo is not implemented: localca has no ACME ARI to poll.
func (s *Signer) RenewalInfo(ctx context.Context, cert *x509.Certificate) (*signer.Window, error) {
	return nil, signer.ErrNotSupported
}
